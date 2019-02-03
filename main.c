#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <signal.h>
#include <stdbool.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <assert.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/prctl.h>
#include <time.h>
#include "pcap_reader.h"


static bool sig_child_caught = false;

static bool sig_intr_caught = false;


static char temp_dir[128];

static bool save_pcaps = false;

static int max_queue_elements = 100;

static struct timeval first_packet;

struct packet_element {
	int number;	/* each packet has a unique number */
	struct timeval enqueue_time;
	struct timeval packet_time;	/* from pcap with divisor and conversions */	
	struct block_info *block;
	bool egress;	/* true for coming in, false for going out */
	struct packet_element *peer;	/* matching packet on other interface */
	struct packet_element *next;
	struct packet_element *prev;
};
	
struct packet_queue {
	struct packet_element *head;  /* oldest packet */
	struct packet_element *tail;	/* newest packet */
	int blocks_in_queue;
};

struct tracers {
	char *pipe;
	int fd;		/* read fd for pipe */
	int save_fd;	/* if -1, don't save, otherwise save all reads to this file for later analysis */
	bool wan;	/* true for upstream side, false for local side  */ 
	pid_t pid;
	int clock_divisor;  /* divisor according to if_tsresol (or absence) */
	int fraction_divisor;   /* to convert to tv_usec  from fraction -- typically 1000? */
	char *interface;
	struct pcap_option_element *interface_list;
	struct pcap_option_element *section_header_list;
	unsigned char mac_addr[6];
	struct packet_queue packet_queue;
	struct tracers *next;
	struct tracers *prev;
};

static enum type_of_tracers { tracer_file, tracer_tshark, tracer_unknown } type_of_tracers = tracer_unknown;
static struct tracers *tracer_list;

static struct tracers *lan;
static struct tracers *wan;


static bool read_pcap_packet(struct tracers *this);

static void catch_child(int signo)
{
	sig_child_caught = true;	
}

static void catch_intr(int signo)
{
	sig_intr_caught = true;
}

static void print_tracer_packets(struct tracers *this)
{
	struct packet_element *packet;

	for(packet = this->packet_queue.tail; packet; packet = packet->prev) {
		assert(enhanced_packet_block == packet->block->type);
		print_enhanced_packet_block(packet->block);
	}
}


static void classify_packet(const char *type, struct packet_element *p)
{
	struct timeval offset;

	timersub(&p->packet_time, &first_packet, &offset);

	fprintf(stderr, "%s: packet #%d, %s, offset %ld:%06ld\n", type,
				p->number, (true == p->egress) ? "egress" : "ingress",
				offset.tv_sec, offset.tv_usec);
}
	
static void print_ip_packet_info(const char *identifier, unsigned char *ip_header)
{
	uint16_t total_length;
	char ascii_source[INET_ADDRSTRLEN];
	char ascii_dest[INET_ADDRSTRLEN];
	uint8_t protocol;	
	uint8_t ttl;
	uint8_t version;
	uint8_t ihl;


	version = *ip_header >> 4;
	ihl = *ip_header & 0xf;
	total_length = ntohs(*(uint16_t *) (ip_header + 2));
	ttl = *(ip_header + 8);
	protocol = *(ip_header + 9);
	
	inet_ntop(AF_INET, ip_header + 12,  ascii_source, sizeof ascii_source);
	inet_ntop(AF_INET, ip_header + 16,  ascii_dest, sizeof ascii_dest);
	fprintf(stderr, "%s packet: total_length = %d, ttl = %d, version = %d, ihl = %d, protocol = %d,   source = %s, dst = %s\n",
			identifier, total_length, ttl, version, ihl, protocol, ascii_source, ascii_dest);
}

/* packets for lan and wan -- incoming flag:
 *    coming in from wan (to lan) == true
 *    going from lan to wan =  false
 */
static bool compare_ipv4_packets(unsigned char *lan_ip_header, unsigned char *wan_ip_header, bool incoming)
{
	char ip_header_size;
	char protocol_type;

	if(memcmp(lan_ip_header, wan_ip_header, 8))
		return false;	
	print_ip_packet_info("wan", wan_ip_header);
	print_ip_packet_info("lan", lan_ip_header);	

	ip_header_size = *wan_ip_header & 0xf;
	protocol_type = *(wan_ip_header + 9);
	if(true == incoming) {
		/* ttl */
		if(*(wan_ip_header + 8) != *(lan_ip_header + 8) + 1)
			return false;
		/* source address */
		if(*((uint32_t *) (wan_ip_header + 12)) != *((uint32_t *) (lan_ip_header + 12)))
			return false;
	} else {
		/* ttl */
		if(*(lan_ip_header + 8) != *(wan_ip_header + 8) + 1)
			return false;
		/* destination address */
		if(*((uint32_t *) (wan_ip_header + 16)) != *((uint32_t *) (lan_ip_header + 16)))
			return false;
	}
	fprintf(stderr, "good src/dest address\n");
	return false;	
}

/* already determined one is ingress and one is egress (when egress is later than ingress) */
static bool compare_packets(struct packet_element *lan_element, struct packet_element *wan_element)
{
	unsigned char *lan_packet;
	unsigned char *wan_packet;
	bool incoming;	/* true for coming in, false for going out */
	uint16_t  ethertype;
	bool packet_pair = false;	/* set when packet pair */
	
	lan_packet = lan_element->block->packet;
	wan_packet = wan_element->block->packet;

	classify_packet("lan", lan_element);
	classify_packet("wan", wan_element);

	if(lan_element->egress == false && wan_element->egress == true) {
		/* packet from lan to wan */
		if(timercmp(&lan_element->packet_time, &wan_element->packet_time, >))
			return false;
		incoming = false;
	} else if(true == lan_element->egress  && false == wan_element->egress) {
		/* packet from wan to lan */
		if(timercmp(&lan_element->packet_time, &wan_element->packet_time, <))
			return false;
		incoming = true;
	} else return false;  /* can't be matched pair */

	if(lan_packet[12] != wan_packet[12] || lan_packet[13] != wan_packet[13])
		return false;	/* ethertype */

	
	ethertype = ntohs(* (uint16_t *)  (lan_packet + 12));
	switch(ethertype) {
		case 0x800:
			packet_pair = compare_ipv4_packets(lan_packet + 14, wan_packet + 14, incoming);
			break;	
		default:
			fprintf(stderr, "unknown ethertype = 0x%04x\n", ethertype);
			break;
	}
		
	if(true == packet_pair) {
		lan_element->peer = wan_element;
		wan_element->peer = lan_element;
	}
	
	
	return packet_pair;
	
	
}



static void remove_tracer(pid_t pid)
{
	struct tracers *this;

	for(this = tracer_list; this; this = this->next) {
		if(pid == this->pid)
			break;
	}
	if(!this) {
		fprintf(stderr, "tracer %d not found\n", pid);
		return;
	}

	if(tracer_list == this) {
		assert(this->prev == NULL);
		tracer_list = this->next;
	}

	if(this->prev) {
		this->prev->next = this->next;
	}
	
	if(this->next) {
		this->next->prev = this->prev;
	}

	print_tracer_packets(this);
	free(this->interface);
	free(this->pipe);
	fprintf(stderr, "freeing %d\n", pid);
	free(this);
}

static void reap_children(void)
{
	while(1) {
		pid_t pid;
		int status;

		pid = waitpid(-1,  &status, WNOHANG);
		switch(pid) {
			case 0:
				return;
			case -1:
				fprintf(stderr, "waitpid had error: %s\n", strerror(errno));
				return;
			default:
				if(false == sig_intr_caught) {
					fprintf(stderr, "unplanned child died\n");
					exit(1);
				}
				remove_tracer(pid);
		}
	}
}


static struct tracers *new_tracer(int fd, const char *pipe, const char *interface, pid_t pid, 
			bool wan, unsigned char mac_addr[6])
{
	static int save_num = 0;
	struct tracers *new;

	new = calloc(sizeof *new, 1);
	new->pipe = strdup(pipe);
	new->interface = strdup(interface);
	new->pid = pid;
	new->fd = fd;
	new->next = tracer_list;
	new->wan = wan;
	tracer_list = new;
	if(true == save_pcaps) {
		char pcap_save_file[128];
	
		assert(type_of_tracers == tracer_tshark);

		sprintf(pcap_save_file, "%s-%d-%d.pcapng", (true == wan) ? "wan" : "lan",
							 getpid(), save_num++);
		new->save_fd = open(pcap_save_file, O_WRONLY | O_CREAT, 0666);
		if(new->save_fd < 0) {
			fprintf(stderr, "Cannot open %s: %s\n",  pcap_save_file, strerror(errno));
			exit(1);
		}
		fprintf(stderr, "save file = %s\n", pcap_save_file);
	} else {
		new->save_fd = -1;
	}
	if(tracer_file == type_of_tracers) {
		while(read_pcap_packet(new))
			;
	}
	memcpy(new->mac_addr, mac_addr, 6);
	return new;
		
}



static void close_and_repopen(int target_fd, const char *interface)
{
	int fd;
	char filename[256];
	char *stream_name;
	int result;
	FILE *file;

	switch(target_fd) {
		case 1:
			stream_name = "stdout";
			break;
		case 2:
			stream_name = "stderr";
			break;
		default:
			fprintf(stderr, "want target_stream %d, need 1 or 2\n", target_fd);
			exit(1);
	}


	sprintf(filename, "%s-%s", interface, stream_name);
	fd = open(filename, O_WRONLY | O_CREAT | O_APPEND, 0644);
	if(fd < 0) {
		fprintf(stderr, "cannot open %s: %s\n", filename, strerror(errno));
		exit(1);
	}
	result = dup2(fd, target_fd);
	if(result < 0) {
		fprintf(stderr, "cannot dup2 for %s to %d: %s\n", filename, target_fd, strerror(errno) );
		exit(1);
	}
	close(fd);
	
	file = fdopen(target_fd, "a");
	if(file) {
		time_t current;

		current = time(NULL);
		fprintf(file, "file = %p\n", file);
		fprintf(file, "pid = %d, time = %s\n", getpid(), ctime(&current));
		fclose(file);
	} else {
		fprintf(stderr, "fdopen failed: %s\n", strerror(errno));
	}
	
}


static int run_tracer(const char *named_pipe,  const char *interface, const char *filter)
{
	pid_t child;
	
	child = fork();
	switch(child) {
		case -1:
			fprintf(stderr, "fork failed\n");
			exit(1);
		case 0:
			break;  // drop through
		default:
			return child;
	}

       // see https://stackoverflow.com/questions/284325/how-to-make-child-process-die-after-parent-exits/17589555#17589555
	prctl(PR_SET_PDEATHSIG, SIGTERM);       // linux only, didn't know about it

	close_and_repopen(1, interface);
	close_and_repopen(2, interface);
	
	if(filter)
		execlp("tshark", "tshark", "-i",  interface,  "-w", 
			named_pipe, "-f", filter, NULL);
	else execlp("tshark", "tshark", "-i", interface, "-w", named_pipe, NULL);
	printf("should never get here\n");
	exit(1);
}

static char *stringize_mac_addr(unsigned char mac_addr[6])
{
	static char ascii[6 * 3 + 1];
	int i;
	char *p = ascii;

	for(i = 0; i <= 5; i++) {
		sprintf(p, "%02x:", mac_addr[i]);
		p += 3;
	}
	p--;
	*p = '\0';
	return ascii;
}
	
static struct tracers *do_tracer(bool wan, const char *interface, unsigned char mac_addr[6], const char *filter)
{
	static int num = 0;
	char named_pipe[128];
	pid_t pid = 0;
	int result;
	int fd;
	char *type_of_stream;

	if(true == wan) {
		type_of_stream = "wan";
	} else {
		type_of_stream = "lan";
	}

	

	fd = open(interface, O_RDONLY);
	if(fd >= 0) {
		/* have a file */
		assert(tracer_tshark != type_of_tracers);   /* cannot select tshark also */
		type_of_tracers = tracer_file;
		fprintf(stderr, "reading %s file from %s: %s\n", type_of_stream, interface, stringize_mac_addr(mac_addr));
	} else {
		assert(tracer_file != type_of_tracers);
		type_of_tracers = tracer_tshark;
		fprintf(stderr, "capturing %s %s:%s\n", type_of_stream, interface, stringize_mac_addr(mac_addr));

		sprintf(named_pipe, "%s/%d", temp_dir,  num++);
		result = mknod(named_pipe, S_IFIFO | 0666, 0);
		if(result < 0) {
			fprintf(stderr, "cannot create named pipe %s: %s\n",
				named_pipe, strerror(errno));
			exit(1);
		}

		/* open read fd read write -- even though never write with this fd -- so there's no blocking */	
		fd = open(named_pipe, O_RDWR);
		if(fd < 0) {
			fprintf(stderr, "Cannot open named pipe %s: %s\n", 
				named_pipe, strerror(errno));
			exit(1);
		}
		pid = run_tracer(named_pipe, interface, filter);
	}
	
	return new_tracer(fd, named_pipe, interface, pid, wan, mac_addr);
	
}

static void free_packet_element(struct packet_element *this)
{
	free_block(this->block);
	free(this);
}
	
static void show_mac_address(const char *string, unsigned char *p)
{
	fprintf(stderr, "%-20s: ", string);
	fprintf(stderr, "%02x:%02x:%02x:%02x:%02x:%02x\n",
			*p, *(p + 1), *(p + 2), *(p + 3), *(p + 4), *(p + 5));
}
	
	
/* return true for sending, false for receiving */
static bool sending_packet(struct block_info *block, unsigned char mac_addr[6])
{
	
	show_mac_address("packet source", block->packet + 6);
	show_mac_address("packet dest", block->packet);
	show_mac_address("target", mac_addr);

	if(!memcmp(block->packet + 6, mac_addr, 6))  {
		fprintf(stderr, "egress\n");
		return true;
	} else {
		fprintf(stderr, "ingress\n");
		return false;
	}

}


static double packet_delay(struct timeval *tv)
{
	double tmp;
	struct timeval delta;
	
	timersub(tv, &first_packet, &delta);
	tmp = (double) delta.tv_sec;
	tmp += delta.tv_usec / 1000000.0;
	return tmp;
}

static void queue_packet(struct tracers *tracer, struct block_info *block)
{
	struct packet_element *this_element;
	struct packet_queue *this_queue;
	bool egress;
	static int packet_num = 0;
	uint64_t seconds;
	uint64_t fraction;

	this_element = calloc(sizeof *this_element, 1);
	assert(this_element != NULL);
	gettimeofday(&this_element->enqueue_time, NULL);
#if 0
	if(!first_packet.tv_sec) {
		first_packet = this_element->enqueue_time;
	}
#endif
	this_queue = &tracer->packet_queue;
	this_element->block = block;

	egress = sending_packet(block, tracer->mac_addr);
	this_element->egress = egress;

	this_element->number = packet_num++;
	fprintf(stderr, "%d: %s: %f  packet %s, direction %s\n",  this_element->number, tracer->interface,
			 packet_delay(&this_element->enqueue_time),
			 true == tracer->wan ? "wan" : "lan",
			true == egress  ? "egress" : "ingress");

	seconds = block->packet_time / tracer->clock_divisor;
	fraction = block->packet_time % tracer->clock_divisor;;
	fprintf(stderr, "enqueue time: %ld:%ld, pcap time = %ld:%ld\n",
			this_element->enqueue_time.tv_sec, this_element->enqueue_time.tv_usec,
			seconds, fraction);
	this_element->packet_time.tv_sec = seconds;
	this_element->packet_time.tv_usec = fraction / tracer->fraction_divisor;
			
	fprintf(stderr, "ethertype = 0x%02x ", ntohs(*( unsigned short *) (block->packet + 12)));
	// mac header is 14 bytes
	fprintf(stderr, "source address = %s ",  inet_ntoa(*(struct in_addr *) (block->packet + 26)));
	fprintf(stderr, "dest   address = %s ",  inet_ntoa(*(struct in_addr *) (block->packet + 30)));
	fprintf(stderr, "\n\n");
	if(!this_queue->head)
		this_queue->head = this_element;
	if(this_queue->tail)
		this_queue->tail->next = this_element;
	this_element->prev = this_queue->tail;
	this_queue->tail = this_element;
	if(!this_queue->blocks_in_queue) {
		/* empty queue */
		if(!first_packet.tv_sec) {
			first_packet = this_element->packet_time;
		} else if(timercmp(&first_packet, &this_element->packet_time, >)) {
			first_packet = this_element->packet_time;
		} 
	} 
	this_queue->blocks_in_queue++;
	if(this_queue->blocks_in_queue > max_queue_elements) {
		/* get rid of tail of queue */
		struct packet_element *to_remove;

		to_remove = this_queue->head;
		assert(to_remove->prev == NULL);
		this_queue->head = to_remove->next;
//		assert(this_queue->tail->next == to_remove);
		this_queue->head->prev = NULL;
		this_queue->blocks_in_queue--;
		free_packet_element(to_remove);
	}
	
}

#define case_asciify(x)    case x:	return #x;

static char *ascii_options_section_header(enum opt_name name)
{
	switch(name) {
		case_asciify(opt_comment);
		case_asciify(shb_hardware);
		case_asciify(shb_os);
		case_asciify(shb_userappl);
		default: return "unknown";
	}
}

static char *ascii_options_interface_description(enum opt_name name)
{
	switch(name) {
		case_asciify(opt_comment);
		case_asciify(if_name);
		case_asciify(if_description);
		case_asciify(if_IPv4addr);
		case_asciify(if_IPv6addr);
		case_asciify(if_MACaddr);
		case_asciify(if_EUIaddr);
		case_asciify(if_speed);
		case_asciify(if_tsresol);
		case_asciify(if_tzone);
		case_asciify(if_filter);
		case_asciify(if_os);
		case_asciify(if_fsclen);
		case_asciify(if_tsoffset);
		case_asciify(if_hardware);
		default: return "unknown";
	}
}
#undef case_asciify



static void print_header_options(char *(*func)(enum opt_name name),
			const char *name, struct pcap_option_element *list)
{
	fprintf(stderr, "list for %s\n", name);

	while(list) {
		fprintf(stderr, "option %s ", func(list->name));
		switch(list->type) {
			case char_pointer:
				fprintf(stderr, "char * %s\n", list->value);
				break;
			case char_single:
				fprintf(stderr, "char 0x%02x\n", list->c);
				break;
			case val_32bit:
				fprintf(stderr, "uint32 0x%x\n", list->value32);
				break;
			case val_64bit:
				fprintf(stderr, "uint64 0x%lx\n", list->value64);
				break;
			case byte_array:
				fprintf(stderr, "byte array ");
				{ int i;

				  for(i = 0; i < list->byte_array_length; i++)
					fprintf(stderr, "0x%02x ", list->byte_array[i]);
				}
				fprintf(stderr, "\n");
				break;
			default:
				fprintf(stderr, "unknown option type %d\n", list->type);
				break;
		}
		list = list->next;
	}
}


static int compute_clock_divisor(char byte)
{
	int value;
	int i;

	assert(!(byte & 0x80));
	
	for(value = 1, i = 0; i < byte; i++, value *= 10)
		;

	return value;
}
	
		
static void figure_out_clock_divisor(struct tracers *tracer)
{
	struct pcap_option_element *option;
	int divisor_value = 6;		/* default is microseconds */

	for(option = tracer->interface_list; option; option = option->next) {
		if(option->name == if_tsresol) {
			assert(char_single == option->type);
			divisor_value = option->value64;
			break;
		}
	}
	tracer->clock_divisor = compute_clock_divisor(divisor_value);	/* default to microsecond */
	fprintf(stderr, "divisor value = %d, clock_divisor = %d\n", divisor_value, tracer->clock_divisor);
	tracer->fraction_divisor = tracer->clock_divisor / compute_clock_divisor(6);
	fprintf(stderr, "fraction divisor = %d\n", tracer->fraction_divisor);
}

/* return true for packet read, false for not */
static bool read_pcap_packet(struct tracers *this)
{
	struct block_info *block;
	
	block = read_pcap_block(this->fd);
	if(!block)
		return false;

	print_block(block);
	if(this->save_fd >= 0) 
		save_block(this->save_fd, block);
	switch(block->type) {
		case enhanced_packet_block:
			queue_packet(this, block);
			return true;
		case section_header_block:
			this->section_header_list = decode_header_options(block);
			print_header_options(ascii_options_section_header, "section header", this->section_header_list);
			break;
		case interface_description:
			this->interface_list = decode_interface_options(block);
			print_header_options(ascii_options_interface_description, "interface_description",
						this->interface_list);
			figure_out_clock_divisor(this);
			break;
		default:
			fprintf(stderr, "unknown block type  = 0x%x\n", block->type);
			break;
	}	
	free_block(block);
	return true;
	
}


static void select_on_input(void)
{
	fd_set set;
	struct tracers *this;
	int result;
	int max_fd = 0;
	

	FD_ZERO(&set);
	for(this = tracer_list; this; this = this->next) {
		FD_SET(this->fd, &set);
		if(this->fd > max_fd)
			max_fd = this->fd;
	}
	
	result = select(max_fd + 1, &set, NULL, NULL, NULL);
	if(result < 0) {
		fprintf(stderr, "Select failed %s\n", strerror(errno));
		return;
	}
	if(result == 0) {
		fprintf(stderr, "select returned 0?\n");
		return;
	}
	for(this = tracer_list; this  && result > 0; this = this->next) {
		if(FD_ISSET(this->fd, &set)) {
			read_pcap_packet(this);
			result--;
		}
	}
	if(result > 0) {
		printf("result not cleared\n");
	}
}

static void create_temp_dir(void)
{
	int result;

	sprintf(temp_dir, "/tmp/chox-%d", getpid());
	result = mkdir(temp_dir, 0777);
	assert(0 == result);
}
	

static void usage(void) 
{
	printf("-s -- save pcaps\n");
	printf("-l -- specify lan (downstream) tap\n");
	printf("-w -- specify wan (upstream) tap\n");
	printf("-f -- tshark filter expression\n");
	printf("\ttaps are expressed \"interface_name:<mac addr>\"\n");
	exit(1);
	
}


	
static void compare_streams(void)
{
}

static bool decode_interface(char *arg, char **interface, unsigned char mac_addr[6])
{
	char *p;
	int i;
	int result;
	
	p = strchr(arg, ':');
	if(!p)
		return false;

	*interface = strndup(arg, p - arg);
	p++;
	for(i = 0;  i < 5; i++) {

		result = sscanf(p, "%02hhX", &mac_addr[i]);
		if(result != 1) {
			fprintf(stderr, "cannot decode remained %s\n", p);
			return false;
		}
		p = strchr(p, ':');
		if(!p) {
			fprintf(stderr, "cannot find a : at mac entry %d for %s\n", i, arg);
			return false;
		}
		p++;
		if(!*p) {
			fprintf(stderr, "end of string at entry %d\n", i);
			return false;
		}
	}
	result = sscanf(p, "%02hhX", &mac_addr[i]);
	if(1 != result) {
		fprintf(stderr, "cannot find mac addr 5\n");
		return false;
	}
	return true;
	
	
}


static void display_packet_list(const char *type, struct tracers *tracer)
{
	struct packet_element *packet;

	for(packet = tracer->packet_queue.head; packet; packet = packet->next) {
		classify_packet(type, packet);
	}
}

static void found_packet_match(struct packet_element *lan_element, struct packet_element *wan_element)
{
	fprintf(stderr, "found match\n");
	lan_element->peer = wan_element;
	wan_element->peer = lan_element;
}


static void match_packets(void)
{
	struct packet_element *lan_element;

	for(lan_element = lan->packet_queue.head; lan_element; lan_element = lan_element->next) {
		struct packet_element *wan_element;

		if(lan_element->peer)
			continue;
		for(wan_element = wan->packet_queue.head; wan_element; wan_element = wan_element->next) {
			if(wan_element->peer)
				continue;
			if(true == compare_packets(lan_element, wan_element)) {
				found_packet_match(lan_element, wan_element);
				break;
			}
		}	
	}
}

static void terminate(void)
{
	display_packet_list("lan", lan);
	display_packet_list("wan", wan);
	match_packets();
	show_mac_address("target lan", lan->mac_addr);
	show_mac_address("target wan", wan->mac_addr);
	exit(0);
}



int main(int argc, char *argv[])
{
	char *filter = "icmp";
	create_temp_dir();
	

	signal(SIGCHLD, catch_child);
	char *wan_interface;
	unsigned char wan_mac[6];
	char *lan_interface;
	unsigned char lan_mac[6];

	while(1) {
		int c;
		bool result;

		c = getopt(argc, argv, "sf:w:l:");
		if(-1 == c)
			break;
		switch(c) {
			case 's':
				save_pcaps = true;
				break;
			case 'l':
				result = decode_interface(optarg, &lan_interface, lan_mac);
				if(false == result) {
					fprintf(stderr, "Need valid lan addresses: got %s\n", optarg);
					exit(1);
				}
				break;	
			case 'w':
				result = decode_interface(optarg, &wan_interface, wan_mac);
				if(false == result) {
					fprintf(stderr, "Need valid wan addresses: got %s\n", optarg);
					exit(1);
				}
				break;
			case 'f':
				filter = strdup(optarg);
				fprintf(stderr, "filter expression = \"%s\"\n", filter);
				break;
			default:
				usage();
		}
	}


	wan =  do_tracer(true, wan_interface, wan_mac, filter);
	lan = do_tracer(false, lan_interface, lan_mac, filter);

	if(!lan || !wan) {
		fprintf(stderr, "Haven't selected wan or lan\n");
		exit(1);
	}

	
	signal(SIGINT, catch_intr);

	if(tracer_file == type_of_tracers) {
		compare_streams();
	} else {
		while(wan && lan) {
			if(true == sig_child_caught) {
				printf("caught sig child\n");
				reap_children();
			}
			if(true == sig_intr_caught) {
				terminate();
			}
			select_on_input();
		}
	}
	return 0;
}

