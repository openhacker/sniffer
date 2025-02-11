#include <stdio.h>
#include <unistd.h>
#include <stdarg.h>
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
#include <mcheck.h>
#ifdef USE_DMALLOC
#include <dmalloc.h>
#endif
#include "pcap_reader.h"


static bool sig_child_caught = false;

static bool start_triggers = false;
static bool terminate_program = false;

static char temp_dir[128];

static bool save_pcaps = false;

static bool show_consec_packets = false;
static int max_queue_elements = 100;

static bool run_gui = false;
static pid_t gui_pid;

static int prepend_queue = 10;

static struct timeval first_packet;

static char *lan_filter = "";
static char *wan_filter = "";

/* for debugging */
static char *mismatch_reason;

static int verbose = 0;

static bool track_packets = false;

static char *capture_program = "dumpcap";
static char *config_file = NULL;

static char mismatched_name[128];

static int ttl_same_counter = 0;
static int ttl_off_by_one_counter = 0;

static int packets_matched = 0;

static int realtime_wireshark_fd = -1;
static int mismatched_packet_fd = -1;

/* should be MAXPATH_LEN? */
static char output_directory[128];


/* increment for each mismatch write */
static int mismatch_number = 0;


/* semaphore -- while this is true, don't start writing (or count down) */
static bool writing_mismatches = false;
static pid_t writing_pid;



struct consec_stats {
	int num_bursts;
	int num_packets;
	int max_burst;
};

struct inside_filter_array {
	uint16_t *array;
	int      num;
};

static struct inside_filter_array tcp_interesting;
static struct inside_filter_array udp_interesting;
static struct inside_filter_array icmp_interesting;


/* first one is 0, second is 1 */
static int interface_id_seen = -1;
struct packet_element {
	int number;	/* order of packet read on the interface */
	struct timeval enqueue_time;
	struct timeval packet_time;	/* from pcap with divisor and conversions */	
	struct block_info *block;
	bool egress;	/* true for coming in, false for going out */
	bool passed_inner_filter;   /* if true, passes inner filter */
	struct packet_element *peer;	/* matching packet on other interface */
	struct packet_element *next;
	struct packet_element *prev;
#ifdef MAGIC
	void *magic;
#endif
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
	int packets_read;
	int unmatched;	/* number of unmatched packets seen (match will subtract one) */
	struct packet_queue packet_queue; 	/* packets coming in */
	struct packet_queue old_queue;		/* some packets so we can start before a mismatch */
	struct block_info *section_header;
	struct block_info *interface_description;
	int interface_id;	/* number to write  in packets */
	struct tracers *next;
	struct tracers *prev;
};

static enum type_of_tracers { tracer_file, tracer_tshark, tracer_unknown } type_of_tracers = tracer_unknown;
static struct tracers *tracer_list;

static struct tracers *lan;
static struct tracers *wan;

static void *prefix;
static int prefix_length;
static int no_peers = 0;	/* number of mismatched packets */

static void found_packet_match(struct packet_element *lan_element, struct packet_element *wan_element);

static bool read_pcap_packet(struct tracers *this);
static void setup_mismatched_file(int number);


static int log_wtime(const char *format, ...)
{
	int ret;

	va_list args;
	struct timeval tv;
	struct tm *broken;
	char string[40];

	gettimeofday(&tv, NULL);
	broken = localtime(&tv.tv_sec);
	strftime(string, sizeof string, "%H:%M:%S", broken);

	fprintf(stderr, "(%d) %s.%06lu ", getpid(), string, tv.tv_usec);
	
	va_start(args, format);
	ret = vfprintf(stderr, format, args);
	va_end(args);
	return ret;
}

static void catch_child(int signo)
{
	sig_child_caught = true;	
}

static void catch_terminate(int signo)
{
	terminate_program = true;
}

static void save_block_to_wireshark(struct block_info *block, const char *comment)
{
	if(realtime_wireshark_fd >= 0) 
		save_block(realtime_wireshark_fd, block, comment);
	if(mismatched_packet_fd >= 0) 
		save_block(mismatched_packet_fd, block, comment);
}

static void save_block_to_prefix(struct block_info *block)
{
	void *cp;

	prefix = realloc(prefix, prefix_length + block->block_length);
	cp = prefix + prefix_length;
	*((uint32_t *) cp) = block->type;
	cp += sizeof(block->type);
	*((uint32_t *) cp) = block->block_length;
	cp += sizeof(block->block_length);
	memcpy(cp, block->block_body, block->body_length);
	cp += block->body_length;
	*((uint32_t *) cp) = block->block_length;
//	fprintf(stderr, "old prefix_length = %d, added %d\n", prefix_length, block->block_length);
	prefix_length += block->block_length;

}

static void print_tracer_packets(struct tracers *this)
{
	struct packet_element *packet;

	
	for(packet = this->packet_queue.tail; packet; packet = packet->prev) {
		assert(enhanced_packet_block == packet->block->type);
		print_enhanced_packet_block(packet->block);
	}
}

static const char *identify_tracer(struct tracers *this)
{
	if(true == this->wan)
		return "wan";
	else	return "lan";
}


static void make_ascii_mac(unsigned char *address, char *string)
{
	int i;

	for(i = 0; i < 6; i++) {
		sprintf(string, "%02x:", *(address + i));
		string += 3;
	}
	string--;
	*string = 0;
}
		


static void classify_ipv4(const char *ip_header)
{
	char src_addr[INET_ADDRSTRLEN];
	char dst_addr[INET_ADDRSTRLEN];
	unsigned short length;

	length = ntohs(*(unsigned short *) (ip_header + 2));
	inet_ntop(AF_INET, ip_header + 12, src_addr, sizeof src_addr);
	inet_ntop(AF_INET, ip_header + 16, dst_addr, sizeof dst_addr);
	fprintf(stderr, "length = %d, source: %s, dest = %s\n",
			length, src_addr, dst_addr);
}

static void classify_packet(const char *type, struct packet_element *p)
{
	void *packet;
	struct timeval offset;
	char source_mac[2 * 6 + 6];
	char dest_mac[2 * 6 + 6];
	unsigned short ethertype;

	TEST_MAGIC(p);
	timersub(&p->packet_time, &first_packet, &offset);

	fprintf(stderr, "%s: packet #%d, %s, offset %ld:%06ld\n", type,
				p->number, (true == p->egress) ? "egress" : "ingress",
				offset.tv_sec, offset.tv_usec);
	packet = p->block->packet;
	make_ascii_mac(packet, dest_mac);
	make_ascii_mac(packet + 6, source_mac);
	ethertype = ntohs(*(unsigned short *) (packet + 12));
	fprintf(stderr, "source = %s, dest = %s, ethertype = %04x\n", source_mac, dest_mac, ethertype);
	switch(ethertype) {
		case 0x800:
			classify_ipv4(packet + 14);
			break;
	}
		
	
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
	
	if(verbose) {
		inet_ntop(AF_INET, ip_header + 12,  ascii_source, sizeof ascii_source);
		inet_ntop(AF_INET, ip_header + 16,  ascii_dest, sizeof ascii_dest);
		fprintf(stderr, "%s packet: total_length = %d, ttl = %d, version = %d, ihl = %d, protocol = %d,   source = %s, dst = %s\n",
				identifier, total_length, ttl, version, ihl, protocol, ascii_source, ascii_dest);
	}
}

/* packets after IP header */
static bool compare_icmp_packet(unsigned char *lan, unsigned char *wan, int length)
{
	uint8_t type;
	uint8_t code;
		
	/* check code and subtype */
	if(*((uint16_t *) lan) != *((uint16_t *) wan))
		return false;

	type = *lan;
	code = *(lan + 1);
	switch(type) {
		case 0:	/* ping request */
		case 8: /* ping reply */
			/* only compare identifier -- seems router changes sequence number -- but this isn't speced out */
			if(*(uint16_t *) (lan + 4) != *(uint16_t *) (wan + 4)) 
				break;
			if(length > 8) {
				if(memcmp(lan + 8, wan + 8, length - 8))
					break;
			}
			return true;
		default:
			fprintf(stderr, "unknown type: %d\n", type);
			break;
	}

	return false;
}

/* packets after IP header  -- incoming is "from wan"*/
static bool compare_tcp_packet(unsigned char *lan_tcp, unsigned char *wan_tcp, int length, bool incoming)
{
	int header_length;

	mismatch_reason = "tcp packet";

	if(true == incoming) {
		if(*(uint16_t *) lan_tcp != *(uint16_t *) wan_tcp)  {
			/* from wan -- source port is different */
			mismatch_reason = "source port";
			return false;
		}
	} else if(*(uint16_t *) (lan_tcp + 2) != *(uint16_t *) (wan_tcp + 2)) {
			mismatch_reason = "destination port";
			return false;
	}

	if(memcmp(lan_tcp + 4, wan_tcp + 4, 12))  {
		mismatch_reason = "tcp bytes 4-16";
		return false;	/* these 12 bytes have to match */
	}

	header_length = (*(lan_tcp + 12)  >> 4);
	header_length *= 4;
	if(verbose > 0) 
	 	fprintf(stderr, "length = %d, header length = %d\n", length, header_length);
	if(!memcmp(lan_tcp + header_length, wan_tcp + header_length, length - header_length)) {
		return true;
	} else { 
		mismatch_reason = "tcp data";
		return false;
	}
	
}

enum type_of_line { LINE_TCP, LINE_UDP, LINE_ICMP };



static void add_interesting_port(struct inside_filter_array *interesting, unsigned short num)
{
	
	interesting->array = realloc(interesting->array, (interesting->num + 1) * sizeof(uint16_t));
	interesting->array[interesting->num] = num;
	interesting->num++;
}

static void add_port_number(enum type_of_line type_of_line, unsigned short num)
{
//	printf("type of line = %d, num = %d\n", type_of_line, num);
	switch(type_of_line) {
		case LINE_TCP:
			add_interesting_port(&tcp_interesting, num);
			break;
		case LINE_UDP:
			add_interesting_port(&udp_interesting, num);
			break;
		case LINE_ICMP:
			if(num > 255) {
				fprintf(stderr, "cannot have ICMP number > 255, read %d\n", num);
				exit(1);
			}	
			add_interesting_port(&icmp_interesting, num);
			break;
	}
}

static void parse_config_line(enum type_of_line type_of_line, char *rest_of_line)
{
	while(rest_of_line) {
		int num;
		char *end;

		num = strtol(rest_of_line,  &end, 0);
		if(end == rest_of_line)
			return;
		add_port_number(type_of_line, num);
		rest_of_line = strchr(end, ',');
		if(rest_of_line)
			rest_of_line++;
		else return;
	}
}


/* only accept 0 and 8 (echo/reply) */
static void validate_icmp_types(void)
{
	int i;

	for(i = 0; i < icmp_interesting.num; i++) {
		switch(icmp_interesting.array[i]) {
			case 0:
			case 8:
				break;
			default:
				fprintf(stderr, "Illegal icmp type = %d\n", icmp_interesting.array[i]);
				exit(1);
		}
	}

	
	
}

static void parse_config_file(const char *filename)
{
	FILE *fp;
	char buffer[200];
	const char lan_token[] = "lan_filter=";
	const char wan_token[] = "wan_filter=";

	fp = fopen(filename, "r");
	if(!fp) {
		fprintf(stderr, "cannot open %s\n", filename);
		exit(EXIT_FAILURE);
	}

	while(!feof(fp)) {
		enum type_of_line;
		fgets(buffer, sizeof buffer, fp);
		if(*buffer == '#') {
			continue;
		}
		if(!strncmp(buffer, "tcp=", 4)) {
			parse_config_line(LINE_TCP, strchr(buffer, '=') + 1);
		} else if(!strncmp(buffer, "udp=", 4)) {
			parse_config_line(LINE_UDP, strchr(buffer, '=') + 1);
		} else if(!strncmp(buffer, lan_token, sizeof(lan_token) - 1)) {
			char *cp = strchr(buffer, '=') + 1;

			lan_filter = strdup(cp);
		} else if(!strncmp(buffer, wan_token, sizeof(wan_token) - 1)) {
			char *cp = strchr(buffer, '=') + 1;
		
			wan_filter = strdup(cp);
		} else if(!strncmp(buffer, "icmp=", 5)) {
			parse_config_line(LINE_ICMP, strchr(buffer, '=') + 1); 
			validate_icmp_types();
		} else {
			fprintf(stderr, "cannot parse %s\n", buffer);
		}
	}
	
	fclose(fp);
}

/* packets after  IP header */
static bool compare_udp_packet(unsigned char *lan, unsigned char *wan, int length)
{
	uint16_t payload_length;

	/* compare src port, dest port, length */
	if(memcmp(lan, wan, 6))
		return false;

	payload_length = ntohs(*((uint16_t *) (lan + 4)));

	if(memcmp(lan + 8, wan + 8, payload_length - 8))
		return false;

	return true;
}


/* packets for lan and wan -- incoming flag:
 *    coming in from wan (to lan) == true
 *    going from lan to wan =  false
 */
static bool compare_ipv4_packets(unsigned char *lan_ip_header, unsigned char *wan_ip_header, bool incoming)
{
	int ip_header_size;
	int total_length;
	char protocol_type;
	int remaining_length;
	bool is_pair = false;
	unsigned char lan_ttl;
	unsigned char wan_ttl;
	bool ttl_same_state; 	/* true if ttl is the same, false if not -- only used for matches */

	mismatch_reason = "unknown";
	
	if(memcmp(lan_ip_header, wan_ip_header, 8)) {
		mismatch_reason = "first 8 bytes of IP header";
		return false;	
	}
	print_ip_packet_info("wan", wan_ip_header);
	print_ip_packet_info("lan", lan_ip_header);	

	ip_header_size = *wan_ip_header & 0xf;
	if(*(wan_ip_header + 9) != *(lan_ip_header + 9)) {
		mismatch_reason = "IPv4 protocol";
		return false;
	}
	protocol_type = *(wan_ip_header + 9);
	wan_ttl = *(wan_ip_header + 8);
	lan_ttl = *(lan_ip_header + 8);
	if(verbose > 0) 
		fprintf(stderr, "matching wan_ttl = %d, lan_ttl = %d\n",  wan_ttl, lan_ttl);
	if(true == incoming) {
		/* source address */
		if(*((uint32_t *) (wan_ip_header + 12)) != *((uint32_t *) (lan_ip_header + 12))) {
			mismatch_reason = "source IPv4 address";
			return false;
		}

		if(wan_ttl == lan_ttl + 1) {
			ttl_same_state = false;
		} else if(wan_ttl == lan_ttl) {
			ttl_same_state = true;
		} else {
			mismatch_reason = "ttl counter";
			return false;
		}
	} else {
		/* ttl */
		if(wan_ttl + 1 == lan_ttl) {
			ttl_same_state = false;
		} else if(lan_ttl == wan_ttl) {
			ttl_same_state = true;
		} else {
			mismatch_reason = "ttl counter";
			return false;	
		}
		/* destination address */
		if(*((uint32_t *) (wan_ip_header + 16)) != *((uint32_t *) (lan_ip_header + 16))) {
			mismatch_reason = "destination IPv4 address";
			return false;
		}
	}

	ip_header_size *= 4;	/* convert to bytes from words */
	total_length = ntohs(*(uint16_t *) (lan_ip_header + 2));
	remaining_length = total_length - ip_header_size;
#if 0
	fprintf(stderr, "ip_header_size = %d, total length = %d, remaining length = %d\n",
		ip_header_size, total_length, remaining_length);
#endif
	assert(total_length > 0);
			
	
	switch(protocol_type) {
		case 1:
			is_pair = compare_icmp_packet(lan_ip_header + ip_header_size, 
					wan_ip_header +  ip_header_size, remaining_length);	
			break;
		case 6:
			is_pair = compare_tcp_packet(lan_ip_header + ip_header_size, 
					wan_ip_header +  ip_header_size, remaining_length, incoming);	
			break;
		case 17:
			is_pair = compare_udp_packet(lan_ip_header + ip_header_size, 
					wan_ip_header + ip_header_size, remaining_length);
//			fprintf(stderr, "compare udp packet: %d\n", is_pair);
			break;
		default:
			fprintf(stderr, "unknown protocol type = %d\n", protocol_type);
			break;
	}
	if(true == is_pair) {
		if(true == ttl_same_state) {
			ttl_same_counter++;
		} else ttl_off_by_one_counter++;
	}
	return is_pair;	
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

#if 0
	classify_packet("lan", lan_element);
	classify_packet("wan", wan_element);
#endif

	if(lan_element->egress == false && wan_element->egress == true) {
		/* it seems the timestamp may not be accurate on close packets -- sometimes I see the incoming packet
                 * coming AFTER the outgoing packet through the router
                 */
#ifdef TEST_TIMES
		/* packet from lan to wan */
		if(timercmp(&lan_element->packet_time, &wan_element->packet_time, >)) {
			mismatch_reason = "lan > wan time";
			return false;
		}
#endif
		incoming = false;
	} else if(true == lan_element->egress  && false == wan_element->egress) {
		/* packet from wan to lan */
#ifdef TEST_TIMES
		if(timercmp(&lan_element->packet_time, &wan_element->packet_time, <)) {
			mismatch_reason = "wan < lan time";
			return false;
		}
#endif
		incoming = true;
	} else {
		mismatch_reason = "wrong ingress/egress";
		return false;  /* can't be matched pair */
	}

	if(lan_packet[12] != wan_packet[12] || lan_packet[13] != wan_packet[13]) {
		mismatch_reason = "ethertype";
		return false;	/* ethertype */
	}

	
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
		found_packet_match(lan_element, wan_element);
	} else if(wan_element->number == lan_element->number) {
		if(verbose)  {
			fprintf(stderr, "No match -- number is the same\n");		
			classify_packet("lan", lan_element);
			classify_packet("wan", wan_element);
		}
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
	sig_child_caught = false;
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
				if(gui_pid == pid) {
					fprintf(stderr, "gui died, ignoring\n");
					run_gui = false;
					close(realtime_wireshark_fd);
					continue;
				}
				
				if(lan && lan->pid == pid) {
					fprintf(stderr, "lan dumpcap died\n");
					exit(1);
				}

				if(wan && wan->pid == pid) {
					fprintf(stderr, "wan dumpcap died\n");
					exit(1);
				
				}
				if(pid == writing_pid) {
					assert(true == writing_mismatches);
					log_wtime("writing process seen ended\n");
					writing_mismatches = false;
					continue;
				}			
				fprintf(stderr, "child died %d\n", pid);
				break;
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
//			fprintf(stderr, "tracer = %d\n", child);
			return child;
	}

       // see https://stackoverflow.com/questions/284325/how-to-make-child-process-die-after-parent-exits/17589555#17589555
	// not sure why this isn't working
	
	prctl(PR_SET_PDEATHSIG, SIGTERM);       // linux only, didn't know about it
	log_wtime("launching dumpcap for %s\n", interface);

	close_and_repopen(1, interface);
	close_and_repopen(2, interface);
	
	if(filter)
		execlp(capture_program, capture_program, "-i",  interface,  "-w", 
			named_pipe, "-f", filter, NULL);
	else execlp(capture_program, capture_program,  "-i", interface, "-w", named_pipe, NULL);

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

	
	if(!interface) {
		fprintf(stderr, "no %s interface/file\n", type_of_stream);
		exit(1);
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
//		fprintf(stderr, "capturing %s %s:%s\n", type_of_stream, interface, stringize_mac_addr(mac_addr));

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
#if 0
	fprintf(stderr, "free packet element: %p\n", this);
#endif
	TEST_MAGIC(this);
	free_block(this->block);
	TEST_MAGIC(this);
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
	
#if 0
	show_mac_address("packet source", block->packet + 6);
	show_mac_address("packet dest", block->packet);
	show_mac_address("target", mac_addr);
#endif

	if(!memcmp(block->packet + 6, mac_addr, 6))  {
//		fprintf(stderr, "egress\n");
		return true;
	} else {
//		fprintf(stderr, "ingress\n");
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


static void try_to_find_peer(bool is_wan, struct packet_element *packet)
{
	TEST_MAGIC(packet);
	assert(packet->peer == NULL);
	if(true == is_wan) {
		/* packet is wan packet */
		struct packet_element *lan_packet;

		for(lan_packet = lan->packet_queue.head; lan_packet; lan_packet = lan_packet->next) {
			bool result;

			if(lan_packet->peer)
				continue;
			result = compare_packets(lan_packet, packet);
			if(verbose > 0) {
				fprintf(stderr, "wan packet %d: %s  with lan packet %d\n",
						packet->number, 
						true == result ? "match" : "no match", 
						lan_packet->number);
			}
			if(true == result) {
				return;
			}
		}
	} else {
		struct packet_element *wan_packet;
		
		for(wan_packet = wan->packet_queue.head; wan_packet; wan_packet = wan_packet->next) {
			bool result; 

			if(wan_packet->peer)
				continue;
			result = compare_packets(packet, wan_packet);
			if(verbose > 0) {
				fprintf(stderr, "lan packet %d %s with wan packet %d\n",
					packet->number, true == result ? "match" : "no match",
					wan_packet->number);
			}
			if(true == result) {
				return;
			}
		}
	}
}


static bool interesting_icmp_packet(uint8_t *icmp_packet)
{
	int i;

	for(i = 0; i < icmp_interesting.num; i++) {
		if(*icmp_packet == icmp_interesting.array[i])
			return true;
	}
	
	return false;
}

static bool interesting_tcp_packet(uint8_t *tcp_packet)
{
	uint16_t src_port;
	uint16_t dest_port;
	int i;

	src_port = ntohs(*(uint16_t *) tcp_packet);
	dest_port = ntohs(*(uint16_t *) (tcp_packet + 2));
	
#if 0
	fprintf(stderr, "tcp: src port = %d, dest port = %d\n", src_port, dest_port);
#endif
	for(i = 0; i < tcp_interesting.num; i++) {
		if(src_port == tcp_interesting.array[i] || dest_port == tcp_interesting.array[i])
			return true;
	}
	
	return false;
}

static bool interesting_udp_packet(uint8_t *udp_packet)
{
	uint16_t src_port;
	uint16_t dest_port;
	int i;

	src_port = ntohs(*(uint16_t *) udp_packet);
	dest_port = ntohs(*(uint16_t *) (udp_packet + 2));
	
	for(i = 0; i < udp_interesting.num; i++) {
		if(src_port == udp_interesting.array[i] || dest_port == udp_interesting.array[i])
			return true;
	}
			 
	return false;
}
	
/* remove elements before tv, return elements remaining in queue */
static int advance_queue(struct packet_queue *queue, struct timeval *tv)
{
	int removed  = 0;

	while(queue->blocks_in_queue > 0) {
		struct packet_element *to_remove;

		to_remove = queue->head;

		if(timercmp(&to_remove->packet_time, tv, >))
			break;
		queue->head = to_remove->next;
		if(queue->head) {
			queue->head->prev = NULL;
			assert(queue->blocks_in_queue > 1);
		}
		queue->blocks_in_queue--;
		free_packet_element(to_remove);
		removed++;

		if(!queue->blocks_in_queue) {
			queue->head = NULL;
			queue->tail = NULL;
		}
	}
	if(removed > 0) 
		fprintf(stderr, "removed %d elements\n", removed);

	return queue->blocks_in_queue;
}

static int wireshark_emit_queue_until(struct tracers *tracer, struct packet_queue *queue, struct timeval *tv, int i)
{
	int removed  = 0;
	char base_comment[128];

	
	sprintf(base_comment, "%s (other)",  identify_tracer(tracer));
	while(queue->blocks_in_queue > 0) {
		struct packet_element *to_remove;
		char comment[128];

		to_remove = queue->head;

		if(timercmp(&to_remove->packet_time, tv, >))
			break;
		queue->head = to_remove->next;
		if(queue->head) {
			queue->head->prev = NULL;
			assert(queue->blocks_in_queue > 1);
		}
		queue->blocks_in_queue--;
		sprintf(comment, "%s %d", base_comment, i);
		i++;
		save_block_to_wireshark(to_remove->block, comment);
		
		free_packet_element(to_remove);
		removed++;

		if(!queue->blocks_in_queue) {
			queue->head = NULL;
			queue->tail = NULL;
		}
	}
#if 0
	if(removed > 0) {
		struct timeval now;
		
		gettimeofday(&now, NULL);
		fprintf(stderr, "%ld:%06ld wrote to wireshark %d elements %s\n", now.tv_sec, now.tv_usec, removed, base_comment);
	}
#endif

	return removed;


}


static int emit_other_queue(struct tracers *tracer, struct packet_queue *queue, struct timeval *until, int i)
{
	int packets_written = 0;

	return packets_written;
}

static int wireshark_emit_until(struct tracers *tracer, struct timeval *till_time, int i)
{
	int packets_written = 0;

	if(tracer->old_queue.blocks_in_queue > 0) {
		/* have old queue to try to write */
		packets_written = wireshark_emit_queue_until(tracer, &tracer->old_queue, till_time, i);
	}
	if(tracer->old_queue.blocks_in_queue > 0) {
		/* didn't finish this queue yet */
		return packets_written;
	}
	i += packets_written;   /* new index */
	packets_written += wireshark_emit_queue_until(tracer, &tracer->packet_queue, till_time, i);

	return packets_written;
}
	
static void advance_other_tracer(struct tracers *tracer, struct timeval *till_time)
{
	int remaining;
	

	remaining = advance_queue(&tracer->old_queue, till_time);
	if(!remaining) {
		advance_queue(&tracer->packet_queue, till_time);
	}
}

/* test if packet passes inner filter rules -- if no inner filter, than all packets pass */
static void test_inner_filter(struct packet_element *this_element)
{
	unsigned char *packet;
	unsigned char *ipv4_packet;
	uint16_t ethertype;
	uint8_t protocol_type;
	int ip_header_size;

	if(!config_file) {
		/* no config file, all packets interesting */
		this_element->passed_inner_filter = true;
		return;
	}

	this_element->passed_inner_filter = false;	/* start off false */
	packet = this_element->block->packet;	
	ethertype = ntohs(* (uint16_t *) (packet + 12));

	if(ethertype  != 0x800) 
		return; 	/* ignore non-ipv4 packets */
	
	ipv4_packet = packet + 14;	/* start of IP  packet */
	protocol_type = *(ipv4_packet+  + 9);
	ip_header_size = *ipv4_packet & 0xf;
	ip_header_size *= 4;

	switch(protocol_type) {
		case 1:	/* icmp packet */
			this_element->passed_inner_filter = interesting_icmp_packet(ipv4_packet + ip_header_size);
			break;
		case 6:	/* tcp packet */
			this_element->passed_inner_filter = interesting_tcp_packet(ipv4_packet + ip_header_size);
#if 0
			fprintf(stderr, "interesting tcp packet returned %d\n", this_element->passed_inner_filter);
#endif
			break;
		case 17: /* udp packet */
			this_element->passed_inner_filter = interesting_udp_packet(ipv4_packet + ip_header_size);
			break;
		default:
			break;
	}			
}

/* count and return packets < this_time in this tracer */
static int count_packets_till_time(struct tracers *tracer, struct timeval this_time)
{
	int packets = 0;
	struct packet_element *this_packet;

	for(this_packet = tracer->old_queue.head; this_packet; this_packet = this_packet->next) {
		if(timercmp(&this_packet->packet_time,  &this_time, >)) {
			return packets;
		}
		packets++;
	}

	/* look at main queue */
	for(this_packet = tracer->packet_queue.head; this_packet; this_packet = this_packet->next) {
		if(timercmp(&this_packet->packet_time, &this_time, >)) {
			return packets;
		}
		packets++;
	}
	
	/* return sum of both queues */
	return packets;
}

static struct packet_element *unlink_head_element(struct packet_queue *this_queue)
{
	struct packet_element *to_remove;
	
	to_remove = this_queue->head;
	if(NULL == to_remove) {
		assert(0 == this_queue->blocks_in_queue);
		return NULL;
	}

	assert(to_remove->prev == NULL);
	this_queue->head = to_remove->next;

	if(this_queue->head) {
		this_queue->head->prev = NULL;
	} else {
		/* queue better be empty */
		assert(this_queue->tail == to_remove);
		assert(this_queue->blocks_in_queue  == 1);
		this_queue->tail = NULL;
	}
	this_queue->blocks_in_queue--;
	return to_remove;
}

/* this_element is already unlinked, add it to the old queue */
static void just_remove(struct tracers *this_tracer, struct packet_element *this_element) 
{

	/* add the element to the old_queue, maybe freeing the head element if too big */
	struct packet_queue *queue;

	if(0 == prepend_queue)  {
		free_packet_element(this_element);
		assert(0);	// this isn't right 
		return;
	}

	queue = &this_tracer->old_queue;
	queue->blocks_in_queue++;
	if(queue->blocks_in_queue > prepend_queue) {
		/* pop off the head element */
		struct packet_element *to_remove;

		to_remove = queue->head;
		queue->head = to_remove->next;
		if(NULL == queue->head) {
			queue->tail = NULL;
			/* queue should be empty -- need to insert one element */
			assert(queue->blocks_in_queue == 1);
		} else	{
			queue->head->prev = NULL;
		}
		free_packet_element(to_remove);
		queue->blocks_in_queue--;
	}
	
	/* add this element to the tail -- already incremented */
#if 0
	fprintf(stderr, "add element to old queue = %p\n", this_element);
#endif
	if(NULL == queue->head) {
		/* empty queue */
		assert(NULL == queue->tail);
		queue->head = queue->tail = this_element;
		this_element->next = this_element->prev = NULL;
		assert(1 == queue->blocks_in_queue);
	} else {
		assert(queue->tail);	
		this_element->prev = queue->tail;
		queue->tail->next = this_element;
		queue->tail = this_element;
		this_element->next = NULL;
	}
}

static void erase_queue(struct packet_queue *queue)
{
	while(queue->head) {
		struct packet_element *next;

		next = queue->head->next;
		free_packet_element(queue->head);
		queue->head = next;
		if(next) {
			next->prev = NULL;
		}
		queue->blocks_in_queue--;
		if(!next) {
			assert(queue->blocks_in_queue == 0);
			assert(NULL == queue->head);
			queue->tail = NULL;
			return;
		}
	}
}



/* advance the queue -- and return number of non-peer (triggers?) if passed inner_filter */
static int advance_queue_after_trigger(struct tracers *ptracer)
{
	int how_many;
	int triggers_seen = 0;
	struct packet_queue *queue;

	queue = &ptracer->packet_queue;
	if(queue->blocks_in_queue > prepend_queue)
		how_many = prepend_queue;
	else 	how_many = queue->blocks_in_queue/2;	// ??
	
	log_wtime("%s: remove %d\n", identify_tracer(ptracer),  how_many);

	while(how_many > 0) {
		struct packet_element *to_remove;

		to_remove = unlink_head_element(queue);
		assert(to_remove);
		if(to_remove->passed_inner_filter && !to_remove->peer) 
			triggers_seen++;
		just_remove(ptracer, to_remove);
		how_many--;
	}

	return triggers_seen;
}

static void erase_old_packets(struct tracers *this_tracer)
{
	int num_triggers;
	struct packet_element *p;

	/* erase old queues */
	erase_queue(&wan->old_queue);
	erase_queue(&lan->old_queue);

	p =  unlink_head_element(&this_tracer->packet_queue);
	if(p)
		just_remove(this_tracer, p);
	num_triggers = advance_queue_after_trigger(wan);
	num_triggers += advance_queue_after_trigger(lan);
	log_wtime("advance, seen %d triggers\n", num_triggers);
	
}

/* look to see if this packet has a peer -- if not, write out to wireshark the prepend queue (emptying queue)
 * and this packet
 */
static void move_to_old_queue(struct tracers *this_tracer, struct packet_element *this_element)
{
	TEST_MAGIC(this_element);

	if(true == this_element->passed_inner_filter && !this_element->peer && true == start_triggers) {
		static int trigger;
		struct timeval limit_time;
		char trigger_comment[128];
		struct timeval delta_limit = { 0, 100 * 1000 }; 	// 100 msec
		char comment_base[128];
		char comment[128];
		struct tracers *other_tracer;
		int trigger_queue_number = 0;    /* starts at -, ends in + at the trigger  */
		int other_queue_base_number;	/* to offset in the "other queue" */
		struct timeval start;
		struct timeval stop;
		struct timeval delta;
		pid_t pid;


		if( true == writing_mismatches) {
//			log_wtime("want to write, but writing mismatches\n");
			just_remove(this_tracer, this_element);
			return;
		}
	
		pid = fork();
		log_wtime("PID %d: fork returned %d\n", getpid(), pid); 
		switch(pid) {
			default:
				mismatch_number++;
				trigger++;
				writing_mismatches = true;
				writing_pid = pid;
				erase_old_packets(this_tracer);
				return;
			case -1:
				log_wtime("fork failed: %s\n", strerror(errno));
				exit(1);
			case 0:
				break;
		}

		/* child process */
			
		gettimeofday(&start, NULL);

		setup_mismatched_file(mismatch_number);

		if(this_tracer == wan)
			other_tracer = lan;
		else	other_tracer = wan;
		
		/* save prequeue and this element to wireshark */
		struct packet_element *to_remove;
		struct packet_queue *queue;

		log_wtime("lan read = %d, wan read = %d, pre lan = %d,  pre wan = %d, post lan = %d, post wan = %d\n", 
			lan->packets_read, wan->packets_read,
			lan->old_queue.blocks_in_queue, wan->old_queue.blocks_in_queue,
			lan->packet_queue.blocks_in_queue, wan->packet_queue.blocks_in_queue);
				

		sprintf(comment_base, "%s: prequeue", identify_tracer(this_tracer));
		queue = &this_tracer->old_queue;

		if(queue->blocks_in_queue > 0) {
			fprintf(stderr, "old queue has %d\n", queue->blocks_in_queue);
			assert(queue->head && queue->tail);
			trigger_queue_number = -queue->blocks_in_queue;
		}

		to_remove = queue->head;
		
		if(to_remove) {
			TEST_MAGIC(to_remove);
			advance_other_tracer(other_tracer, &to_remove->packet_time);
		}

		/* figure out how many packets are in other queue */
		other_queue_base_number = count_packets_till_time(other_tracer,  this_element->packet_time);
		other_queue_base_number = -other_queue_base_number; 	/* make negative */

		while(to_remove) {
			TEST_MAGIC(to_remove);
			other_queue_base_number += wireshark_emit_until(other_tracer, &to_remove->packet_time,
						other_queue_base_number);

			sprintf(comment, "%s: %d", comment_base, trigger_queue_number);
			trigger_queue_number++;
			save_block_to_wireshark(to_remove->block, comment);
			queue->head = to_remove->next;
			queue->blocks_in_queue--;	

			free_packet_element(to_remove);

			if(queue->head) {
				queue->head->prev = NULL;
				assert(queue->blocks_in_queue > 0);
			} else {
				queue->head = NULL;
				queue->tail = NULL;
				assert(queue->blocks_in_queue == 0);
			}
			to_remove = queue->head;
			
		}
		log_wtime("%d: trigger packet\n", trigger);
		sprintf(trigger_comment, "trigger %s #%d", identify_tracer(this_tracer),
					trigger);
		trigger++;
		save_block_to_wireshark(this_element->block, trigger_comment);
		no_peers++;
		timeradd(&this_element->packet_time, &delta_limit, &limit_time);
		free_packet_element(this_element);

		sprintf(comment_base, "%s: postqueue", identify_tracer(this_tracer));

		queue = &this_tracer->packet_queue;
		to_remove = queue->head;
		log_wtime("lan post queue = %d, wan post queue = %d\n", lan->packet_queue.blocks_in_queue, 
						wan->packet_queue.blocks_in_queue);

		while(to_remove && timercmp(&to_remove->packet_time, &limit_time, <)) {
			TEST_MAGIC(to_remove);

			other_queue_base_number += wireshark_emit_until(other_tracer, &to_remove->packet_time,
							other_queue_base_number);

			sprintf(comment, "%s %d", comment_base, trigger_queue_number);
			trigger_queue_number++;
			save_block_to_wireshark(to_remove->block, comment);
			queue->head = to_remove->next;
			queue->blocks_in_queue--;	

			free_packet_element(to_remove);

			if(queue->head) {
				queue->head->prev = NULL;
				assert(queue->blocks_in_queue > 0);
			} else {
				queue->head = NULL;
				queue->tail = NULL;
				assert(queue->blocks_in_queue == 0);
			}
			to_remove = queue->head;

		}
		close(mismatched_packet_fd);
		mismatched_packet_fd = -1;
		gettimeofday(&stop, NULL);
		timersub(&stop, &start, &delta);
		log_wtime("time to write: %ld.%06ld\n", delta.tv_sec, delta.tv_usec);
#if 0
		if(mismatch_number > 3)
			kill(getppid(), SIGTERM);
#endif
		exit(0);
	} else {
		just_remove(this_tracer, this_element);
	}
}


static void queue_packet(struct tracers *tracer, struct block_info *block)
{
	struct packet_element *this_element;
	struct packet_queue *this_queue;
	bool egress;
	uint64_t seconds;
	uint64_t fraction;

	this_element = calloc(sizeof *this_element, 1);
	SET_MAGIC(this_element);
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

	this_element->number = ++tracer->packets_read;
	test_inner_filter(this_element);
	++tracer->unmatched;
	if(verbose > 0) 
		fprintf(stderr, "%d: %s: %f  packet %s, direction %s\n",  this_element->number, tracer->interface,
			 packet_delay(&this_element->enqueue_time),
			 true == tracer->wan ? "wan" : "lan",
			true == egress  ? "egress" : "ingress");

	seconds = block->packet_time / tracer->clock_divisor;
	fraction = block->packet_time % tracer->clock_divisor;;
	if(verbose > 0) 
		fprintf(stderr, "enqueue time: %ld:%ld, pcap time = %ld:%ld\n",
			this_element->enqueue_time.tv_sec, this_element->enqueue_time.tv_usec,
			seconds, fraction);
	this_element->packet_time.tv_sec = seconds;
	this_element->packet_time.tv_usec = fraction / tracer->fraction_divisor;
			
	if(true == track_packets) {
		struct timeval delta;

		timersub(&this_element->enqueue_time, &this_element->packet_time, &delta);
		fprintf(stderr, "%s read %d, time = %f, delay = %ld.%06ld\n", 
				true == tracer->wan ? "wan" : "lan", this_element->number,
				packet_delay(&this_element->packet_time), delta.tv_sec, 
				delta.tv_usec);
	}

	if(verbose > 0) {
		fprintf(stderr, "ethertype = 0x%02x ", ntohs(*( unsigned short *) (block->packet + 12)));
	// mac header is 14 bytes
		fprintf(stderr, "source address = %s ",  inet_ntoa(*(struct in_addr *) (block->packet + 26)));
		fprintf(stderr, "dest   address = %s ",  inet_ntoa(*(struct in_addr *) (block->packet + 30)));
		fprintf(stderr, "\n\n");
	}
		
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

#if 0
		to_remove = this_queue->head;
		assert(to_remove->prev == NULL);
		this_queue->head = to_remove->next;
//		assert(this_queue->tail->next == to_remove);
		if(this_queue->head) {
			this_queue->head->prev = NULL;
		} else {
			assert(this_queue->tail == to_remove);
			assert(this_queue->blocks_in_queue  == 1);
			this_queue->tail = NULL;
		}
		this_queue->blocks_in_queue--;
#else
		to_remove = unlink_head_element(this_queue);
#endif
		move_to_old_queue(tracer, to_remove);

	}
	
	try_to_find_peer(tracer->wan, this_element);
	
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
	
		
static void set_interface_id(struct block_info *block, int interface_id)
{
	assert(block->body_length > sizeof(int));
	*((int *) block->block_body) = interface_id;	/* ??? */
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
	static bool seen_section_header = false;;
	
	block = read_pcap_block(this->fd);
	if(!block)
		return false;

#if 0
	print_block(block);
#endif

	if(this->save_fd >= 0) 
		save_block(this->save_fd, block, NULL);

	switch(block->type) {
		case enhanced_packet_block:
			queue_packet(this, block);
			set_interface_id(block, this->interface_id);
			break;
		case section_header_block:
			this->section_header_list = decode_header_options(block);
			print_header_options(ascii_options_section_header, "section header", this->section_header_list);
			
			this->section_header = block;
			if(false == seen_section_header) {
				seen_section_header = true;
				save_block_to_wireshark(block, NULL);
				save_block_to_prefix(block);
			}
			return true;
		case interface_description:
			this->interface_list = decode_interface_options(block);
			print_header_options(ascii_options_interface_description, "interface_description",
						this->interface_list);
			figure_out_clock_divisor(this);
			this->interface_description = block;
			this->interface_id = ++interface_id_seen;
			save_block_to_wireshark(block, NULL);
			save_block_to_prefix(block);
			break;
		default:
			fprintf(stderr, "unknown block type  = 0x%x\n", block->type);
			free_block(block);
			break;
	}
		
	return true;
	
}


static void show_consec(const char *type, int consec, int packet_number, struct timeval *when_started)
{
	struct timeval now;
	struct timeval delta;
	double micros;


	if(false == show_consec_packets)
		return;

	gettimeofday(&now, NULL);
	timersub(&now, when_started, &delta);
	micros = delta.tv_sec * 1000000.0;
	micros += delta.tv_usec;
	fprintf(stderr, "%s: %d packets (%d), %.03f msec\n", type, consec, packet_number, micros / 1000.0);
}

static void select_on_input(void)
{
	fd_set set;
	struct tracers *this;
	int result;
	int max_fd = 0;
	struct timeval timeout = {
		.tv_sec = 0,
		.tv_usec = 500000
	};
	static struct timeval when_consec_started;
	static int consec_lan_read = 0;
	static int consec_wan_read = 0;	
	

	FD_ZERO(&set);
	for(this = tracer_list; this; this = this->next) {
		FD_SET(this->fd, &set);
		if(this->fd > max_fd)
			max_fd = this->fd;
	}
	
	result = select(max_fd + 1, &set, NULL, NULL, &timeout);
	if(result < 0) {
		fprintf(stderr, "Select failed %s\n", strerror(errno));
		return;
	}
	if(result == 0) {
		return;
	}

	for(this = tracer_list; this  && result > 0; this = this->next) {
		if(FD_ISSET(this->fd, &set)) {
			if(true == this->wan) {
				if(consec_lan_read > 20)  {
					show_consec("lan", consec_lan_read, lan->packets_read,	
							&when_consec_started);
				}
				if(consec_lan_read > 0) {
					gettimeofday(&when_consec_started, NULL);
					consec_lan_read = 0;
				}
				consec_wan_read++;
			} else {
				if(consec_wan_read > 20)  {
					show_consec("wan", consec_wan_read, wan->packets_read,	
							&when_consec_started);
				}
				if(consec_wan_read > 0) {
					gettimeofday(&when_consec_started, NULL);
					consec_wan_read = 0;
				}
				consec_lan_read++;
			}
			read_pcap_packet(this);
			result--;
		}
	}
	if(result > 0) {
		fprintf(stderr, "result not cleared\n");
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
	printf("chox [-s] [-D directory] [-g] [-q prepend queue] [-c file]  -l lan -w wan [-f filter] [-v] [-b num] [-t] [-d capture]\n");
	printf("-s -- save pcaps\n");
	printf("-l -- specify lan (downstream) tap\n");
	printf("-w -- specify wan (upstream) tap\n");
	printf("-D -- directory to store files (default to ./chox-<pid>\n");
	printf("-f -- tshark filter expression\n");
	printf("-v -- verbose\n");
	printf("-b -- max queue elements\n");
	printf("-t -- track packets\n");
	printf("-d <capture program> (default %s)\n", capture_program);
	printf("-c <config file> -- specify config file\n");
	printf("-q <prepend number> -- packets in front of anomoly (default = %d)\n", prepend_queue);	
	printf("-g\trun realtime GUI\n"); 
	printf("\ttaps are expressed \"interface_name:<mac addr>\"\n");
	exit(1);
	
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
	packets_matched++;
	if(true == track_packets)
		fprintf(stderr, "found match: wan %d, lan %d\n", wan_element->number, lan_element->number);
	lan_element->peer = wan_element;
	wan_element->peer = lan_element;
	assert(wan->unmatched > 0);
	assert(lan->unmatched > 0);
	wan->unmatched--;
	lan->unmatched--;
}


static void match_packets(void)
{
	struct packet_element *lan_element;

	for(lan_element = lan->packet_queue.head; lan_element; lan_element = lan_element->next) {
		struct packet_element *wan_element;

		if(lan_element->peer || false == lan_element->passed_inner_filter)
			continue;

		for(wan_element = wan->packet_queue.head; wan_element; wan_element = wan_element->next) {
			bool result;
			if(wan_element->peer || false == wan_element->passed_inner_filter)
				continue;
			
			result = compare_packets(lan_element, wan_element);
			if(true == result) {
				found_packet_match(lan_element, wan_element);
				break;
			}  else { 
				if(verbose > 0) {
					fprintf(stderr, "no match,  wan %d, lan %d: %s\n", 
					wan_element->number, lan_element->number, mismatch_reason); 
				}
			}
		}	
	}
}

static void find_unmatched_packets(struct tracers *this)
{
	struct packet_element *packet;
	int total_unmatched;

	for(total_unmatched = 0, packet = this->packet_queue.head; packet; packet = packet->next) {
		if(!packet->peer)
			total_unmatched++;
	}

	fprintf(stderr, "\n%s: unmatched packets %d out of %d\n", 
			identify_tracer(this), total_unmatched, this->packets_read);

	for(packet = this->packet_queue.head; packet; packet = packet->next) {
		if(!packet->peer) {
			classify_packet(identify_tracer(this), packet);
		}
	}
}

static void statistics()
{
	fprintf(stderr, "ttl same = %d, ttl off by one = %d\n",
			ttl_same_counter, ttl_off_by_one_counter);
	fprintf(stderr, "wan packets seen = %d, lan packets seen = %d\n", 
			wan->packets_read, lan->packets_read);
	fprintf(stderr, "packets matched = %d\n", packets_matched);
	fprintf(stderr, "wan unmatched = %d, lan unmatched = %d\n",
				wan->unmatched, lan->unmatched);
			
}

static void match_and_find_unmatched(void)
{
	match_packets();
	find_unmatched_packets(wan);
	find_unmatched_packets(lan);
}

static void terminate(void)
{
	fprintf(stderr, "%s\n", __func__);

	if(verbose > 0) {
		display_packet_list("lan", lan);
		display_packet_list("wan", wan);
	}
	statistics();
	if(mismatched_packet_fd >= 0 && 0 == no_peers) {
		int result;

		fprintf(stderr, "no mismatched packets\n");
		result = unlink(mismatched_name);
		if(result < 0) {
			fprintf(stderr, "Cannot unlink %s: %s\n", mismatched_name, strerror(errno));
		}
	
		if(result < 0) {
			fprintf(stderr, "Cannot rmdir %s: %s\n", output_directory, strerror(errno));
		}	
	}
	/* try to remove directory if nothing is in it */
	rmdir(output_directory);

	kill(wan->pid, SIGTERM);
	kill(lan->pid, SIGTERM);

	exit(0);
}


static void setup_mismatched_file(int number)
{
	int result;

	sprintf(mismatched_name, "%s/mismatched-%d.pcapng", output_directory, number) ;
	log_wtime("Creating mismatch file %s\n", mismatched_name);
	mismatched_packet_fd = open(mismatched_name, O_WRONLY | O_CREAT, 0644);
	if(mismatched_packet_fd < 0) {
		fprintf(stderr, "cannot created %s: %s\n", mismatched_name, strerror(errno));
		exit(1);
	}
	
	result = write(mismatched_packet_fd, prefix, prefix_length);
	assert(result == prefix_length);
}

static void setup_realtime_wireshark(void)
{
	int pipefd[2];
	int result;
	char *program = "wireshark-gtk";


	if(false == run_gui)
		return;		/* TODO: refactor this */

	result = pipe(pipefd);
	if(result < 0) {
		fprintf(stderr, "pipe failed: %s\n", strerror(errno));
		exit(1);
	}
		

	gui_pid = fork();
	switch(gui_pid) {
		case 0:
			close(pipefd[1]);
			close(0);
			dup(pipefd[0]);
			close(pipefd[0]);
			execlp(program, program, "-k", "-i", "-", NULL);
			fprintf(stderr, "cannot exec %s: %s\n", program, strerror(errno));
			exit(1);
		case -1:
			fprintf(stderr, "forked failed: %s\n", strerror(errno));
			exit(1);
		default:
			close(pipefd[0]);
			realtime_wireshark_fd = pipefd[1];
			fprintf(stderr, "wireshark pid = %d\n", gui_pid);
			break;
	}
	
}


static void load_interface(struct tracers *this)
{
	while(read_pcap_packet(this))
		;
}


/* return how many packets were timed out */
static int timeout_a_queue(struct tracers *interface, struct timeval *timeout)
{
	struct packet_queue *queue;
	struct timeval current_time;
	int packets_timedout = 0;

	queue = &interface->packet_queue;

	gettimeofday(&current_time, NULL);
	while(queue->blocks_in_queue > 0) {
		struct packet_element *to_test;
		struct timeval delta;

		to_test = queue->head;
		timersub(&current_time, &to_test->packet_time, &delta);
		if(timercmp(&delta, timeout, <))
			break;

		queue->head = to_test->next;
		if(queue->head) {
			queue->head->prev = NULL;
		} else {
			/* one element queue */
			assert(queue->tail == to_test);
			assert(queue->blocks_in_queue == 1);
			queue->tail  = NULL;
		}

		queue->blocks_in_queue--;
		move_to_old_queue(interface, to_test);
		packets_timedout++;
		
	}
#if 1
	if(packets_timedout) 
		fprintf(stderr, "Timed out %d packets in queue %s\n", packets_timedout, 
					identify_tracer(interface)); 
#endif
	return packets_timedout;
}

static void timeout_queues(void)
{
	int wan_timedout;
	int lan_timedout;

	struct timeval timeout = {
		.tv_sec = 2,
		.tv_usec = 0
	};

	wan_timedout = timeout_a_queue(wan, &timeout);
	lan_timedout = timeout_a_queue(lan, &timeout);

	if(wan_timedout || lan_timedout) {
		struct timeval now;

		gettimeofday(&now, NULL);

		if(verbose > 0) 
			log_wtime("%ld.%06ld: lan timedout = %d, wan timedout = %d\n", 
							now.tv_sec, now.tv_usec, lan_timedout, wan_timedout);
	}
}

int main(int argc, char *argv[])
{
	char *filter = NULL;
	char *wan_interface = NULL;
	unsigned char wan_mac[6];
	char *lan_interface = NULL;
	unsigned char lan_mac[6];
	struct timeval start_time;
	struct timeval target_time;	/* start_time + delta */
	struct timeval delta = { 
			.tv_sec = 1,
			.tv_usec = 0
			};
	int result;

	
	create_temp_dir();

	while(1) {
		int c;
		bool result;

		c = getopt(argc, argv, "D:c:gq:d:pb:vsf:w:l:t");
		if(-1 == c)
			break;
		switch(c) {
			case 'd':
				capture_program = strdup(optarg);
				break;
			case 'g':
				run_gui = true;
				break;
			case 'b':
				max_queue_elements = atoi(optarg);
				fprintf(stderr, "new max queue = %d\n", max_queue_elements);
				break; 
			case 'D':
				strcpy(output_directory, optarg);	
				break;
			case 'c':
				config_file = strdup(optarg);
				break;
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
			case 'q':
				prepend_queue = strtol(optarg, NULL, 0);
				fprintf(stderr, "new prepend queue = %d\n", prepend_queue);
				break;
			case 'p':
				show_consec_packets = true;
				break;
			case 'w':
				result = decode_interface(optarg, &wan_interface, wan_mac);
				if(false == result) {
					fprintf(stderr, "Need valid wan addresses: got %s\n", optarg);
					exit(1);
				}
				break;
			case 'v':
				verbose++;
				break;
			case 'f':
				filter = strdup(optarg);
				fprintf(stderr, "filter expression = \"%s\"\n", filter);
				break;
			case 't':
				track_packets = true;
				break;
			default:
				usage();
		}
	}

	if(config_file)
		parse_config_file(config_file);


	if(0 == output_directory[0]) {
		sprintf(output_directory, "./chox-%d", getpid());
	}

	result = mkdir(output_directory, 0755);
	if(result < 0) {
		fprintf(stderr, "cannot make %s: %s\n", output_directory, strerror(errno));
		exit(1);
	}

	fprintf(stderr, "Output directory = %s\n", output_directory);
	

	wan =  do_tracer(true, wan_interface, wan_mac, wan_filter);
	lan = do_tracer(false, lan_interface, lan_mac, lan_filter);

	if(!lan || !wan) {
		fprintf(stderr, "Haven't selected wan or lan\n");
		exit(1);
	}

	if(tracer_file != type_of_tracers) {
		setup_realtime_wireshark();
	} else {
		load_interface(lan);
		load_interface(wan);
		match_packets();
		statistics();
		exit(0);
	}
		
	signal(SIGCHLD, catch_child);
	signal(SIGUSR1, statistics);
	signal(SIGINT, catch_terminate);
	signal(SIGTERM,  catch_terminate);

	gettimeofday(&start_time, NULL);
	timeradd(&start_time, &delta, &target_time);
	
	while(wan && lan) {
		if(false == start_triggers) {
			struct timeval now;
	
			gettimeofday(&now, NULL);
			if(timercmp(&now, &target_time, >)) {
				start_triggers = true;
				fprintf(stderr, "starting triggers\n");
			}
		}
			
		if(true == sig_child_caught) {
			printf("caught sig child\n");
			reap_children();
		}
		if(true == terminate_program) {
			terminate();
		}
		
		timeout_queues();
		select_on_input();
	}
	return 0;
}

