#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
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
#include "pcap_reader.h"

static bool sig_child_caught = false;

static bool pause_children = false;

static char temp_dir[128];

static bool save_pcaps = false;

static int max_queue_elements = 100;

struct packet_element {
	struct timeval enqueue_time;
	struct block_info *block;
	bool ingress;	/* true for coming in, false for going out */
	struct packet_element *next;
	struct packet_element *prev;
};
	
struct packet_queue {
	struct packet_element *head;
	struct packet_element *tail;
	int blocks_in_queue;
};

struct tracers {
	char *pipe;
	int fd;		/* read fd for pipe */
	int save_fd;	/* if -1, don't save, otherwise save all reads to this file for later analysis */
	bool upstream;
	pid_t pid;
	char *interface;
	unsigned char mac_addr[6];
	struct packet_queue packet_queue;
	struct tracers *next;
	struct tracers *prev;
};

static enum type_of_tracers { tracer_file, tracer_tshark, tracer_unknown } type_of_tracers = tracer_unknown;
static struct tracers *tracer_list;

static struct tracers *upstream;
static struct tracers *downstream;


static struct block_info *read_pcap_packet(struct tracers *this);

static int catch_child(int signo)
{
	sig_child_caught = true;	
	return 0;
}

static void print_tracer_packets(struct tracers *this)
{
	struct packet_element *packet;

	for(packet = this->packet_queue.tail; packet; packet = packet->prev) {
		assert(enhanced_packet_block == packet->block->type);
		print_enhanced_packet_block(packet->block);
	}
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
				remove_tracer(pid);
		}
	}
}


static struct tracers *new_tracer(int fd, const char *pipe, const char *interface, pid_t pid, bool upstream)
{
	static int save_num = 0;
	struct tracers *new;

	new = calloc(sizeof *new, 1);
	new->pipe = strdup(pipe);
	new->interface = strdup(interface);
	new->pid = pid;
	new->fd = fd;
	new->next = tracer_list;
	new->upstream = upstream;
	tracer_list = new;
	if(true == save_pcaps) {
		char pcap_save_file[128];
	
		assert(type_of_tracers == tracer_tshark);

		sprintf(pcap_save_file, "%s-%d-%d", (true == upstream) ? "upstream" : "downstream",
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
	return new;
		
}

#if 0
static char **add_argv(char **old_argv, int size, char *new_arg)
{
}

static void exec_parser(const char *command)
{
	char **argv = NULL;
	char *progname = NULL;

	
}
#endif


static int run_tracer(const char *named_pipe,  const char *interface)
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

	prctl(PR_SET_PDEATHSIG, SIGTERM);       // linux only, didn't know about it
       // see https://stackoverflow.com/questions/284325/how-to-make-child-process-die-after-parent-exits/17589555#17589555
	
	execlp("tshark", "tshark", "-i",  interface,  "-w", 
			named_pipe, "-f", "port ssh", NULL);
	printf("should never get here\n");
	exit(1);
}

static char *stringize_mac_addr(unsigned char mac_addr[6])
{
	static unsigned char ascii[6 * 3 + 1];
	int i;
	char *p = &ascii;

	for(i = 0; i <= 5; i++) {
		sprintf(p, "%02x:", mac_addr[i]);
		p += 3;
	}
	p--;
	*p = '\0';
	return &ascii;
}
	
static struct tracers *do_tracer(bool upstream, const char *interface, unsigned char mac_addr[6])
{
	static int num = 0;
	char named_pipe[128];
	pid_t pid = 0;
	int result;
	int fd;
	char *type_of_stream;
	char *p;

	if(true == upstream) {
		type_of_stream = "upstream";
	} else {
		type_of_stream = "downstream";
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
		fprintf(stderr, "capturing %s %s:%s\n", upstream == true ? "upstream" : "downstream", interface, stringize_mac_addr(mac_addr));

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
		pid = run_tracer(named_pipe, interface);
	}
	
	return new_tracer(fd, named_pipe, interface, pid, upstream);
	
}

static void free_packet_element(struct packet_element *this)
{
	free_block(this->block);
	free(this);
}
	

static void queue_packet(struct tracers *tracer, struct block_info *block)
{
	struct packet_element *this_element;
	struct packet_queue *this_queue;

	this_element = calloc(sizeof *this_element, 1);
	assert(this_element != NULL);
	gettimeofday(&this_element->enqueue_time, NULL);
	this_queue = &tracer->packet_queue;
	this_element->block = block;
	
	if(this_queue->head)
		this_queue->head->prev = this_element;
	this_element->next = this_queue->head;
	this_queue->head = this_element;
	if(0 == this_queue->blocks_in_queue) {
		/* empty queue */
		this_queue->tail = this_element;
	} 
	this_queue->blocks_in_queue++;
	if(this_queue->blocks_in_queue > max_queue_elements) {
		/* get rid of tail of queue */
		struct packet_element *to_remove;

		to_remove = this_queue->tail;
		this_queue->tail = to_remove->prev;
		assert(this_queue->tail->next == to_remove);
		this_queue->tail->next = NULL;
		this_queue->blocks_in_queue--;
		free_packet_element(to_remove);
	}
	
}

static struct block_info *read_pcap_packet(struct tracers *this)
{
	struct block_info *block;
	
	block = read_pcap_block(this->fd);
	if(!block)
		return NULL;

	print_block(block);
	if(this->save_fd >= 0) 
		save_block(this->save_fd, block);
	if(enhanced_packet_block == block->type) {
		queue_packet(this,  block);
	} else {
		free_block(block);	
	}
	return block;
	
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
	printf("\ttaps are expressed \"interface_name:<mac addr>\"\n");
	exit(1);
	
}


	
static void compare_streams(void)
{
}

static bool decode_interface(char *arg, char **interface, char mac_addr[6])
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

main(int argc, char *argv[])
{
	create_temp_dir();
	signal(SIGCHLD, catch_child);
	char *wan_interface;
	unsigned char wan_mac[6];
	char *lan_interface;
	unsigned char lan_mac;

	while(1) {
		int c;
		bool result;

		c = getopt(argc, argv, "sw:l:");
		if(-1 == c)
			break;
		switch(c) {
			case 's':
				save_pcaps = true;
				break;
			case 'l':
				result = decode_interface(optarg, &lan_interface, &lan_mac);
				if(false == result) {
					fprintf(stderr, "Need valid lan addresses: got %s\n", optarg);
					exit(1);
				}
				break;	
			case 'w':
				result = decode_interface(optarg, &wan_interface, &wan_mac);
				if(false == result) {
					fprintf(stderr, "Need valid wan addresses: got %s\n", optarg);
					exit(1);
				}
				break;
			default:
				usage();
		}
	}


	upstream =  do_tracer(true, wan_interface, &wan_mac);
	downstream = do_tracer(false, lan_interface, &lan_mac);

	if(!upstream || !downstream) {
		fprintf(stderr, "Haven't select upstream or downstream\n");
		exit(1);
	}

	if(tracer_file == type_of_tracers) {
		compare_streams();
	} else {
		while(upstream && downstream) {
			if(true == sig_child_caught) {
				printf("caught sig child\n");
				reap_children();
			}
			select_on_input();
		}
	}
}

