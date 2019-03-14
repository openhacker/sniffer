/* much is borrowed from Tim Carstens sniffex.c demo */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pcap.h>
#include <unistd.h>
#include <limits.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <stdarg.h>
#include <assert.h>


#define SNAP_LEN   1518

static int verbose = 0;


enum opt_name {
        opt_endofopt = 0,
        opt_comment = 1,
        shb_hardware = 2,
        shb_os = 3,
        shb_userappl = 4,
        if_name = 2,
        if_description = 3,
        if_IPv4addr = 4,
        if_IPv6addr = 5,
        if_MACaddr = 6,
        if_EUIaddr = 7,
        if_speed = 8,
        if_tsresol = 9,
        if_tzone = 10,
        if_filter = 11,
        if_os = 12, 
        if_fsclen = 13,
        if_tsoffset = 14,
        if_hardware = 15
};

enum block_type {
        interface_description = 1,
        packet_block = 2,
        simple_packet_block = 3,
        name_resolution_block = 4,
        interface_statistics_block = 5,
        enhanced_packet_block = 6,
        section_header_block = 0x0a0d0d0a
};


static int output_fd = -1;

struct block {
	void *data;
	int size;
};

static const uint32_t zero = 0;
static struct block end_of_opt = {
		.data = &zero,
		.size = sizeof zero
};

static bool write_block(enum block_type type, ...);


static void usage(void)
{
	fprintf(stderr, "capture -i <interface> -f <filter> -w output\n");
	exit(EXIT_FAILURE);
}

static void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	struct block packet_block;
	unsigned char prefix[20];
	struct block prefix_block = {
		.data = prefix,
		.size = sizeof prefix
	};
	uint64_t timestamp;
	uint32_t high_order_ts;
	uint32_t low_order_ts;

	packet_block.data = packet;
	packet_block.size = header->caplen;
	timestamp = header->ts.tv_sec * 1000000L;
	timestamp += header->ts.tv_usec;
	high_order_ts = timestamp >> 32;
	low_order_ts = (uint32_t ) (timestamp & 0xffffffffL);
	fprintf(stderr, "timestamp = %lx, high order = %x, low order = %x\n",
			timestamp, high_order_ts, low_order_ts);
	*(uint32_t *) (prefix + 4) = high_order_ts;
	*(uint32_t *) (prefix + 8) = low_order_ts;
	*(int32_t *) prefix = 0;	/* interface id */
	*(int32_t *) (prefix + 12) =  header->caplen;
	*(int32_t *) (prefix + 16) = header->len;

	
	fprintf(stderr, "\ntime = %ld:%06ld, caplen = %d, len = %d\n",
			header->ts.tv_sec, header->ts.tv_usec, header->caplen, header->len);
	
	
	write_block(enhanced_packet_block, &prefix_block, &packet_block, &end_of_opt, NULL);
}

static int round_to_dword(int n)
{
	return (n + 3)   & ~0x3;
}


static void print_block(int i, struct block *p)
{
	int count;

	if(!verbose)
		return;
	fprintf(stderr, "block #%d\n", i);
	fprintf(stderr, "block  %d bytes\n", p->size);

	for(count = 0; count < p->size; ) {
		int loop;

			
		for(loop = 0; loop < 16 && count < p->size; count++, loop++) {
			unsigned char c;
			c =  *((char *) p->data + count);
			fprintf(stderr, "x%02x %c " , c, isascii(c) ? c : ' ');
		}
		fprintf(stderr, "\n");
	}
}

/* write a section of blocks -- compute how the total we need (each block needs to rounded up to  a double word */
static bool write_block(enum block_type type,  ...)
{
	
	const int MAX_BLOCK = 2000;
	va_list ap;
	int block_size = 0;
	char block[MAX_BLOCK];
	char *current;  // where inserting into current block;
	int result;
	int i = 0;

	*(uint32_t *) block = type;

	block_size = 8;
	current = &block[block_size];

	va_start(ap, type);
	while(1) {
		struct block *this;
		int actual_size;

		this = va_arg(ap, struct block *);
		if(!this) 
			break;

		print_block(i++, this);
		memcpy(current, this->data, this->size);
		actual_size = round_to_dword(this->size);		
		current += actual_size;
		block_size += actual_size;
	}

	*(int32_t *) (block + block_size) = block_size + 4;
	block_size += 4;
	*(int32_t *) (block + 4) = block_size;
	result = write(output_fd, block, block_size);
	fprintf(stderr, "wrote block of %d\n", block_size);
	assert(result == block_size);
	return true;	
}

static void free_ascii_option(struct block *ascii_option)
{
	free(ascii_option->data);
	free(ascii_option);
}

static struct block *construct_ascii_option(enum opt_name option, const char *string)
{
	struct block *new_block;
	int length;
	int rounded_length;

	new_block = malloc(sizeof *new_block);
	length = strlen(string);
	rounded_length = round_to_dword(length);
	new_block->data = malloc(rounded_length + 4);
	new_block->size = rounded_length + 4;
	*(unsigned short *) new_block->data = option;
	*(unsigned short *) (new_block->data + 2) = length;
	memcpy(new_block->data + 4, string, length);

	return new_block;
}


static void generate_section_header(void)
{
	struct block *hardware;
	struct block *os;
	struct block *userappl;
	struct block prefix;
	char prefix_data[16];
	char hostname[HOST_NAME_MAX];
	char version[2048];
	int fd;
	uint32_t zero = 0;
	int result;
	
	
	*(uint32_t *) prefix_data = 0x1a2b3c4d;
	*(uint16_t *) (prefix_data + 4) = 1;
	*(uint16_t *) (prefix_data + 6) = 0;
	*(int64_t *) (prefix_data + 8) = -1L;
	prefix.data = prefix_data;
	prefix.size = sizeof(prefix_data);

	gethostname(hostname, sizeof hostname);
	hardware = construct_ascii_option(shb_hardware,  hostname);
	
	fd = open("/proc/version", O_RDONLY);
	if(fd < 0) {
		fprintf(stderr, "Cannot open /proc/version: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
	result = read(fd, version, sizeof version);
	assert(result < sizeof version);
	close(fd);
	*(version + result) = '\0';
	
	os =  construct_ascii_option(shb_os, version);
	userappl = construct_ascii_option(shb_userappl, "chox capture");
	
	write_block(section_header_block,  &prefix, hardware, os, hardware, userappl, &end_of_opt, NULL);

}

static void generate_interface_description(const char *interface, const char *filter)
{
	struct block *name_option;
	struct block *filter_option;
 	short prefix_data[4] = { 1, 0, 0, 0};
	struct block prefix;
	struct block resolution;
	short resolv_data[3] = { if_tsresol, 1, 0x606 };	/* first 6 is useful */
	
	

	prefix.data = prefix_data;
	prefix.size = sizeof(prefix_data);

	resolution.data = resolv_data;
	resolution.size = 5;
	
	name_option = construct_ascii_option(if_name, interface);
	filter_option = construct_ascii_option(if_filter, filter);

	write_block(interface_description, &prefix, name_option, filter_option, &resolution, &end_of_opt, NULL);
}

static void prime_pcap_file(const char *interface, const char *filter, const char *filename)
{
	output_fd = open(filename, O_WRONLY | O_CREAT, 0644);
	if(output_fd < 0) {
		fprintf(stderr,  "Cannot create %s: %s\n", filename, strerror(errno));
		exit(EXIT_FAILURE);
	}

	generate_section_header();
	generate_interface_description(interface, filter);
}
		
	

int main(int argc, char *argv[])
{
	char *dev = NULL;
	char *filter_exp = NULL;
	char errbuf[PCAP_ERRBUF_SIZE];
	char *output = NULL;
	bpf_u_int32 mask;
	bpf_u_int32 net;
	struct bpf_program bpf;
	int result;
	pcap_t *handle;
	
	while(1) {
		int c;
		
		c = getopt(argc, argv, "i:w:f:v");
		if(-1 == c) 
			break;

		switch(c) {
			case 'v':
				verbose++;
				break;
			case 'i':
				dev = strdup(optarg);
				break;
			case 'f':
				filter_exp = strdup(optarg);
				break;
			case 'w':
				output = strdup(optarg);
				break;
			default:
				usage();
		}
	}

	if(!dev || !filter_exp || !output)       {
		fprintf(stderr, "Missing parameter\n");
		usage();
	}

	result = pcap_lookupnet(dev, &net, &mask, errbuf);
	if(result == -1) {
		fprintf(stderr, "pcap_lookup net failed\n");
	}
	handle = pcap_open_live(dev, SNAP_LEN, 1, 10, errbuf);
	if(!handle) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		exit(EXIT_FAILURE);	
	}

	if(pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "%s is not an Ethernet\n", dev);
		exit(EXIT_FAILURE);
	}

	result = pcap_compile(handle, &bpf, filter_exp, 0, net);
	if(result == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n",
			filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	result = pcap_setfilter(handle, &bpf);
	if(-1 == result) {
		fprintf(stderr, "Couldn't install filter %s: %s\n",
			filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	prime_pcap_file(dev, filter_exp, output);
	pcap_loop(handle, 0, got_packet, NULL);
	                             
	pcap_freecode(&bpf);
	pcap_close(handle);
	return 0;
}

