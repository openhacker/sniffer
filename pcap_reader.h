#ifndef _PCAP_READER_H
#define _PCAP_READER_H

#include <stdint.h>

enum block_type {
	interface_description = 1,
	packet_block = 2,
	simple_packet_block = 3,
	name_resolution_block = 4,
	interface_statistics_block = 5,
	enhanced_packet_block = 6,
	section_header_block = 0x0a0d0d0a
};



/* the options for section header and interface need to be used differently, since they don't have unique option numbers */
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

enum opt_type {
	char_pointer,
	char_single,
	val_32bit,
	val_64bit,
	mac_addr,
	byte_array
};

struct pcap_option_element {
	enum opt_name name;
	enum opt_type type;
	int byte_array_length;		/* only for byte array */
	union {
		char *value;
		char c;
		uint32_t value32;
		uint64_t value64;
		uint8_t mac_addr[6];
		char *byte_array;
	};
	struct pcap_option_element *next;
};
	
	
#define MAGIC
struct block_info {
	enum block_type type;
	int block_length;
	int body_length;
	/* block_length - 12 == body_length */
	void *block_body;
	unsigned char *packet; /*  within block body */
	uint64_t packet_time;	/* in pcap format */
	struct timeval timeval;	/* in timeval format after divisor */
	uint32_t captured_packet_length;
	uint32_t original_packet_length;
	uint32_t interface_id;
#ifdef MAGIC
	void *indirect;
	void *magic;
#endif
};


#ifdef MAGIC
#define SET_INDIRECT(x, p) { x->indirect = p; }
#define TEST_INDIRECT(x, p) { assert(x->indirect == p); }
#define SET_MAGIC(x) 	{ x->magic  = x; }
#define TEST_MAGIC(x)	{ assert(x == x->magic); }
#else
#define SET_INDIRECT(x, p)
#define TEST_INDIRECT(x, p)
#define SET_MAGIC(x)
#define TEST_MAGIC(x)
#endif


struct block_info *read_pcap_block(int fd);
void print_block(struct block_info *this);
void free_block(struct block_info *this);
void save_block(int fd, struct block_info *this, const char *comment);
void print_enhanced_packet_block(struct block_info *pblock);
struct pcap_option_element *decode_header_options(struct block_info *this);
struct pcap_option_element *decode_interface_options(struct block_info *this);

#endif

