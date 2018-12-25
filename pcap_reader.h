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

enum option_code {
	opt_endofopt = 0,
	opt_comment = 1,
};
	

struct interface_info {
	char *name;
	char *description;
	unsigned char ts_resolv;
	uint32_t units_per_sec;		// from ts_resolv 
};	

struct block_info {
	enum block_type type;
	int block_length;
	int body_length;
	/* block_length - 12 == body_length */
	void *block_body;
	unsigned char *packet; /*  within block body */
	uint64_t packet_time;
	uint32_t captured_packet_length;
	uint32_t original_packet_length;
	uint32_t interface_id;
};


struct block_info *read_pcap_block(int fd);
void print_block(struct block_info *this);
void free_block(struct block_info *this);
void save_block(int fd, struct block_info *this);
void print_enhanced_packet_block(struct block_info *pblock);

#endif

