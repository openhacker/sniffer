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



enum opt_name {
	opt_enedofopt = 0,
	opt_comment = 1,
	shb_hardware = 2,
	shb_of = 3,
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
	if_tsoffet = 14,
	if_hardware = 15
};

enum opt_type {
	char_pointer,
	char_single,
	val_32bit,
	val_64bit,
	mac_addr
};

struct pcap_option_element {
	enum opt_name name;
	enum opt_type type;
	union {
		char *value;
		char c;
		uint32_t value32;
		uint64_t value64;
		uint8_t mac_addr[6];
	};
	struct pcap_option_element *next;
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
struct pcap_option_element *decode_header_options(struct block_info *this);
struct pcap_option_element *decode_interface_options(struct block_info *this);

#endif

