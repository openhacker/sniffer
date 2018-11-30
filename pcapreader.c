#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <stdbool.h>
#include "pcap_reader.h"



static struct block_info *read_section_header_block(FILE *f)
{
	return NULL;
}

static struct block_info *get_new_block(enum block_type block_type, uint32_t length)
{
	struct block_info *block;

	block = calloc(sizeof *block, 1);
	assert(block);
	block->type = block_type;
	block->block_length = length;
	block->body_length = length - 12;
	block->block_body = malloc(block->body_length);
	assert(block->block_body);
	return block;
}

#if 0
static struct block_info *get_block(int fd, enum block_type block_type, uint32_t length)
{
	struct block_info *block;

	block = get_new_block(block_type, length);
	return block;
	
}
#endif

#if 0
static struct block_info *read_pcap_block(FILE *f)
{
	
	enum block_type block_type;
	struct block_info *block;
	uint32_t block_length;
	uint32_t second_length;
	int result;

	result = fread((uint32_t *) &block_type, sizeof block_type, 1, f);
	assert(1 == result);
	result = fread(&block_length, sizeof block_length, 1, f);
	assert(1 == result);

	block = get_block(f, block_type, block_length - 12);
	assert(block);
	result = fread(block->block_body, 1, block->body_length, f);
	assert(result == block->body_length);

	result = fread(&second_length, sizeof second_length, 1, f);
	assert(1 == result);
	assert(second_length == block_length);
	return block;
}
#endif
	

static char *ascii_block_type(enum block_type block_type)
{
	switch(block_type) {
		case interface_description:	return "interface description";
		case packet_block:		return "packet block";
		case simple_packet_block:	return "simple packet block";
		case name_resolution_block:	return "name resolution block";
		case interface_statistics_block:	return "interface statistics block";
		case enhanced_packet_block:		return "enhanced packet block";
		case section_header_block:		return "section header block";
		default:				return "unknown block type";
	}

}

static void print_option_value(const char *comment, char *body, int length)
{
	printf("\n%s\n", comment);
	while(*body  &&  length > 0)  {
		putchar(*body);
		body++;
		length--;
	}
	putchar('\n');
}


static int print_option(char *body, int length)
{
	short option_type;
	int option_length;
	
	option_type = *(short *) body;
	option_length = *(short *) (body + 2);
	printf("option type = %d, option length = %d\n", option_type, option_length);
	

	switch(option_type) {
		case 2:
			print_option_value("shb_hardware", body + 4, option_length);
			break;
		case 3:
			print_option_value("shb_os", body + 4, option_length);
			break;
		case 4:
			print_option_value("shb_userappl", body + 4, option_length);
			break;
	}

	/* round up to size to 4 bytes? */
	option_length += 4;
	if(option_length & 0x3)
		option_length = (option_length & ~0x3) + 4;
		
	printf("option length = %d\n", option_length);
	return option_length ;
}

static void print_section_header_block(void *body, int length)
{
	printf("byte order magic = 0x%08x\n", *(int *) body);
	printf("major = %d, minor = %d\n", *(short  *) (body + 4), *(short *) (body + 6));
	printf("section length = %ld\n", *(long *) (body + 8));
	length -= 16;
	body += 16;
	while(length > 0) {
		int option_length;

		option_length = print_option(body, length);
		length -= option_length;
		body += option_length;
	}
	 	
}

static int print_interface_option(void *body, int length) 
{
	short option_code;
	short option_length;

	option_code = *(short *) body;
	option_length = *(short *) (body + 2);
	body += 4;
	switch(option_code) {
		case 2:
			print_option_value("if_name",  body, option_length);
			break;
		case 3:
			print_option_value("if_description", body, option_length);
			break;
		case 11:
			print_option_value("if_filter", body, option_length);
			break;
		case 12:
			print_option_value("if_os", body, option_length);
			break;
		case 15:
			print_option_value("if_hardware", body, option_length);
			break;
		default:
			printf("interface option value = %d\n", option_code);
	}
	option_length += 4;
	if(option_length & 0x3) 
		option_length = (option_length & ~0x3) + 4;
	return option_length;	
}

static void print_interface_description_block(void *body, int length)
{
	short linktype;
	int snaplen;

	linktype = *(short *) body;
	snaplen = *(int *) (body + 4);
	printf("interface description block: linktype = %d, snaplen = %d\n", linktype, snaplen);
	body += 8;
	length -= 8;
	while(length > 0) {
		int option_length;

		option_length = print_interface_option(body, length);
		length -= option_length;
		body += option_length;
	}
}

static void print_packet(unsigned char *p, int length)
{
	while(length > 0) {
		int i;

		for(i = 0; i < 8 && length > 0; i++, length--, p++) {
			printf("%02x ", *p);
		}
		printf("\n");
	}
		
}

static void print_enhanced_packet_block(void *body, int length)
{
	uint32_t interface_id;
	uint32_t timestamp_high;
	uint32_t timestamp_low;
	uint32_t captured_packet_length;
	uint32_t original_packet_length;
	void *packet;
	
	interface_id = *(uint32_t *) body;
	body  += 4;
	timestamp_high = *(uint32_t *) body;
	body += 4;
	timestamp_low = *(uint32_t *) body;
	body += 4;
	captured_packet_length = *(uint32_t *) body;
	body += 4;
	original_packet_length = *(uint32_t *) body;
	body += 4;
	packet = body;


	printf("interface_id = %d, timestamp = 0x%08x%08x, captured packet length = %d, original packet length = %d\n",
		interface_id, timestamp_high, timestamp_low, captured_packet_length, original_packet_length);
	print_packet(packet, captured_packet_length);
	
		
}


void print_block(struct block_info *block)
{
	printf("block type = %s body length = %d\n", ascii_block_type(block->type), block->body_length);
	switch(block->type) {
		case section_header_block:
			print_section_header_block(block->block_body, block->body_length);
			break;
		case interface_description:
			print_interface_description_block(block->block_body, block->body_length);
			break;
		case enhanced_packet_block:
			print_enhanced_packet_block(block->block_body, block->body_length);
			break;
		default:
			break;
	}
}

	

void free_block(struct block_info *block)
{
	free(block->block_body);
	free(block);
}

struct block_info *read_pcap_block(int fd)
{
	enum block_type block_type;
	struct block_info *block;
	uint32_t block_length;
	uint32_t second_length;
	int result;

	result = read(fd, (uint32_t *) &block_type, sizeof block_type);
	assert(sizeof block_type == result);
	result = read(fd, &block_length, sizeof block_length);
	assert(result == sizeof block_length);

	
	block = get_new_block(block_type, block_length);
	assert(block);

	result = read(fd, block->block_body, block->body_length);
	assert(result == block->body_length);

	result = read(fd, &second_length, sizeof second_length);
	assert(sizeof second_length == result);
	assert(second_length == block_length);
	return block;
}

void save_block(int fd, struct block_info *this)
{
	int result;

	result = write(fd, &this->type, sizeof this->type);
	assert(result == sizeof this->type);
	result = write(fd, &this->block_length, sizeof this->block_length);
	assert(result == sizeof this->block_length);
	result = write(fd, this->block_body, this->body_length);
	assert(result == this->body_length);

	result = write(fd, &this->block_length, sizeof this->block_length);
	assert(result == sizeof this->block_length);

}


#ifdef DEBUG

static int read_pcap(FILE *f)
{
	while(true) {
		struct block_info *block;
		block = read_pcap_block(f);
		if(NULL == block)
			break;
		print_block(block);
		free_block(block);
	}
	return 0;
	
}

int main(int c, char *argv[])
{
	read_pcap(stdin);	
	exit(0);
}
#endif
