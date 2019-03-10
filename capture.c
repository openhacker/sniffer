/* much is borrowed from Tim Carstens sniffex.c demo */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pcap.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdbool.h>


#define SNAP_LEN   1518

static void usage(void)
{
	fprintf(stderr, "capture -i <interface> -f <filter> -w output\n");
	exit(EXIT_FAILURE);
}

static void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	fprintf(stderr, "\ntime = %d:%06d, caplen = %d, len = %d\n",
			header->ts.tv_sec, header->ts.tv_usec, header->caplen, header->len);
}


main(int argc, char *argv[])
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
		
		c = getopt(argc, argv, "i:w:f:");
		if(-1 == c) 
			break;

		switch(c) {
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

	pcap_loop(handle, 0, got_packet, NULL);
	                             
	pcap_freecode(&bpf);
	pcap_close(handle);
	return 0;
}

