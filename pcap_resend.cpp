/*
yum install libnet
yum install libnet-devel
g++ pcap_resend.cpp -lnet -o resend
wangxx created 2017-03-16 19:15
*/

#include <sys/time.h>
#include <sys/types.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/types.h>
#include <stdint.h>
#include <libnet.h>

                                    
#define PCAP_MAGIC  0xa1b2c3d4  /* magic constants for various pcap file types */
#define DEFAULT_MTU 1500        /* Max Transmission Unit of standard ethernet
                                                 * don't forget *frames* are MTU + L2 header! */
#define MAXPACKET 16436         /* MTU of Linux loopback */
#define MAX_SNAPLEN 65535       /* tell libpcap to capture the entire packet */

struct pcap_file_header {
        unsigned int  magic;
        unsigned short int version_major;
        unsigned short int version_minor;
        int thiszone;     /* gmt to local correction */
        unsigned int sigfigs;    /* accuracy of timestamps */
        unsigned int snaplen;    /* max length saved portion of each pkt */
        unsigned int linktype;   /* data link type (LINKTYPE_*) */
};
struct pcap_pkthdr {
        time_t ts;//struct timeval ts;  /* time stamp */
        unsigned int caplen;     /* length of portion present */
        unsigned int len;        /* length this packet (off wire) */
};

struct packet {
	unsigned char data[MAXPACKET];       /* pointer to packet contents */
	unsigned int len;                    /* length of data (snaplen) */
	unsigned int actual_len;             /* actual length of the packet */
	time_t ts;          /* timestamp */
};

struct ethernet_ip_hdr
{
	uint8_t  ether_dhost[6];/* destination ethernet address */
	uint8_t  ether_shost[6];/* source ethernet address */
	uint16_t ether_type;    /* protocol */
	uint8_t  ip_ver_hdrlen; 
	uint8_t  ip_tos;  
	uint16_t ip_total_len;         /* total length */
	uint16_t ip_id;          /* identification */
	uint16_t ip_frag;
	uint8_t  ip_ttl;          /* time to live */
	uint8_t  ip_proto;            /* protocol */
	uint16_t ip_hdrCRC;         /* checksum */
	uint8_t  ip_src[4];
	uint8_t  ip_dst[4];
};

/* return flag if this is a pcap file */
/*
retCode
0 fail
1 success
*/
int is_pcap_file_format(int fd,struct pcap_file_header * pcapFileHdrPtr)
{

	if (lseek(fd, 0, SEEK_SET) != 0) 
	{
		fprintf(stderr,"Unable to seek to start of file\n");
		return 0;
	}

	if (read(fd, (void *) pcapFileHdrPtr, sizeof( struct pcap_file_header )) != sizeof( struct pcap_file_header ))
	{
		fprintf(stderr,"Unable to read whole pcap file hdr of file\n");
		return 0;
	}

	switch (pcapFileHdrPtr->magic) 
	{
		case PCAP_MAGIC:
		break;    
		default:
		{
			fprintf(stderr,"Unable to resolve the magic number %d \n",pcapFileHdrPtr->magic);
			return 0;
		}
	}

	/* version, snaplen, & linktype magic */
	if (pcapFileHdrPtr->version_major != 2)
	{
		fprintf(stderr,"Unable to resolve the version_major number %d \n",pcapFileHdrPtr->version_major);
		return 0;
	}


	if (pcapFileHdrPtr->linktype != 1)
	{
		fprintf(stderr,"Only could resolve the ethernet linktype packet, not %d \n",pcapFileHdrPtr->linktype);
		return 0;
	}

	return 1;
}

void print_pcap_file_header(struct pcap_file_header * pcapFileHdrPtr)
{
	printf("magic number: %X \n",pcapFileHdrPtr->magic);
	printf("version_major: %d \n",pcapFileHdrPtr->version_major);
	printf("version_minor: %d \n",pcapFileHdrPtr->version_minor);
	printf("gmt to local correction: %d \n",pcapFileHdrPtr->thiszone);
	printf("accuracy of timestamps: %d \n",pcapFileHdrPtr->sigfigs);
	printf("max snap length: %d \n",pcapFileHdrPtr->snaplen);
	printf("linktype(1 for ethernet): %d \n",pcapFileHdrPtr->linktype);
}

int pcap_file_get_next_packet(int fd, struct packet *pkt)
{
	struct pcap_pkthdr p1, *p;

	if (read(fd, &p1, sizeof(p1)) != sizeof(p1)){
		return 0;
	}
	p = &p1;

	pkt->len = p->caplen;
	/* stupid OpenBSD, won't let me just assign things, so I've got
	* to use a memcpy() instead
	*/
	memcpy(&(pkt->ts), &(p->ts), sizeof(time_t));
	pkt->actual_len = p->len;

	if (read(fd, &pkt->data, pkt->len) != pkt->len){
		return 0;
	}

	return pkt->len;
}

int pcap_file_print( char * pcapFilePathPtr )
{
	struct pcap_file_header phdr;
	int packet_counter;
	struct packet pkt;
	int fd;
	int i;


	if ( ( fd=open(pcapFilePathPtr,O_RDONLY) )==-1 )
	{
		fprintf(stderr,"error: open file error %s",pcapFilePathPtr);
		return 1;
	}

	if( is_pcap_file_format(fd,&phdr) )
	{
		print_pcap_file_header(&phdr);
	}
	else
	{
		fprintf(stderr, "error: the file %s is not .pcap format\n",pcapFilePathPtr);    
		return 1;
	}

	packet_counter=0;
	while(1)
	{
		if(pcap_file_get_next_packet(fd,&pkt))
		{
			packet_counter++;
			printf("snaplen: %d actual_len: %d packet_counter: %d \n",pkt.len,pkt.actual_len,packet_counter);
			for(i=0; i<pkt.len; ++i)
			{
				printf(" %02x", pkt.data[i]);
				if( (i + 1) % 16 == 0 )
				{
					printf("\n");
				}
			}
			printf("\n\n");
		}
		else 
		{
			break;
		}
	}

	close(fd);
	return 0;

}



int build_send_ethernet_packet(const char * dev,const unsigned int sendTimes,
                   const unsigned char * dst_mac,const unsigned char * src_mac,
                               const uint16_t protoType,const unsigned char * padPtr,const unsigned int padLength
                               )
{
	libnet_t *net_t = NULL; 
	char err_buf[LIBNET_ERRBUF_SIZE];
	libnet_ptag_t p_tag; 
	unsigned int i=0;

	//init the libnet context structure
	net_t  = libnet_init(LIBNET_LINK_ADV, dev, err_buf);     
	if(net_t == NULL)
	{
		fprintf(stderr,"libnet_init error:%s\n",err_buf);
		return 1;
	}

	//build the ethernet packet
	p_tag = libnet_build_ethernet(//create ethernet header
	dst_mac,//dest mac addr
	src_mac,//source mac addr
	protoType,//protocol type
	padPtr,//payload
	padLength,//payload length
	net_t,//libnet context
	0//0 to build a new one
	);
	if(-1 == p_tag)
	{
		fprintf(stderr,"libnet_build_ethernet error!\n");
		fprintf(stderr,"BuildAndSendEthernetPacket: %s",net_t->err_buf);
		goto FAIL;
	}

	for(i=0;i<sendTimes;i++){
		if(-1 == libnet_write(net_t))
		{
			fprintf(stderr,"B libnet_write error!\n");
			fprintf(stderr,"BuildAndSendEthernetPacket: %s",net_t->err_buf);
			goto FAIL;
		}
	}

	libnet_destroy(net_t);
	return 0;
	FAIL:        
	libnet_destroy(net_t);
	return 1;
}


int pcap_ip_repaly( char * pcapFilePathPtr, int usecDelayPerPacket, char * devName)
{
	struct pcap_file_header phdr;
	struct ethernet_ip_hdr * hdrPtr;
	int packet_counter;
	struct packet pkt;
	int fd;
	int i;


	if ( ( fd=open(pcapFilePathPtr,O_RDONLY) )==-1 )
	{
		fprintf(stderr,"error: open file error %s",pcapFilePathPtr);
		return 1;
	}

	if( is_pcap_file_format(fd,&phdr) )
	{
		print_pcap_file_header(&phdr);
	}
	else
	{
		fprintf(stderr, "error: the file %s is not .pcap format\n",pcapFilePathPtr);    
		return 1;
	}

	packet_counter=0;
	while(1)
	{
		if(pcap_file_get_next_packet(fd,&pkt))
		{
			usleep(usecDelayPerPacket);
			packet_counter++;
			//analyze packet and send it
			hdrPtr=(struct ethernet_ip_hdr *) pkt.data;
			if( hdrPtr->ether_type==0x0008) //filter: ip type: 0x0800 -> little endian 0x0008
			{
				// print packet information
				printf("ether: %02x:%02x:%02x:%02x:%02x:%02x ->",hdrPtr->ether_shost[0],hdrPtr->ether_shost[1]
				,hdrPtr->ether_shost[2],hdrPtr->ether_shost[3],hdrPtr->ether_shost[4],hdrPtr->ether_shost[5]);
				printf(" %02x:%02x:%02x:%02x:%02x:%02x   ",hdrPtr->ether_dhost[0],hdrPtr->ether_dhost[1]
				,hdrPtr->ether_dhost[2],hdrPtr->ether_dhost[3],hdrPtr->ether_dhost[4],hdrPtr->ether_dhost[5]);
				printf("ip: %d.%d.%d.%d ->",hdrPtr->ip_src[0],hdrPtr->ip_src[1],hdrPtr->ip_src[2],hdrPtr->ip_src[3]);
				printf(" %d.%d.%d.%d \n",hdrPtr->ip_dst[0],hdrPtr->ip_dst[1],hdrPtr->ip_dst[2],hdrPtr->ip_dst[3]);
				if(pkt.len==pkt.actual_len)
				{
					printf("whole packet:padPtr is %x,padLength is %d \n",pkt.data+14,pkt.len-14);
					if (build_send_ethernet_packet(devName,1, hdrPtr->ether_dhost, hdrPtr->ether_shost,0x0800,pkt.data+14,pkt.len-14)==0){
						printf("resend packet success :) \n");
					}
					else{
						printf("resend packet fail :( \n");
					}
				}
				else
				{
					fprintf(stderr,"this packet is not entire,cannot resend :(");
				}

			}
			else
			{ 
				if(hdrPtr->ether_type==0x0608) //filter: ip type: 0x0806 -> little endian 0x0608
				{printf("arp packet \n");}
				else if(hdrPtr->ether_type==0x3508) //filter: ip type: 0x0835 -> little endian 0x3508
				{printf("rarp packet \n");}
				else
				{printf("unknown packet type\n");}
			}
			//print packet
			printf("snaplen: %d actual_len: %d packet_counter: %d \n",pkt.len,pkt.actual_len,packet_counter);
			for(i=0; i<pkt.len; ++i)
			{
				printf(" %02x", pkt.data[i]);
				if( (i + 1) % 16 == 0 )
				{
					printf("\n");
				}
			}
			printf("\n\n");
		}
		else 
		{
			break;
		}
	}

	close(fd);
	return 0;

}

int main()
{
	return  pcap_ip_repaly("/home/wp.pcap",0,"eth1");
}