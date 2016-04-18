#include<pcap.h>
#include<stdio.h>
#include<stdlib.h> // for exit()
#include<string.h> //for memset
#include<sys/socket.h>
#include<arpa/inet.h> // for inet_ntoa()
#include<net/ethernet.h>
#include<netinet/ip_icmp.h>   //Provides declarations for icmp header
#include<netinet/udp.h>   //Provides declarations for udp header
#include<netinet/tcp.h>   //Provides declarations for tcp header
#include<netinet/ip.h>    //Provides declarations for ip header
#include<assert.h>
#include <stdbool.h>
#define BUFFSIZE 1518
struct sockaddr_in source,dest;
void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
{
    int size = header->len;
    //Get the IP Header part of this packet , excluding the ethernet header
    struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
	if(iph->protocol==6)
	{
		printf("here\n");
    		unsigned short iphdrlen;   
    		iphdrlen = iph->ihl*4; 
    		struct tcphdr *tcph=(struct tcphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));         
		int header_size =  sizeof(struct ethhdr) + iphdrlen + tcph->doff*4;	 
		printf("\n\n***********************TCP Packet*************************\n");  
		printf("TCP Header\n");
		printf("   |-Source Port      : %u\n",ntohs(tcph->source));
		printf("   |-Destination Port : %u\n",ntohs(tcph->dest));
		printf("   |-Sequence Number    : %u\n",ntohl(tcph->seq));
		printf("   |-Acknowledge Number : %u\n",ntohl(tcph->ack_seq));
		printf("   |-Header Length      : %d DWORDS or %d BYTES\n" ,(unsigned int)tcph->doff,(unsigned int)tcph->doff*4);
		printf("   |-Urgent Flag          : %d\n",(unsigned int)tcph->urg);
		printf("   |-Acknowledgement Flag : %d\n",(unsigned int)tcph->ack);
		printf("   |-Push Flag            : %d\n",(unsigned int)tcph->psh);
		printf("   |-Reset Flag           : %d\n",(unsigned int)tcph->rst);
    		printf("|-Synchronise Flag     : %d\n",(unsigned int)tcph->syn);
    		printf("   |-Finish Flag          : %d\n",(unsigned int)tcph->fin);
    		printf("   |-Window         : %d\n",ntohs(tcph->window));
    		printf("   |-Checksum       : %d\n",ntohs(tcph->check));
    		printf("   |-Urgent Pointer : %d\n",tcph->urg_ptr);
    		printf("\n");
    		memset(&source, 0, sizeof(source));
    		source.sin_addr.s_addr = iph->saddr;
    		memset(&dest, 0, sizeof(dest));
    		dest.sin_addr.s_addr = iph->daddr;
    		printf("IP Header\n");
    		printf("   |-IP Version        : %d\n",(unsigned int)iph->version);
    		printf("   |-IP Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);
    		printf("   |-Type Of Service   : %d\n",(unsigned int)iph->tos);
    		printf("   |-IP Total Length   : %d  Bytes(Size of Packet)\n",ntohs(iph->tot_len));
    		printf("   |-Identification    : %d\n",ntohs(iph->id));
    		printf("   |-TTL      : %d\n",(unsigned int)iph->ttl);
    		printf("   |-Protocol : %d\n",(unsigned int)iph->protocol);
    		printf("   |-Checksum : %d\n",ntohs(iph->check));
    		printf("   |-Source IP        : %s\n" , inet_ntoa(source.sin_addr) );
    		printf("   |-Destination IP   : %s\n" , inet_ntoa(dest.sin_addr) );
	}
}
int main(int argc, char *argv[])
{
    	char errbuf[BUFFSIZE];
	pcap_if_t *alldevs,*device;
	pcap_t *handle = NULL;
	assert(pcap_findalldevs(&alldevs,errbuf) >= 0);
	device = alldevs;
	while(device != NULL)
	{
		if(!strcmp(device->name,"eth0"))
		{
			printf("Found data\n");
			handle = pcap_open_live(device->name,BUFFSIZE,1,0,errbuf);
			assert(handle != NULL);
			break;	
		}
		device = device->next;
	}
	pcap_loop(handle,-1,process_packet,NULL);
	return 0;   
}
