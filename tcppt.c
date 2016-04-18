#include <pcap/pcap.h>
#include <unistd.h>
#include <stdio.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <stdbool.h>
#include <assert.h>
#include <string.h>
#define BUFFSIZE 65536
int tcp = 0;
int udp = 0;
void processPacket(u_char *args, const struct pcap_pkthdr *header, const u_char *buff){
struct iphdr *iph = (struct iphdr*)(buff+sizeof(struct ethhdr));
int iphdrlen = iph->ihl*4; //iphdr is variable size

struct tcphdr *tcph = (struct tcphdr*)(buff+iphdrlen+sizeof(struct ethhdr)); //ethhdr is fixed size
if(iph->protocol == 6){
tcp++;
printf("source port: %d\n",ntohs(tcph->source));
printf("dest port: %d\n",ntohs(tcph->dest));
printf("sequence number: %u\n",ntohl(tcph->seq));
//printf("TCP data receievd\n");
}
// else if(iph->protocol == 17){
// udp++;
// printf("UDP data receievd\n");
// }
}

int main(int argc, char const *argv[])
{
char errbuf[BUFFSIZE];
pcap_if_t *alldevs,*device;
pcap_t *handle = NULL;
assert(pcap_findalldevs(&alldevs,errbuf) >= 0);
device = alldevs;
while(device != NULL){
if(!strcmp(device->name,"eth0")){
printf("Found data\n");
handle = pcap_open_live(device->name,BUFFSIZE,1,0,errbuf);
assert(handle != NULL);
break;
}
device = device->next;
}
pcap_loop(handle,-1,processPacket,NULL);
return 0;
}
