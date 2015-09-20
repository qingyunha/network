#include "ping.h"

int datalen = 56;

int main(int argc, char **argv)
{
	struct addrinfo hints, *res;
	int errcode;
	char *h;

	if(argc != 2){
		fprintf(stderr, "usage: ping <hostname>\n");
		exit(1);
	}

	pid = getpid() & 0xffff;
	if(signal(SIGALRM, sig_alrm) == SIG_ERR){
		perror("signal error");
		exit(120);
	}
/*
	sasend.sin_family = AF_INET;
	if(inet_pton(AF_INET, argv[1], &sasend.sin_addr) <= 0){
		perror("inet_pton error");
		exit(2);
	}
	salen = sizeof(sasend);
*/
 	bzero(&hints, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_flags = AI_CANONNAME;
	if((errcode=getaddrinfo(argv[1], NULL, &hints, &res)) != 0){
		fprintf(stderr,"getaddrinfo error: %s\n", gai_strerror(errcode));
		exit(5);
	}
	salen = res->ai_addrlen;
	if(memcpy((void *)&sasend, (void *)res->ai_addr, salen) == NULL){
		fprintf(stderr, "memcpy error\n");
		exit(5);
	}
/*
	if(inet_ntop(res->ai_family, res->ai_addr, h, 20) == NULL){
		fprintf(stderr, "inet_ntop error\n");
		exit(45);
	}
*/
	if((h = inet_ntoa(sasend.sin_addr)) == NULL){
		fprintf(stderr, "inet_ntoa error\n");
		exit(45);
	}
	printf("PING %s (%s): %d data bytes\n",
						res->ai_canonname ? res->ai_canonname : argv[1],
						h, datalen);
						
	readloop();
	exit(0);

}


void readloop()
{
	int size;
	char recvbuf[BUFSIZE];
	char controlbuf[BUFSIZE];
	struct msghdr msg;
	struct iovec iov;
	ssize_t n;
	struct timeval tval;

	if((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP))<0){
		perror("socket error");
		exit(4);
	}
	
	size = 60 * 1024;
	setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));
	
	sig_alrm(SIGALRM);	
	
	iov.iov_base = recvbuf;
	iov.iov_len = sizeof(recvbuf);
	msg.msg_name = &sarecv;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = controlbuf;

	while(1){
		msg.msg_namelen = salen;
		msg.msg_controllen = sizeof(controlbuf);
		n = recvmsg(sockfd, &msg, 0);
		if(n < 0)
			if(errno == EINTR)
				continue;
			else{
				perror("recvmsg erro");
				exit(3);
			}

		if(gettimeofday(&tval, NULL)<0){
			perror("gettimeoftaday error");
			exit(6);
		}
		proc_reply(recvbuf, n, &msg, &tval);
	}
}


void sig_alrm(int signo)
{
	send_icmp();
	alarm(1);
	return;
}


void proc_reply(char *ptr, ssize_t len, struct msghdr *msg, struct timeval *tvrecv)
{
	int iphd_len, icmplen;
	double rrt;
	struct ip *ip;
	struct icmp *icmp;
	struct timeval *tvsend;

	ip = (struct ip *)ptr;
	iphd_len = ip->ip_hl << 2;	
	if(ip->ip_p != IPPROTO_ICMP)
		 return;

	icmp = (struct icmp *)(ptr + iphd_len);
	icmplen = len - iphd_len;
	if(icmplen < 8)
		 return;

	if(icmp->icmp_type == ICMP_ECHOREPLY){
		if(icmp->icmp_id != pid)
			 return;

		if(icmplen < 16)
			 return;
		tvsend = (struct timeval *)icmp->icmp_data;
		tv_sub(tvrecv, tvsend);
		rrt = tvrecv->tv_sec * 1000.0 + tvrecv->tv_usec/1000.0;

		printf("%d bytes from %s: seq=%u, ttl=%d, rtt=%.3f ms\n",
				icmplen, inet_ntoa(sarecv.sin_addr),
				icmp->icmp_seq, ip->ip_ttl, rrt);
	}
	
}


void send_icmp()
{
	int len;
	struct icmp *icmp;
	
	icmp = (struct icmp*)sendbuf;
	icmp->icmp_type = ICMP_ECHO;
	icmp->icmp_code = 0;
	icmp->icmp_id = pid;
	icmp->icmp_seq = nsent++;
	memset(icmp->icmp_data, 0xa5, datalen);
	if(gettimeofday((struct timeval *)icmp->icmp_data, NULL)<0){
		perror("send_icmp gettimeoftaday error");
		exit(6);
	}

	len = datalen + 8;
	icmp->icmp_cksum = 0;
	icmp->icmp_cksum = in_cksum((u_short *)icmp, len);
	if(sendto(sockfd, sendbuf, len, 0, 
								(struct sockaddr *)&sasend, salen) < 0)
	{
		perror("sendto error");
		exit(8);
	}
/*
	int i;
	for(i=0; i<16; i++)
		printf("0x%02hhx ",sendbuf[i]); 
	printf("\n");
*/
}

uint16_t in_cksum(uint16_t *addr, int len)
{
	int nleft = len;
	uint32_t sum = 0;
	uint16_t *w = addr;
	uint16_t answer = 0;

	while(nleft > 1){
		sum += *w++;
		nleft -= 2;
	}

	if(nleft == 1){
		*(uint8_t *)(&answer) = *(uint8_t *)w;
		sum += answer;
	}

	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	answer = ~sum;
	return(answer);
}



void tv_sub(struct timeval *out, struct timeval *in)
{
	if((out->tv_usec -= in->tv_usec) < 0){
		--out->tv_sec;
		out->tv_usec += 1000000;
	}
	out->tv_sec -= in->tv_sec;
}




