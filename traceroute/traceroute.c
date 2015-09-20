#include "traceroute.h"

int datalen = sizeof(struct rec);
int max_ttl = 30;
int nprobes = 3;
uint16_t dport = 42349;


int main(int argc, char **argv)
{
	struct addrinfo hints, *res;
	struct sigaction act;
	char *h;
	int errcode;

	if(argc != 2){
		fprintf(stderr, "usage: traceroute <hostname>\n");
		exit(1);
	}
	host = argv[1];

	pid = getpid();

	act.sa_handler = sig_alrm;
	sigemptyset(&act.sa_mask);
	act.sa_flags = SA_INTERRUPT;
	if(sigaction(SIGALRM, &act, NULL) != 0){
		perror("sigaction error");
		exit(42);
	}

	bzero(&hints, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_flags = AI_CANONNAME;
	if((errcode=getaddrinfo(argv[1], NULL, &hints, &res)) != 0){
		fprintf(stderr,"getaddrinfo error: %s\n", gai_strerror(errcode));
		exit(5);
	}

	if((h = inet_ntoa(((struct sockaddr_in *)res->ai_addr)->sin_addr)) == NULL){
		fprintf(stderr, "inet_ntoa error\n");
		exit(45);
	}
	printf("traceroute to %s (%s): %d hops max, %d data bytes\n",
						res->ai_canonname ? res->ai_canonname : argv[1],
						h, max_ttl, datalen);

	salen = res->ai_addrlen;
	sasend = *(res->ai_addr);
	
	traceloop();
	exit(0);
}


void traceloop()
{
	int seq, code, done;
	double rrt;
	struct rec *rec;
	struct timeval recvtv;

	if((recvfd = socket(sasend.sa_family, SOCK_RAW, IPPROTO_ICMP))<0){
		perror("socket error");
		exit(4);
	}
	if((sendfd = socket(sasend.sa_family, SOCK_DGRAM, 0))<0){
		perror("socket error");
		exit(5);
	}

/*
	struct timeval t;
	t.tv_sec = 3;
	t.tv_usec = 0;
	if(setsockopt(recvfd, SOL_SOCKET, SO_RCVTIMEO, &t, sizeof(t)) < 0)
	{
		perror("setsocketopt error");
		exit(45);
	}
*/
	sabind.sin_family = sasend.sa_family;
	sabind.sin_addr.s_addr = htonl(INADDR_ANY);
	sport = (getpid() & 0xffff) | 0x8000;
	sabind.sin_port = htons(sport);
	if(bind(sendfd, (struct sockaddr *)&sabind, sizeof(struct sockaddr)) < 0){
		perror("bind erro");
		exit(45);
	}

	seq = 0;
	done = 0;
	for(ttl = 1; ttl <= max_ttl && done == 0; ttl++){
		if(setsockopt(sendfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(int)) < 0){
			perror("setsockopt error");
			exit(34);
		}
		bzero(&salast, salen);

		printf("%2d ", ttl);
		fflush(stdout);

		for(probe = 0; probe < nprobes; probe++){
			rec = (struct rec *)sendbuf;
			rec->rec_seq = ++seq;
			rec->rec_ttl = ttl;
			if(gettimeofday(&rec->rec_tv, NULL)<0){
				perror("gettimeoftaday error");
				exit(6);
			}
			
			((struct sockaddr_in *)&sasend)->sin_port = htons(dport+seq);
			
			if(sendto(sendfd, sendbuf, datalen, 0, &sasend, salen)<0){
				perror("sendto error");
				exit(9);
			}

			code = receive(seq, &recvtv);
			if(code == -3)
				printf(" *");
			else{
				char str[NI_MAXHOST];
				if(memcmp(&salast, &sarecv, salen) != 0){	
					if(getnameinfo(&sarecv, salen, str, sizeof(str), 
									NULL, 0, 0) == 0)
						printf("%s (%s)", str, 
						inet_ntoa(((struct sockaddr_in *)&sarecv)->sin_addr));

					memcpy(&salast, &sarecv, salen);
				}
				tv_sub(&recvtv, &rec->rec_tv);
				rrt = recvtv.tv_sec * 1000.0 + recvtv.tv_usec/1000.0;
				printf("  %.3f ms", rrt);

				if(code == -1)
					done++;
				else if(code > 0)
					printf("(ICMP %d)", code);
			}
			fflush(stdout);
		}//3 times probe done
		printf("\n");
	}//30 ttl done
}

int receive(int seq, struct timeval *tv)
{
	int hlen1, hlen2, icmplen, ret;
	socklen_t len;
	ssize_t n;
	struct ip *ip, *hip;
	struct icmp *icmp;
	struct udphdr *udp;

	gotalarm = 0;
	alarm(3);
	while(1){
		if(gotalarm)
			return(-3);
		len = salen;
		n = recvfrom(recvfd, recvbuf, sizeof(recvbuf),0, &sarecv, &len);
		if(n < 0){
			if(errno == EINTR)
				continue;
			else{
				perror("recvfrom error");
				exit(4);
			}
		}

		ip = (struct ip *)recvbuf;
		hlen1 = ip->ip_hl << 2;

		icmp = (struct icmp *)(recvbuf + hlen1);

		if( (icmplen = n - hlen1) < 8)
			continue;

		if(icmp->icmp_type == ICMP_TIMXCEED && 
			icmp->icmp_code == ICMP_TIMXCEED_INTRANS){
			if(icmplen < 8 + sizeof(struct ip))
				continue;
			
			hip = (struct ip *)(recvbuf + hlen1 + 8);
			hlen2 = hip->ip_hl << 2;
			if(icmplen < 8 + hlen2 + 4)
				continue;
			
			udp = (struct udphdr *)(recvbuf + hlen1 + 8 + hlen2);
			
			if(hip->ip_p == IPPROTO_UDP && 
				udp->uh_sport == htons(sport) &&
					udp->uh_dport == htons(dport+seq)){
				ret = -2;
				break;
			}

		}else if(icmp->icmp_type == ICMP_UNREACH){
			if(icmplen < 8 + sizeof(struct ip))
				continue;
			
			hip = (struct ip *)(recvbuf + hlen1 + 8);
			hlen2 = hip->ip_hl << 2;
			if(icmplen < 8 + hlen2 + 4)
				continue;
			
			udp = (struct udphdr *)(recvbuf + hlen1 + 8 + hlen2);
			if(hip->ip_p == IPPROTO_UDP && 
				udp->uh_sport == htons(sport) &&
					udp->uh_dport == htons(dport+seq)){
				if(icmp->icmp_code = ICMP_UNREACH_PORT)
					ret = -1;
				else
					ret = icmp->icmp_code;
				break;
			}
		}

	}//while

	alarm(0);
	if(gettimeofday(tv, NULL)<0){
			perror("gettimeoftaday error");
			exit(6);
	}
	return(ret);
}

void sig_alrm(int signo)
{
	gotalarm = 1;
	return;
}



void tv_sub(struct timeval *out, struct timeval *in)
{
	if((out->tv_usec -= in->tv_usec) < 0){
		--out->tv_sec;
		out->tv_usec += 1000000;
	}
	out->tv_sec -= in->tv_sec;
}
