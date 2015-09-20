#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <setjmp.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <errno.h>
#include <math.h>
#include <pthread.h>
#include <semaphore.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>

#define BUFSIZE 1500

struct rec{
	uint16_t rec_seq;
	uint16_t rec_ttl;
	struct timeval rec_tv;
};

char recvbuf[BUFSIZE];
char sendbuf[BUFSIZE];

int datalen;
char *host;
uint16_t sport, dport;
int nsent;
pid_t pid;
int probe, nprobes;
int sendfd, recvfd;
int ttl, max_ttl;

void sig_alrm(int);
void traceloop(void);
int receive(int, struct timeval *);
void tv_sub(struct timeval *, struct timeval *);

struct sockaddr sasend, sarecv, salast;
struct sockaddr_in sabind;
socklen_t salen;

int gotalarm;
