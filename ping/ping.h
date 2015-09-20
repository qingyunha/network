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

#define BUFSIZE 1500

char sendbuf[BUFSIZE];

int sockfd;
int nsent;
pid_t pid;

void send_icmp(void);
void readloop(void);
void proc_reply(char *ptr, ssize_t len, struct msghdr *msg, struct timeval *tvrecv);
void sig_alrm(int sigo);
uint16_t in_cksum(uint16_t *addr, int len);
void tv_sub(struct timeval *out, struct timeval *in);

struct sockaddr_in sasend;
struct sockaddr_in sarecv;
socklen_t salen;

typedef void (*sighandler_t)(int);
sighandler_t Signal(int signo, sighandler_t func)
{
	struct sigaction act, oact;
	act.sa_handler = func;
	sigemptyset(&act.sa_mask);
	if(signo == SIGALRM){
#ifdef SA_INTERRUPT
	act.sa_flags |= SA_INTERRUPT;
#endif
	}else
		act.sa_flags |= SA_RESTART;

	if(sigaction(signo, &act, &oact)<0)
		return(SIG_ERR);

	return(oact.sa_handler);

}




