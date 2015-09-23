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

void doit(int);
void sig_child(int);
void handle_mpty(int, int);

#define err(msg) \
	do { perror(msg); exit(1); }while(0);

int main(int argc, char **argv)
{

	int listenfd, connfd;
	int n;
	pid_t pid;
	struct addrinfo hints, *res;
	
	signal(SIGCHLD, sig_child);

	bzero(&hints, sizeof(hints));
	hints.ai_flags = AI_PASSIVE;
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	
	if( (n = getaddrinfo(NULL, "5677", &hints, &res)) != 0 ){
		fprintf(stderr, "getaddrinfo error: %s\n",
						gai_strerror(n));
		exit(1);
	}

	if( (listenfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol)) < 0)
		err("socket error");
	
	if( bind(listenfd, res->ai_addr, res->ai_addrlen) < 0)
		err("bind error");
	
	if(	listen(listenfd, 20) < 0)
		err("listen error");
	
	printf("listen at %s: %d ...\n", res->ai_canonname, 
						ntohs(((struct sockaddr_in *)res->ai_addr)->sin_port));

	fflush(stdout);
	while(1){
		if( (connfd = accept(listenfd, NULL, NULL)) < 0)
			err("accept error");
	
		if((pid = fork()) < 0){
			err("fork error");
		}else if(pid == 0){
			close(listenfd);
			doit(connfd);
			exit(0);
		}else
			close(connfd);
	}

}

void doit(int connfd)
{
	pid_t pid;
	int mfd;

	if( (pid = pty_fork(&mfd, NULL, 0, NULL, NULL)) < 0){
		err("pty_fork error");
	}else if(pid == 0){
		execl("/bin/bash", "sh", (char *)0);
		exit(127);
	}else{
		handle_mpty(connfd, mfd);
	}

/*
	printf("handle a connection\n");
	if( dup2(connfd, 0) == -1)
		err("dup2 0 error");
	if( dup2(connfd, 1) == -1)
		err("dup2 1 error");
	if( dup2(connfd, 2) == -1)
		err("dup2 2 error");
	close(connfd);
	
	execl("/bin/bash", "sh", (char *)0);

	exit(127);
*/
}

void sig_child(int signo)
{
	pid_t pid;
	while( (pid = waitpid(-1, NULL,WNOHANG)) > 0)
		;
	if(pid < 0 && errno != ECHILD)
		err("waitpid error");
	return;
}


void handle_mpty(int connfd, int mfd)
{
	pid_t pid;
	char buf[512];
	int n;
	if( (pid = fork()) < 0){
		err("handle_mpty fork error");
	}else if(pid > 0){
		while( (n = read(connfd, buf, sizeof(buf))) > 0)
			write(mfd, buf, n);
	}else{
		while( (n = read(mfd, buf, sizeof(buf))) > 0)
			write(connfd, buf, n);
	}

}
