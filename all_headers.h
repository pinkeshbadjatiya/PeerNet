#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <regex.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "color.h"
#include "mythreads.h"

#include <stdio.h>
#include <memory.h>
#include <string.h>
#include "sha256.h"


struct thread_data{
	char ip[INET_ADDRSTRLEN];
	int port;
	// Can add more client data as ip and all....
};
typedef struct thread_data THREAD_DATA;
THREAD_DATA *CLIENT_FOUND = NULL;

unsigned int SERVER_PORT = -1;

#define BACKLOG 10
#define MAX_PACKET_CHUNK_LEN 1024
#define MAX_BUFFER_LEN 5000
#define MAX_COMMAND_LEN 200
#define MAX_THREADS 2	// Client and server for each

#define FILE_TRANSFER_PORT 10005

int yes = 1;
regex_t REG_getfile_tcp, REG_getfile_udp, REG_rls, REG_find;
char shared_dir[]={"shared_dir_GRIM"};


int create_udp(int portno) {
	int sockfd, newsockfd;
	socklen_t clilen;
	struct sockaddr_in serv_addr, cli_addr;

	// Create a socket
	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0) {
		perror("ERROR opening socket");
		exit(1);
	}

	memset((char *) &serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = INADDR_ANY;
	serv_addr.sin_port = htons(portno);		// htons = Converts the address from host byte order to network byte order. For short int(clear from s)...

	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) == -1) {
		perror("setsockopt");
	}
	// Bind the socket
	if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
		perror("ERROR on binding");
		close(sockfd);
		return -1;
	}
	return sockfd;
}

int create_tcp(int portno) {
	int sockfd, newsockfd;
	socklen_t clilen;
	struct sockaddr_in serv_addr;

	// Create a socket
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0) {
		perror("ERROR opening socket");
		exit(1);
	}

	memset((char *) &serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = INADDR_ANY;
	serv_addr.sin_port = htons(portno);		// htons = Converts the address from host byte order to network byte order. For short int(clear from s)...

	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) == -1) {
    	perror("setsockopt");
	}
	// Bind the socket
	if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
		error("ERROR on binding");
		close(sockfd);
		exit(1);
	}

	return sockfd;
}

int listen_tcp(int sockfd) {
	// The other factor in this is the 'backlog' parameter for listen();
	// that defines how many of these completed connections can be queued at one time.
	//	If the specified number is exceeded, then new incoming connects are simply ignored (which causes them to be retried).
	struct sockaddr_in cli_addr;
	listen(sockfd, BACKLOG);
	int clilen, newsockfd;
	clilen = sizeof(cli_addr);
	newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);
	if (newsockfd < 0) {
		perror("ERROR: Accepting client");
	}
	return newsockfd;
}

int establish_tcp(char *ip, int portno) {
	int sockfd, n;
	struct sockaddr_in serv_addr;
	struct hostent *server;
	socklen_t clilen;

	char buffer[1025];
	memset(buffer, 0, sizeof(buffer));

	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0)
		error("ERROR opening socket");

	printf("%sIP:%s %s\n", KRED, RESET, ip);
	server = gethostbyname(ip);
	printf("%sHOST:%s %s\n",KRED, RESET, server->h_name);
	if (server == NULL) {
		fprintf(stderr,"ERROR, no such host\n");
		exit(0);
	}
	memset((char *) &serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	bcopy((char *)server->h_addr, (char *)&serv_addr.sin_addr.s_addr, server->h_length);
	serv_addr.sin_port = htons(portno);

	if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
		error("ERROR connecting");
	}
	return sockfd;
}

int establish_udp(char *ip, int portno) {
	int sockfd, n;
	struct hostent *server;

	char buffer[1025];
	memset(buffer, 0, sizeof(buffer));

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0)
		error("ERROR opening socket");

	server = gethostbyname(ip);
	if (server == NULL) {
		fprintf(stderr,"ERROR, no such host\n");
		exit(0);
	}
	return sockfd;
}

void destroy_SOCK(int sockfd) {
	close(sockfd);
}

void error(const char *msg) {
	perror(msg);
	exit(0);
}

void print_hash(unsigned char hash[]) {
	int idx;
	for (idx=0; idx < 32; idx++)
		printf("%02x",hash[idx]);
	printf("-\n");
}


void print_file_details(char *filename, char *hash, char *mtime) {
	printf("%sFileName:%s %s%s%s\n", KYEL, RESET, KRED, filename, RESET);
	printf("%sFileHash:%s ",KYEL, RESET); print_hash(hash);
	printf("%sDateModified:%s %s\n", KYEL, RESET, mtime);
}

int verify_hash(unsigned char hash1[], unsigned char hash2[]) {
	int idx;
	for (idx=0; idx < 32; idx++)
		if (hash1[idx] != hash2[idx])
			return 0;
	return 1;
}

void ls(char buffer2[]) {
	int pipefd[2];
	pipe(pipefd);

    char buffer[MAX_BUFFER_LEN];
	memset(buffer, 0, sizeof(buffer));

	int pid=fork();
	if(pid==0)
	{
	    close(pipefd[0]);    // close reading end in the child
	    dup2(pipefd[1], 1);  // send stdout to the pipe
	    dup2(pipefd[1], 2);  // send stderr to the pipe
	    close(pipefd[1]);    // this descriptor is no longer needed

		char *args[] = { "ls", "-a1", NULL };
		execvp(args[0], &args[0]);
		exit(EXIT_SUCCESS);
	}
	else {
	   // parent

	    close(pipefd[1]);  // close the write end of the pipe in the parent

	    while (read(pipefd[0], buffer, sizeof(buffer)) != 0)
	    {
	    }
	}

	strcpy(buffer2, buffer);	// Copy into the given buffer
	return;
}


void run_command_and_bufferize(int len, char *command[len], char **buffer2) {
	int pipefd[2];
	pipe(pipefd);

	*buffer2 = (unsigned char*)malloc(sizeof(unsigned char)*MAX_BUFFER_LEN);
	// printf("\tCommand ---- %s\n", command);

    char buffer[MAX_BUFFER_LEN];

	int pid=fork();
	if(pid==0)
	{
	    close(pipefd[0]);    // close reading end in the child
	    dup2(pipefd[1], 1);  // send stdout to the pipe
	    dup2(pipefd[1], 2);  // send stderr to the pipe
	    close(pipefd[1]);    // this descriptor is no longer needed

		//	char *args[] = { command, NULL };
		if (execvp(command[0], &command[0]) < 0) {
			perror("ERROR: Exec failed.");
		}
		exit(EXIT_SUCCESS);
	}
	else {
		// parent

	    close(pipefd[1]);  // close the write end of the pipe in the parent

	    while (read(pipefd[0], buffer, sizeof(buffer)) != 0)
	    {
	    }
	}

	strcpy(*buffer2, buffer);	// Copy into the given buffer
	return;
}

void send_buffer(int socket_id, char buff[]) {
	// To be run on pc whose file list you need

	// Send length of data
	char snum[200];
	int size=strlen(buff);
	sprintf(snum, "%d", size);
	send(socket_id, snum, MAX_PACKET_CHUNK_LEN, 0);

	// Send all data
	int S,sent=0;
	while(sent < size) {
		S = send(socket_id, buff + sent, MAX_PACKET_CHUNK_LEN, 0);
		if(S < 0) {
			perror("send_buffer: Sending Error");
		}
		sent += S;
	};
}

void rls_send(int socket_id) {
	// To be run on pc whose file list you need
	char buff[MAX_BUFFER_LEN];
	memset(buff, 0, sizeof(buff));
	ls(buff);

	// Send length of data
	char snum[200];
	memset(snum, 0, sizeof(snum));
	int size=strlen(buff);
	sprintf(snum, "%d", size);
	send(socket_id, snum, MAX_PACKET_CHUNK_LEN, 0);

	// Send all data
	int S,sent=0;
	while(sent < size) {
		S = send(socket_id, buff + sent, MAX_PACKET_CHUNK_LEN, 0);
		if(S < 0) {
			perror("rls_client: Sending Error");
		}
		sent += S;
	};
}

void rls_get(char **buff, int socket_id) {
	// To be run on pc who has asked for the list

	// Get bytes of transfer
	char small_buff[MAX_BUFFER_LEN];
	memset(small_buff, 0, sizeof(small_buff));
	recv(socket_id, small_buff, MAX_PACKET_CHUNK_LEN,0);
	int to_receive = atoi(small_buff);
	int R, received = 0;

	// Malloc size;
	*buff = (unsigned char*)malloc(sizeof(unsigned char)*(to_receive+100));
	memset(small_buff, 0, sizeof(small_buff));
	**buff = '\0';

	while(received < to_receive) {
		R = recv(socket_id,small_buff,MAX_PACKET_CHUNK_LEN,0);
		if(R<0) {
			printf("ERROR: Received Failed\n");
		}
		strncat(*buff, small_buff, strlen(small_buff)-1);
		memset(small_buff, 0, sizeof(small_buff));
		received += R;
	}

	//buff[received] =  '\0';
	return;
}

void get_prompt(char *cmd) {
	printf("%s> %s",KGRN,RESET); scanf("%[^\n]",cmd);getchar();
	return;
}

int get_filesize(FILE* fileid) {
	fseek(fileid, 0L, SEEK_END);
	int sz = ftell(fileid);
	fseek(fileid, 0L, SEEK_SET);
	return sz;
}

void get_last_modified(char **buff, char file_name[]) {
	struct stat attr;
    stat(file_name, &attr);
	*buff = (BYTE*)malloc(sizeof(BYTE)*MAX_BUFFER_LEN);
	strcpy(*buff, ctime(&attr.st_mtime));
}

void receive_n_save_to(int SOCKET) {
	unsigned char buffer[MAX_BUFFER_LEN + 4];
	unsigned char file_name[MAX_BUFFER_LEN];
	int file_data_len;

	memset(buffer,0,sizeof(buffer));
	memset(file_name,0,sizeof(file_name));

	/* Get File name + len, under 256 characters */
	if(recv(SOCKET,buffer,MAX_PACKET_CHUNK_LEN,0)<0) {
		error("ERROR: Reading file name");
		return;
	}
	//printf("1: %s\n",buffer);

	char *end_pointer;
	char* ch = strtok_r(buffer, "|", &end_pointer);
	strncpy(file_name, ch, strlen(ch));

	// Append _received
	// strcat(file_name, "_received\0");
	// Do not append _received
	strcat(file_name, "\0");

	ch = strtok_r(NULL, " ,",&end_pointer);
	file_data_len = atoi(ch);

	printf("%sFileName: %s%s\n",KRED ,RESET, file_name);
	printf("%sFilesize: %s%d bytes\n", KRED, RESET, file_data_len);

	/* Create File */
	FILE *fp = fopen(file_name, "wb+");
	if(fp==NULL){
		printf("File open error");
		return;
	}

	// Hash inits
	BYTE buf[SHA256_BLOCK_SIZE];
	SHA256_CTX ctx;
	sha256_init(&ctx);

	printf("%s-----------------------------------------------------%s\n", KYEL, RESET);
	int data_received=0;
	char dd[10];
	int received = 0;
	while(received < file_data_len) {
		int R = recv(SOCKET,buffer,MAX_PACKET_CHUNK_LEN,0);
		if(R < 0) {
			perror("receive_n_save_to: Receive Error");
		}
		if(!fputs(buffer, fp)){
			perror("ERROR: While saving to file.");
		};
		data_received += R;

		sha256_update(&ctx, buffer, (((file_data_len - received) < MAX_PACKET_CHUNK_LEN)?(file_data_len - received): MAX_PACKET_CHUNK_LEN));

		memset(buffer, 0, sizeof(buffer));
		received += R;
	}
	if (received >= file_data_len) {
		printf("%sFile Length:%s nbytes %s%s%s\n",KRED, RESET, KGRN, TICK, RESET);
	}
	else {
		printf("%sCONCERN:%s File Length not matching%s\n",KRED, KYEL, RESET);
	}

	// Calculate and send final hash
	sha256_final(&ctx, buffer);
	unsigned char received_hash[SHA256_BLOCK_SIZE];
	if(recv(SOCKET, received_hash, SHA256_BLOCK_SIZE, 0) < 0) {
		perror("FileHash Receiving Error");
	};
	// printf("HASH(calc): "); print_hash(buffer);
	// printf("HASH(recv): "); print_hash(received_hash);

	if (verify_hash(buffer, received_hash)) {
		printf("%sFile Signature:%s SHA256 | %s%s%s\n",KRED, RESET, KGRN, TICK, RESET);
	}
	else {
		printf("%sCONCERN:%s File Hash Match Failure.%s\n",KRED, KYEL, RESET);
	}

	fclose(fp);
}


void receive_n_save_to_udp(int SOCKET, struct sockaddr_in *servaddr) {
	unsigned char buffer[MAX_BUFFER_LEN + 4];
	unsigned char file_name[MAX_BUFFER_LEN];
	int file_data_len;

	memset(buffer,0,sizeof(buffer));
	memset(file_name,0,sizeof(file_name));

	int LENG = sizeof(*servaddr);

	/* Get File name + len, under 256 characters */
	if(recvfrom(SOCKET, buffer, MAX_PACKET_CHUNK_LEN, 0, (struct sockaddr *)servaddr,  &LENG)<0) {
		error("ERROR: Reading file name");
		return;
	}

	char *end_pointer;
	char* ch = strtok_r(buffer, "|", &end_pointer);
	strncpy(file_name, ch, strlen(ch));

	// Append _received
	// strcat(file_name, "_received\0");
	// Do not append _received
	strcat(file_name, "\0");

	ch = strtok_r(NULL, " ,",&end_pointer);
	file_data_len = atoi(ch);

	printf("FILE_NAME_R: %s\n",file_name);
	printf("FILE_SIZE_R: %s(string) or %d(int)\n", ch, file_data_len);

	/* Create File */
	FILE *fp = fopen(file_name, "wb+");
	if(fp==NULL){
		printf("File open error");
		return;
	}
	printf("FILE NAME(%d): %s\n", (int)strlen(file_name), file_name);

	// Hash inits
	BYTE buf[SHA256_BLOCK_SIZE];
	SHA256_CTX ctx;
	sha256_init(&ctx);

	int data_received=0;
	char dd[10];
	int received = 0;
	while(received < file_data_len) {
		int R = recvfrom(SOCKET, buffer, MAX_PACKET_CHUNK_LEN, 0, (struct sockaddr *)servaddr, &LENG);
		if(R < 0) {
			perror("receive_n_save_to: Receive Error");
		}
		if(!fputs(buffer, fp)){
			perror("ERROR: While saving to file.");
		};
		data_received += R;

		sha256_update(&ctx, buffer, (((file_data_len - received) < MAX_PACKET_CHUNK_LEN)?(file_data_len - received): MAX_PACKET_CHUNK_LEN));

		memset(buffer, 0, sizeof(buffer));
		received += R;
	}
	if (received >= file_data_len) {
		printf("%sFile Length:%s nbytes %s%s%s\n",KRED, RESET, KGRN, TICK, RESET);
	}
	else {
		printf("File Length not matching\n");
	}

	// Calculate and send final hash
	sha256_final(&ctx, buffer);
	unsigned char received_hash[SHA256_BLOCK_SIZE];
	if(recvfrom(SOCKET, received_hash, SHA256_BLOCK_SIZE, 0, (struct sockaddr *)servaddr, &LENG) < 0) {
		perror("FileHash Receiving Error");
	};
	// printf("HASH(calc): "); print_hash(buffer);
	// printf("HASH(recv): "); print_hash(received_hash);

	if (verify_hash(buffer, received_hash)) {
		printf("%sFile Signature:%s SHA256 %s%s%s\n",KRED, RESET, KGRN, TICK, RESET);
	}
	else {
		printf("File Hash Match Failure.\n");
	}

	// printf("DATA_LENGTH_REMAIN: %d\n",file_data_len - data_received);
	fclose(fp);
}


void read_n_send_to(char* file_name, int socket_id){

	unsigned char buff[MAX_BUFFER_LEN + 3];
	memset(buff, 0, sizeof(buff));

	FILE *fp = fopen(file_name,"rb");
	if(fp==NULL){
		printf("File opern error");
		return;
	}

	/* Send file_name + file_size first */
	// Filename
	if (strlen(file_name) >= MAX_BUFFER_LEN) {
		printf("ERROR: Please use a filename less than 256 characters\n");
		fclose(fp);
		return;
	}

	// Length
	int SIZE = get_filesize(fp);
	char snum[5];
	sprintf(snum, "%d", SIZE);

	// Write all
	memset(buff,0,sizeof(buff));
	strcat(buff,file_name);
	strcat(buff,"|");
	strcat(buff,snum);
	// printf("FILE_NAME_DATA: %s\n",buff);
	if(strlen(snum) + strlen(file_name) + 1 > MAX_PACKET_CHUNK_LEN) {
		printf("Name + Size length exceeded. Error may occur.\n");
	}

	send(socket_id, buff, MAX_PACKET_CHUNK_LEN, 0);

	// Hash inits
	BYTE buf[SHA256_BLOCK_SIZE];
	SHA256_CTX ctx;
	sha256_init(&ctx);

	int R;
	memset(buff,0,sizeof(buff));
	while ((R=fread(buff, sizeof(char), MAX_PACKET_CHUNK_LEN, fp)))
	{
		if(send(socket_id,buff,MAX_PACKET_CHUNK_LEN,0) < 0) {
			perror("Sending Error");
		};
		sha256_update(&ctx, buff, strlen(buff));
		bzero(buff,MAX_PACKET_CHUNK_LEN);
	}

	// Calculate and send final hash
	memset(buff,0,sizeof(buff));
	sha256_final(&ctx, buff);
	if(send(socket_id, buff, SHA256_BLOCK_SIZE, 0) < 0) {
		perror("FileHash Sending Error");
	};

	fclose(fp);
}


void read_n_send_to_udp(char* file_name, int socket_id, struct sockaddr_in *cliaddr) {

	unsigned char buff[MAX_BUFFER_LEN + 3];
	memset(buff, 0, sizeof(buff));

	int LENG = sizeof(*cliaddr);
	FILE *fp = fopen(file_name,"rb");
	if(fp==NULL){
		printf("File opern error");
		return;
	}

	/* Send file_name + file_size first */
	// Filename
	if (strlen(file_name) >= MAX_BUFFER_LEN) {
		printf("ERROR: Please use a filename less than 256 characters\n");
		fclose(fp);
		return;
	}

	// Length
	int SIZE = get_filesize(fp);
	char snum[5];
	sprintf(snum, "%d", SIZE);

	// Write all
	memset(buff,0,sizeof(buff));
	strcat(buff,file_name);
	strcat(buff,"|");
	strcat(buff,snum);
	// printf("FILE_NAME_DATA: %s\n",buff);
	if(strlen(snum) + strlen(file_name) + 1 > MAX_PACKET_CHUNK_LEN) {
		printf("Name + Size length exceeded. Error may occur.\n");
	}

	sendto(socket_id, buff, MAX_PACKET_CHUNK_LEN, 0, (struct sockaddr *)cliaddr,  LENG);

	// Hash inits
	BYTE buf[SHA256_BLOCK_SIZE];
	SHA256_CTX ctx;
	sha256_init(&ctx);

	int R;
	memset(buff,0,sizeof(buff));
	while ((R=fread(buff, sizeof(char), MAX_PACKET_CHUNK_LEN, fp)))
	{
		if(sendto(socket_id, buff, MAX_PACKET_CHUNK_LEN, 0, (struct sockaddr *)cliaddr,  LENG) < 0) {
			perror("Sending Error");
		};
		sha256_update(&ctx, buff, strlen(buff));
		bzero(buff,MAX_PACKET_CHUNK_LEN);
	}

	// Calculate and send final hash
	memset(buff,0,sizeof(buff));
	sha256_final(&ctx, buff);
	if(sendto(socket_id, buff, SHA256_BLOCK_SIZE, 0, (struct sockaddr *)cliaddr,  LENG) < 0) {
		perror("FileHash Sending Error");
	};
	printf("%s%s%s: ",KRED, file_name, RESET);
	fclose(fp);
}



int reg_match(char to_match[], regex_t REGEX) {
	char msgbuf[100];
	memset(msgbuf, 0, sizeof(msgbuf));
	int reti;
	reti = regexec(&REGEX, to_match, 0, NULL, 0);
	if(!reti) {
		return 1;
	}
	else if (reti == REG_NOMATCH) {
		return 0;
	}
    regerror(reti, &REGEX, msgbuf, sizeof(msgbuf));
    fprintf(stderr, "Regex match failed: %s\n", msgbuf);
	return 0;
}


void compile_regexes() {
	int reti = regcomp(&REG_getfile_tcp, "^ *getfile tcp.*", 0);
	if (reti) {
	    fprintf(stderr, "REG_getfile: TCP: Could not compile regex\n");
	}

	reti = regcomp(&REG_getfile_udp, "^ *getfile udp.*", 0);
	if (reti) {
	    fprintf(stderr, "REG_getfile: UDP: Could not compile regex\n");
	}

	reti = regcomp(&REG_rls, "^ *rls.*", 0);
	if (reti) {
		fprintf(stderr, "REG_rls: Could not compile regex\n");
	}

	reti = regcomp(&REG_find, "^ *rfind.*", 0);
	if (reti) {
		fprintf(stderr, "REG_find: Could not compile regex\n");
	}
	return;
}


void hash() {
	BYTE text1[2000];
	printf("Enter Text:");
	scanf("%s",text1);
	BYTE buf[SHA256_BLOCK_SIZE];
	SHA256_CTX ctx;

	sha256_init(&ctx);
	sha256_update(&ctx, text1, strlen(text1));
	sha256_final(&ctx, buf);
	printf("%s%s%s: ",KRED, text1, RESET);
	print_hash(buf);
	return;
}


void run_find(char buffer2[], char* NewerDate, char* OlderDate) {

	// find . -mindepth 1 -newermt "2013-01-01 00:00:00" ! -newermt "2016-02-27 00:00:00" -printf '%30f\t%7s\t%4Y\t%TY-%Tm-%Td %TH:%TM:%0.2TS\n'
	char *args[] = { "find", "./", "-mindepth", "1", "-newermt", NewerDate, "!", "-newermt", OlderDate, NULL };
	int i=0;

	int pipefd[2];
	pipe(pipefd);

    char buffer[MAX_BUFFER_LEN];

	int pid=fork();
	if(pid==0) {
	    close(pipefd[0]);    // close reading end in the child
	    dup2(pipefd[1], 1);  // send stdout to the pipe
	    dup2(pipefd[1], 2);  // send stderr to the pipe
	    close(pipefd[1]);    // this descriptor is no longer needed


		if(execvp(args[0], &args[0]) == -1) {
			perror("ERROR: in execvp call");
			exit(EXIT_FAILURE);
		};
		exit(EXIT_SUCCESS);
	}
	else {
		// parent
	    close(pipefd[1]);  // close the write end of the pipe in the parent
	    while (read(pipefd[0], buffer, sizeof(buffer)) != 0)
		{}
	}
	strcpy(buffer2, buffer);	// Copy into the given buffer
	return;
}

void run_find_regex(char buffer2[], char* regex) {
	char *r;
	if (*regex == '\'' && regex[strlen(regex)-1] == '\'') {
		r = regex + 1;
		regex[strlen(regex)-1] = '\0';
	}
	else if (*regex == '\"' && regex[strlen(regex)-1] == '\"') {
		r = regex + 1;
		regex[strlen(regex)-1] = '\0';
	}
	else {
		r = regex;
	}

	char *args[] = { "find", "./", "-mindepth", "1", "-regex", r, NULL };
	int pipefd[2];
	pipe(pipefd);

    char buffer[MAX_BUFFER_LEN];
	memset(buffer, 0, sizeof(buffer));

	int pid=fork();
	if(pid==0) {
	    close(pipefd[0]);    // close reading end in the child
	    dup2(pipefd[1], 1);  // send stdout to the pipe
	    dup2(pipefd[1], 2);  // send stderr to the pipe
	    close(pipefd[1]);    // this descriptor is no longer needed

		if(execvp(args[0], &args[0]) == -1) {
			perror("ERROR: in execvp call");
			exit(EXIT_FAILURE);
		};
		exit(EXIT_SUCCESS);
	}
	else {
		// parent
	    close(pipefd[1]);  // close the write end of the pipe in the parent
	    while (read(pipefd[0], buffer, sizeof(buffer)) != 0)
	    {}

	}

	strcpy(buffer2, buffer);	// Copy into the given buffer
	return;
}

void send_full_buffer(char buff[], int newsockfd) {
	int S,sent=0;

	// Send size
	int size = strlen(buff);
	char snum[15];
	sprintf(snum, "%d", size);

	if (send(newsockfd, snum, MAX_PACKET_CHUNK_LEN, 0) < 0) {
		perror("send_full_buffer: Size Sending Error");
	}

	// Send all data
	while(sent < size) {
		S = send(newsockfd, buff + sent, MAX_PACKET_CHUNK_LEN, 0);
		if(S < 0) {
			perror("send_full_buffer: Sending Error");
		}
		sent += S;
	};
}

void find_matching(char cmd[], int newsockfd) {
	char buffer[MAX_BUFFER_LEN];
	char *start = strchr(cmd, ' ');
	if (!strncmp(start+1, "regex", 5)) {
		char *regex = strchr(cmd, ' ');
		regex = strchr(regex+1, ' ');
		while(*regex == ' '){
			regex++;
		}

		char output[MAX_BUFFER_LEN];
		memset(output, 0, sizeof(output));
		*output='\0';
		run_find_regex(output, regex);
		send_full_buffer(output, newsockfd);
	}
	else if (!strncmp(start+1, "longlist", 8)) {
		// unsigned char *receive;
		// char *ttemp;
		// rls_get(&ttemp, newsockfd);
		// printf("%s\n",ttemp);
		// free(ttemp);

		// find ./ -mindepth 1 -printf '%30f\t%10s\t%Y\t%TD %TH:%TM:%0.2TS\n'
		// printf("LOGNLIST\n");
		char *bufr;
		char *stri[8]= {"find", "find", "./", "-mindepth", "1", "-printf", "\"%30f\\t%10s\\t%Y\\t%TD %TH:%TM:%0.2TS\\n\"", NULL};
		run_command_and_bufferize(8, stri, &bufr);
		// printf("OUTPUT: bufferiser: %s\n", bufr);
		send_buffer(newsockfd, bufr);
		memset(bufr, 0, sizeof(bufr));
	}
	else if (!strncmp(start+1, "shortlist", 9)) {
		// rfind shortlist 2013-02-05 00:00:00 2016-02-27 00:00:00

		// Get timestamps
		printf("FIND:shortlist\n");
		char STARTDATE[12];
		char *startDate = strchr(start+1, ' ');
		*STARTDATE='"'; startDate++;
		strncpy(STARTDATE+1, startDate, 10);
		*(STARTDATE+11)='\0';

		char STARTTIME[10];
		char *startTime = strchr(startDate, ' ');
		startTime++;
		strncpy(STARTTIME, startTime, 8);
		*(STARTTIME+8)='"';
		*(STARTTIME+9)='\0';

		char ENDDATE[12];
		char *endDate = strchr(startTime, ' ');
		*ENDDATE='"'; endDate++;
		strncpy(ENDDATE+1, endDate, 10);
		*(ENDDATE+11)='\0';


		char ENDTIME[10];
		char *endTime = strchr(endDate, ' ');
		endTime++;
		strncpy(ENDTIME, endTime, 8);
		*(ENDTIME+8)='"';
		*(ENDTIME+9)='\0';

		char START[strlen(STARTDATE)+strlen(STARTTIME)+1];
		strncpy(START, STARTDATE, strlen(STARTDATE));
		*(START+strlen(STARTDATE))=' ';
		strncpy(START+strlen(STARTDATE)+1, STARTTIME, strlen(STARTTIME));
		*(START+strlen(STARTDATE)+strlen(STARTTIME)+1)='\0';
		printf("START:%s\n", START);


		char END[strlen(ENDDATE)+strlen(ENDTIME)+1];
		strncpy(END, ENDDATE, strlen(ENDDATE));
		*(END+strlen(ENDDATE))=' ';
		strncpy(START+strlen(ENDDATE)+1, ENDTIME, strlen(ENDTIME));
		*(END+strlen(ENDDATE)+strlen(ENDTIME)+1)='\0';
		printf("END:%s\n", END);


		printf("SDATE:%s\n", STARTDATE);
		printf("STIME:%s\n", STARTTIME);
		printf("EDATE:%s\n", ENDDATE);
		printf("ETime:%s\n", ENDTIME);

		run_find(buffer, START, END);
		printf("OUT:%s\n", buffer);
	};
}

int verify_directory() {
	struct stat s;
	int err = stat(shared_dir, &s);
	if(-1 == err) {
	    if(ENOENT == errno) {
	        /* does not exist */
			printf("ERROR: Directory %s does not exist. Please create the directory.\n", shared_dir);
			return -1;
		} else {
	        perror("stat");
	        exit(1);
	    }
	} else {
	    if(S_ISDIR(s.st_mode)) {
	        /* it's a dir */
			return 1;
	    } else {
			printf("ERROR: There is a file with name %s, expected directory.\n", shared_dir);
			return -1;
	        /* exists but is no dir */
	    }
	}
}


void hash_file(char **hash, char *file_name) {
	FILE *fp = fopen(file_name, "rb");
	if(fp==NULL) {
		printf("File open error");
		return;
	}

	// Hash inits
	*hash = (BYTE*)malloc(sizeof(BYTE)*SHA256_BLOCK_SIZE);
	SHA256_CTX ctx;
	sha256_init(&ctx);

	char buff[MAX_BUFFER_LEN];
	int R;
	memset(buff,0,sizeof(buff));
	while ((R=fread(buff, sizeof(char), MAX_PACKET_CHUNK_LEN, fp))) {
		sha256_update(&ctx, buff, strlen(buff));
		bzero(buff, MAX_PACKET_CHUNK_LEN);
	}

	// Calculate and send final hash
	sha256_final(&ctx, *hash);
	fclose(fp);
}

void find_hashing_arg(char *cmd, int newsockfd) {
	char *t = strchr(cmd, ' ');
	t++;
	if (!strncmp(t, "verify", 6)) {
		*(t-1) = 'H';
		// Send 'Hverify <filename>'

		if(send(newsockfd, t-1, MAX_COMMAND_LEN, 0) < 0) {
			perror("filehash:send_request: Sending Error");
		};

		char hash[MAX_BUFFER_LEN];
		memset(hash, 0, sizeof(hash));
		recv(newsockfd, hash, MAX_PACKET_CHUNK_LEN,0);

		char mtime[MAX_BUFFER_LEN];
		memset(mtime, 0, sizeof(mtime));
		recv(newsockfd, mtime, MAX_PACKET_CHUNK_LEN,0);

		t = strchr(t, ' ');
		t++;

		print_file_details(t, hash, mtime);
	}
	else if (!strncmp(t, "checkall", 6)) {

		char filename[MAX_BUFFER_LEN];
		char hash[MAX_BUFFER_LEN];
		char mtime[MAX_BUFFER_LEN];

		memset(filename, 0, sizeof(filename));
		memset(hash, 0, sizeof(hash));
		memset(mtime, 0, sizeof(mtime));

		while(1) {
			recv(newsockfd, filename, MAX_PACKET_CHUNK_LEN,0);
			if(!strncmp(filename, "--END--", 7)) {
				break;
			}
			recv(newsockfd, hash, MAX_PACKET_CHUNK_LEN,0);
			recv(newsockfd, mtime, MAX_PACKET_CHUNK_LEN,0);
			print_file_details(filename, hash, mtime);

		}
	}
}

void* server_main(void* arg) {
	// FOR SERVER DATA
	int sockfd, newsockfd;
	socklen_t clilen;
	struct sockaddr_in serv_addr, cli_addr;

	// Create a socket
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0) {
		perror("ERROR opening socket");
		exit(1);
	}

	memset((char *) &serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = INADDR_ANY;
	serv_addr.sin_port = htons(0);		// htons = Converts the address from host byte order to network byte order. For short int(clear from s)...

	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) == -1) {
    	perror("setsockopt");
	}
	// Bind the socket
	if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
		error("ERROR on binding");
		close(sockfd);
		exit(1);
	}

	struct sockaddr_in sin;
	int port;
	socklen_t len = sizeof(sin);
	if (getsockname(sockfd, (struct sockaddr *)&sin, &len) == -1)
	    perror("getsockname");
	else
		SERVER_PORT = ntohs(sin.sin_port);

	printf("%s------------------------------------------------------------%s\n",KYEL, RESET);
	printf("\t%sSERVER%s ---------> %sIP:%s LOCAL_IP, %sPORT:%s %d\n", KRED, RESET, KYEL, RESET, KYEL, RESET, SERVER_PORT);
	printf("%s------------------------------------------------------------%s\n",KYEL, RESET);

	// The other factor in this is the 'backlog' parameter for listen();
	// that defines how many of these completed connections can be queued at one time.
	//	If the specified number is exceeded, then new incoming connects are simply ignored (which causes them to be retried).
	listen(sockfd, BACKLOG);
	clilen = sizeof(cli_addr);
	newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);
	if (newsockfd < 0) {
		error("ERROR on accept");
	}

	if(CLIENT_FOUND == NULL) {
		printf("....Incomming Connection from %s | %sCONNECTED%s\n", inet_ntoa(cli_addr.sin_addr), KGRN, RESET);
	}

	char temp[MAX_COMMAND_LEN];
	if (recv(newsockfd, temp, MAX_COMMAND_LEN, 0) < 0) {
		perror("Error receiving other port for parallel connection");
	};

	// If the port received is -1 then just run the server code.
	if(CLIENT_FOUND == NULL && atoi(temp)!=-1) {
		printf("-----> NEW port received: %d\n", atoi(temp));
		CLIENT_FOUND = (THREAD_DATA*)malloc(sizeof(THREAD_DATA));
		strcpy(CLIENT_FOUND->ip, inet_ntoa(cli_addr.sin_addr));
		CLIENT_FOUND->port = atoi(temp);
	}

	// Go through normal routine
	char cmd[MAX_COMMAND_LEN];
	recv(newsockfd, cmd, MAX_COMMAND_LEN, 0);
	while(strcmp(cmd, "exit")) {
		if(reg_match(cmd, REG_rls)) {
			rls_send(newsockfd);
		}
		else if(reg_match(cmd, REG_getfile_tcp)) {
			int SOCKFD = create_tcp(FILE_TRANSFER_PORT);
			int NEWSOCKFD = listen_tcp(SOCKFD);
			char *start = strchr(cmd, ' ');
			start = strchr(start+1, ' ');
			*start = '\0';
			read_n_send_to(start+1, NEWSOCKFD);
			destroy_SOCK(SOCKFD);
			destroy_SOCK(NEWSOCKFD);
		}
		else if(reg_match(cmd, REG_getfile_udp)) {
			int SOCKFD = create_udp(FILE_TRANSFER_PORT);

			char *start = strchr(cmd, ' ');
			start = strchr(start+1, ' ');
			*start = '\0';

			struct sockaddr_in cliaddr;
			int len = sizeof(cliaddr);
			char temp[MAX_PACKET_CHUNK_LEN+2];
			int slen = sizeof(struct sockaddr);

			recvfrom(SOCKFD, temp, MAX_PACKET_CHUNK_LEN, 0, (struct sockaddr *)&cliaddr, &slen);
			read_n_send_to_udp(start+1, SOCKFD, &cliaddr);
			destroy_SOCK(SOCKFD);
		}
		else if(reg_match(cmd, REG_find)) {
			find_matching(cmd, newsockfd);
		}
		else if(!strncmp(cmd, "Hverify", 7)) {
			char *file = strchr(cmd, ' ');
			file++;

			// Get file hash
			char *hash;
			hash_file(&hash, file);
			if(send(newsockfd, hash, MAX_PACKET_CHUNK_LEN, 0) < 0) {
				perror("Hverify: Sending Error");
			};
			free(hash);

			// Now print modified time
			char *mtime;
			get_last_modified(&mtime, file);
			if(send(newsockfd, mtime, MAX_PACKET_CHUNK_LEN, 0) < 0) {
				perror("Hverify: Sending Error");
			};
			free(mtime);
		}
		else if(!strncmp(cmd, "filehash checkall", 17)) {
			// Do ls on server
			char bufs[MAX_BUFFER_LEN];
			memset(bufs, 0 ,strlen(bufs));
			ls(bufs);

			char *end_str, *tok=NULL;
			tok = strtok_r(bufs, "\n", &end_str);
			while(tok != NULL) {
				if (!strcmp(tok, ".") || !strcmp(tok, "..")) {
					tok = strtok_r(NULL, "\n", &end_str);
					continue;
				}

				// Send filename
				if(send(newsockfd, tok, MAX_PACKET_CHUNK_LEN, 0) < 0) {
					perror("Hcheckall: Sending Error");
				};

				// Get file hash
				char *hash;
				hash_file(&hash, tok);
				if(send(newsockfd, hash, MAX_PACKET_CHUNK_LEN, 0) < 0) {
					perror("Hcheckall: Sending Error");
				};
				free(hash);

				// Now send modified time
				char *mtime;
				get_last_modified(&mtime, tok);
				if(send(newsockfd, mtime, MAX_PACKET_CHUNK_LEN, 0) < 0) {
					perror("Hcheckall: Sending Error");
				};
				free(mtime);

				tok = strtok_r(NULL, "\n", &end_str);
			}

			if(send(newsockfd, "--END--", MAX_PACKET_CHUNK_LEN, 0) < 0) {
				perror("Hcheckall: Sending Error");
			};

		}
		memset(cmd, 0 ,sizeof(cmd));
		recv(newsockfd, cmd, MAX_COMMAND_LEN, 0);
	}

	// Close everything
	close(newsockfd);
	close(sockfd);
	printf("BYE server\n");
	return;
}


void client_main(void *data) {
	if (data == NULL) {
		printf("CLIENT not received.\n");
		return;
	}

	THREAD_DATA *temp = (THREAD_DATA*)data;

	char ip[INET_ADDRSTRLEN];
	int port = temp->port;
	strcpy(ip, temp->ip);

	unsigned char *receive;
	int reti;

	int sockfd, n;
	struct sockaddr_in serv_addr;
	struct hostent *server;

	char buffer[1025];

	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0) {
		error("ERROR opening socket");
	}
	server = gethostbyname(ip);
	if (server == NULL) {
		fprintf(stderr,"ERROR, no such host\n");
		exit(0);
	}
	memset((char *) &serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	bcopy((char *)server->h_addr, (char *)&serv_addr.sin_addr.s_addr, server->h_length);
	serv_addr.sin_port = htons(port);
	if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
		error("ERROR connecting");
	}

	char serv_port[MAX_COMMAND_LEN];
	sprintf(serv_port, "%d", SERVER_PORT);

	if(send(sockfd, serv_port, MAX_COMMAND_LEN, 0) < 0) {
		perror("Error sending the other port.");
	};

	char cmd[MAX_COMMAND_LEN];
	get_prompt(cmd);
	while(strcmp(cmd,"exit")) {
		if(!strcmp(cmd,"ls")) {
			char temp_buff[MAX_BUFFER_LEN];
			ls(temp_buff);
			printf("%s\n",temp_buff);
		}
		else if(!strcmp(cmd, "rls")) {
			if(send(sockfd, "rls_send", MAX_COMMAND_LEN, 0) < 0) {
				perror("rls:send_request: Sending Error");
			};
			rls_get(&receive, sockfd);
			printf("%s\n",receive);
			free(receive);
		}
		else if(reg_match(cmd, REG_getfile_tcp)) {
			if(send(sockfd, cmd, MAX_COMMAND_LEN, 0) < 0) {
				perror("getfile:send_request: Sending Error");
			};
			int SOCKFD = establish_tcp(ip, FILE_TRANSFER_PORT);;
			receive_n_save_to(SOCKFD);				// <- file transfer on new created port
			destroy_SOCK(SOCKFD);
		}
		else if(reg_match(cmd, REG_getfile_udp)) {
			if(send(sockfd, cmd, MAX_COMMAND_LEN, 0) < 0) {
				perror("getfile:send_request: Sending Error");
			};
			int iii =0 ;
			for(iii=0;iii<1000000;iii++){}
			int SOCKFD = establish_udp(ip, FILE_TRANSFER_PORT);		// <- Original file transerfer on newly created port.

			// Create server struct
			struct sockaddr_in servaddr;
			bzero(&servaddr, sizeof(servaddr));
			servaddr.sin_family = AF_INET;
			servaddr.sin_addr.s_addr = INADDR_ANY; // ANY address or use specific address
			servaddr.sin_port = htons(FILE_TRANSFER_PORT);  // Port address
			char temp[MAX_PACKET_CHUNK_LEN+2];
			temp[0] = 'a';
			temp[1] = '\0';

			int slen = sizeof(struct sockaddr);
			sendto(SOCKFD, temp, MAX_PACKET_CHUNK_LEN, 0, (struct sockaddr *)&servaddr,  slen);

			struct sockaddr_in cliaddr;
			receive_n_save_to_udp(SOCKFD, &cliaddr);
			destroy_SOCK(SOCKFD);
		}
		else if(reg_match(cmd, REG_find)) {
			if(send(sockfd, cmd, MAX_COMMAND_LEN, 0) < 0) {
				perror("getfile:send_request: Sending Error");
			};

			rls_get(&receive, sockfd);
			printf("%s\n",receive);
			free(receive);
			receive = NULL;
		}
		else if(!strncmp(cmd, "filehash", 8)) {
			if(send(sockfd, cmd, MAX_COMMAND_LEN, 0) < 0) {
				perror("filehash:send_request: Sending Error");
			};
			find_hashing_arg(cmd, sockfd);
		}
		else if(!strcmp(cmd, "hash")) {
			hash();getchar();
		}
		else if(!strcmp(cmd, "clear")) {
			system("clear");
		}
		get_prompt(cmd);
	}
	if(send(sockfd, "exit", MAX_PACKET_CHUNK_LEN,0) < 0) {
		perror("EXIT: Sending Error");
	};

	close(sockfd);
	printf("BYE client\n");
	return;
}
