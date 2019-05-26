////////////////////////////////////////////////////////////////////////
//
// Program: network_rop_me
//
// Date: 02/16/2018
//
// Author: Travis Phillips
//
// Website: https://github.com/jaxhax-travis/presentation-pwntools
//
// Purpose: A small C forking server program with a buffer overflow in it
//          This challenge is designed to be exploited with ASLR and DEP
//          Enabled. No PIE or Canaries. This demo is a part of the
//          pwntools demos created to go with the Pwntools presentation.
//
// Compile: gcc -m32 -no-pie -fno-stack-protector network_rop_me.c -o network_rop_me
//
////////////////////////////////////////////////////////////////////////
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

void error(const char *msg) {
    perror(msg);
    exit(1);
}

////////////////////////////////////////////////////////////////////////
// handleClient - Vulnerable function that clients will interact with.
//                The vulnerablility is due to buffer being 1024 bytes,
//                however the call to read() will read 2048 bytes into
//                it. This is a classic stack based buffer overflow.
//                However there is no win() function this time. The goal
//                is to create a real exploit for this that will get you
//                a shell or some other payload executed.
////////////////////////////////////////////////////////////////////////
void handleClient(int sockfd, int pid){
    char buffer[1024]; // Note the size of this buffer.
    int n;

	//////////////////////////////////////////////////////////////
	// Greet the client.
	//////////////////////////////////////////////////////////////
	n = write(sockfd, "Please Enter your message: ", 28);
	
	//////////////////////////////////////////////////////////////
	// Zero out the buffer to ensure it is clean before we use it.
	//////////////////////////////////////////////////////////////
    bzero(buffer,1024);

	//////////////////////////////////////////////////////////////
	// read in 2048 bytes from the client socket.
	// !!!!!!!! THIS IS THE VULNERABLE LINE OF CODE !!!!!!!!!
	//////////////////////////////////////////////////////////////
    n = read(sockfd,buffer,2048);

	//////////////////////////////////////////////////////////////
	// Error out if the client sent nothing or we couldn't
	// read from it.
	//////////////////////////////////////////////////////////////
    if (n < 0) {
		error("ERROR reading from socket");
	} else {
		//////////////////////////////////////////////////////////////
		// In the server side console, print a message to let us know
		// the user used it. pid will probably be stack smashed if the
		// client is doing stuff right!
		//////////////////////////////////////////////////////////////
		printf(" [*] PID[%d]: Got Message from client...\n", pid);
	}
	return;
}


///////////////////////////////////////////////////////////////////////
//                                 Main
///////////////////////////////////////////////////////////////////////
int main(int argc, char *argv[]) {
    int sockfd = 0;
    int newsockfd = 0;
    int portno = 0;
    int realpid = 0;
    char *server_ip;
    struct sockaddr_in serv_addr, client_address;
	socklen_t client_addr_len = sizeof(client_address);

	printf("\n\t      ---===[ Pwntools Network ROP Me ]===---\n\n");

    /////////////////////////////////////////////////////////
	// If the user didn't provide a port number, Error out.
	/////////////////////////////////////////////////////////
    if (argc < 3) {
		printf("\t[*] Usage: %s [BindIP] [BindPortNum]\n", argv[0]);
		printf("\t[*] Example: %s 127.0.0.1 31337\n\n", argv[0]);
		exit(1);
	}

	/////////////////////////////////////////////////////////
	// Create a socket and get the socket file descriptor.
	/////////////////////////////////////////////////////////
	puts(" [*] Getting server socket file descriptor...");
	sockfd = socket(AF_INET, SOCK_STREAM, 0);

	/////////////////////////////////////////////////////////
	// if we got a bad file descriptor than we error out.
    /////////////////////////////////////////////////////////
    if (sockfd < 0) {
        error("ERROR opening socket");
	}
	
	/////////////////////////////////////////////////////////
	// If we got a socket file descriptor, then show it in
	// the server console.
	/////////////////////////////////////////////////////////
	printf(" [*] Got socket file descriptor: %d...\n", sockfd);
	
	/////////////////////////////////////////////////////////
	// Zero out the serv_addr buffer
	/////////////////////////////////////////////////////////
    bzero((char *) &serv_addr, sizeof(serv_addr));

	/////////////////////////////////////////////////////////
	// Get our port number
	/////////////////////////////////////////////////////////
    server_ip = argv[1];
    portno = atoi(argv[2]);

	/////////////////////////////////////////////////////////
	// Setup our socket info to bind port to any interface.
	/////////////////////////////////////////////////////////
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(server_ip);
    serv_addr.sin_port = htons(portno);

	/////////////////////////////////////////////////////////
	// Bind the socket.
	/////////////////////////////////////////////////////////
	printf(" [*] Binding socket to port %d...\n", portno);
    if (bind(sockfd, (struct sockaddr *) &serv_addr,
		sizeof(serv_addr)) < 0)
        error("ERROR on binding");

	/////////////////////////////////////////////////////////
	// Start listening for a connection with a connection
	// pool of 5
	/////////////////////////////////////////////////////////
	puts(" [*] Starting listener...");
    listen(sockfd,5);
    
    /////////////////////////////////////////////////////////
	// Accept a new connection and retrive the new socket
	// handle. The program will wait here till a connection
	// is established.
	/////////////////////////////////////////////////////////
	puts(" [*] Waiting for connections...");
	while (1) {
		newsockfd = accept(sockfd, (struct sockaddr *) &client_address, &client_addr_len);
		if (newsockfd < 0) {
			error("ERROR on accept");
		}

		/////////////////////////////////////////////////////////
		// Fork a child process off.
		/////////////////////////////////////////////////////////
		pid_t pid = fork();

		/////////////////////////////////////////////////////////
		// If the pid is zero, we are the child process. Close
		// the Server socket and pass the client off to
		// handleClient()..
		/////////////////////////////////////////////////////////
		if (pid == 0) {
			realpid = getpid();
			close(sockfd);
			printf(" [*] PID[%d]: Got connection from %s:%d\n", realpid, inet_ntoa(client_address.sin_addr), ntohs(client_address.sin_port));
			handleClient(newsockfd, realpid);
			printf(" [*] PID[%d]: Closing Client Socket...\n", realpid);
			close(newsockfd);
			exit(0);
		} else if(pid > 0) {
			/////////////////////////////////////////////////////////
			// Otherwise, we are the parent process, just close the
			// new accept() socket and resume listening for new connections.
			/////////////////////////////////////////////////////////
			close(newsockfd);
		}
	}
	/////////////////////////////////////////////////////////
	// If we exit the while loop, then close 
	// the server socket...
	/////////////////////////////////////////////////////////
	puts(" [*] Closing server socket...");
    close(sockfd);

	/////////////////////////////////////////////////////////
	// Finally exit the program...
	/////////////////////////////////////////////////////////
	puts(" [*] Exiting...");
    return 0;
}

