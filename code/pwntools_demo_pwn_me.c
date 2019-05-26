////////////////////////////////////////////////////////////////////////
//
// Program: pwntools_demo_pwn_me
//
// Date: 02/16/2018
//
// Author: Travis Phillips
//
// Website: https://github.com/jaxhax-travis/presentation-pwntools
//
// Purpose: A small C program with a buffer overflow in it that is
//          triggered by a string argument passed at the program start.
//          It contains a function that is never called. Use the Buffer
//          Overflow to run neverCalledWinnerFunction().
//
// Compile: gcc -m32 -no-pie -fno-stack-protector pwntools_demo_pwn_me.c -o pwntools_demo_pwn_me
//
////////////////////////////////////////////////////////////////////////
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void neverCalledWinnerFunction(){
	printf("\n\n\t\033[32;1m---===[ I should never be run! You Win! ]===---\033[0m\n\n");
	exit(0);
}

void vulnFunc(char *AttackStr) {
	char buf[1000];
	
	printf(" [*] in vulnFunc().\n");
	bzero(buf, sizeof(buf));
	
	printf(" [*] Copying User string to buffer.\n");
	strcpy(buf, AttackStr);
	
	printf(" [*] Finished copying to buffer. Returning from vulnFunc().\n");
}

int main(int argc, char *argv[]) {
	
	////////////////////////////////////////
	// Print Banner
	////////////////////////////////////////
	printf("\n\t\033[33;1m---===[ Pwntools Pwn Me Demo ]===---\033[0m\n\n");
	
	////////////////////////////////////////
	// Check we got an argument. If not,
	// print usage and bail...
	////////////////////////////////////////
	if (argc != 2){
		printf(" \033[32;1m[*] Usage:\033[0m %s [String]\n\n", argv[0]);
		return 0;
	}
	
	////////////////////////////////////////
	// If we did, let's hand it to our vuln
	// function.
	////////////////////////////////////////
	vulnFunc(argv[1]);
	
	printf(" [*] Back in main().\n\n");

	return 0;
}

