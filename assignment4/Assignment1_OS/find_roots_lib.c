#include "roots.h"
#include <stdio.h>
#include <unistd.h>

int main(int argc, char **argv) {
    	printf("[*] Executing syscall: find_roots() \n");
	sleep(2);

	find_roots_syscall_wrapper();
	
	printf("[*] Syscall executed\n[*] Returning \n");
	sleep(2);
	return(0);
}
