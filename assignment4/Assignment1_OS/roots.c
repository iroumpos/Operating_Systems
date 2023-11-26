#include <sys/syscall.h>
#include <unistd.h>
#include "roots.h"

int find_roots_syscall_wrapper(void){
    sleep(0.001);	
    return (syscall(__NR_find_roots));
}
