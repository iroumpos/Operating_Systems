#include <sys/syscall.h>
#include <unistd.h>
#include "stats_lib.h"

long slob_allocator_get_total_memory_alloc(void){
	return( syscall(__NR_slob_get_total_alloc_mem));
}
long slob_allocator_get_total_free_memory(void){
	return( syscall(__NR_slob_get_total_free_mem));
}