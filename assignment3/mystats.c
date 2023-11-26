#include <stdio.h>
#include "stats_lib.h"

int main(int argc, char* argv[]) {

	printf("allocated memory: %ld\n",slob_allocator_get_total_memory_alloc());
	printf("free memory: %ld\n", slob_allocator_get_total_free_memory());
	return 0;
}