#include<stdio.h>
#include<stdlib.h>

#define MAX_ITERS 3000

int main(int argc, char *argv[]){

	int *array;
	int i;
	
	for(i = 0; i < MAX_ITERS; i++){
		// allocate memory for an array of integers
		array = (int*)malloc(25*sizeof(int));
		if(array == NULL){
			printf("malloc failed to allocate memory\n");
		}
	}
	
	return 0;
}