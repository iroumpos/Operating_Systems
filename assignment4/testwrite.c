#include <stdio.h>
#include <stdlib.h>

int main()
{
   
   FILE *fptr1,*fptr2,*fptr3;

   if ((fptr1 = fopen("file1.txt","w")) == NULL){
       printf("Error! opening file");
       exit(1);
   }

   if ((fptr2 = fopen("file2.txt","w")) == NULL){
       printf("Error! opening file");
       exit(1);
   }

   if ((fptr3 = fopen("file3.txt","w")) == NULL){
       printf("Error! opening file");
       exit(1);
   }

   for(int i=0; i<4096; i++){
       fprintf(fptr1,"a");
       fprintf(fptr2,"d");
       fprintf(fptr3,"g");
   }
   for(int i=4096;i <8192; i++){
       fprintf(fptr1,"b");
       fprintf(fptr2,"c");
       fprintf(fptr3,"h");
   }

   fclose(fptr1);
   fclose(fptr2); 
   fclose(fptr3);
  
   return 0;
}