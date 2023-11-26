#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

int main(int argc,char*argv[]){
    int fd1,fd2,res;
    char str[8192];


    fd1 = open("./mountdir/file1.txt",O_RDWR|O_CREAT,S_IRWXU);
    if(fd1 == -1){
        printf("Error in open\n");
    }


    fd1 = open("./mountdir/file2.txt",O_RDWR|O_CREAT,S_IRWXU);
    if(fd1 == -1){
        printf("Error in open\n");
    }

    res = read(fd2,str,8192);
    printf("%d\n",res);
    
    write(fd1,str,8192);
    write(fd1,str,8192);
    write(fd1,str,8192);
    /*We expect final size = 3*8192 = 24576*/

    close(fd1);
    close(fd2);
    
    
    return 0;

}