#include <stdio.h>
#include <unistd.h>

int main(int argc,char* argv[]){
    unlink("./mountdir/file3.txt");
    return 0;
}