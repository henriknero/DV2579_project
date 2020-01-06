#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>


// {"s":{"length": 4}}
int main(int argc, char* argv[]) {
    int symvar = 48;
    pid_t pid = getpid();
    if(pid == symvar)
        printf("Bomb");
    else
        printf("No bomb");
}
