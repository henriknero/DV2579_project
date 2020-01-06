#include <stdio.h>
#include <string.h>
int main(int argc, char const *argv[])
{
    if (argc<3){
        printf("No Bomb\n");
    }
    else {
        if (!strncmp(argv[1], "bomb_string", 11)){
            if (!strncmp(argv[2], "bomb_2", 6)){
                printf("Bomb\n");
            }
        }

            
    }
    return 0;
}
