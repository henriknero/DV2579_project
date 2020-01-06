#include <string.h> 
#include <stdio.h>

int logic_bomb(char* s) {
    int trigger = 0;
    FILE *fp = fopen(s, "r");
    if(fp != NULL) {
	    trigger = 1;
        fclose(fp);
    }

    if(trigger) {
        return 1;
    } else {
        return 0;
    }
}

int main(int argc, char const *argv[])
{
    if(logic_bomb("test_file"))
        printf("Bomb\n");
    else
    {
        printf("No bomb\n");
    }
    return 0;
}
