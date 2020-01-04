#include <stdio.h>
#include <time.h>

int testTime(time_t now){
    time_t triggerTime = 1578167180;
    if (!difftime(triggerTime, now))
    {
        return 1;
    }
    return 0;
    
    
}

int main(int argc, char const *argv[])
{
    time_t now = time(NULL);
    if (testTime(now))
        printf("bomb\n");
    else
    {
        printf("no_bomb\n");
    }
    return 0;
}
