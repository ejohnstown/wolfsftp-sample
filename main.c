#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include "sshtest.h"


#define TEST_TIMEOUT 10


static int shutdown = 0;


static void signal_handler(const int sig)
{
    if (sig == SIGINT)
        shutdown = 1;
}


int main(void)
{
    int ret;
    int doPut = 0;

    signal(SIGINT, signal_handler);
    ret = SSH_Test_Init();

    do {
        if (doPut) {
            ret = SSH_Test_Put();
        }
        else {
            ret = SSH_Test_Get();
        }
        doPut = !doPut;

        sleep(TEST_TIMEOUT);
    } while (!shutdown && ret == 0);

    ret |= SSH_Test_Cleanup();

    return ret ? 1 : 0;
}
