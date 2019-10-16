/* main.c
 *
 * Copyright (C) 2019 wolfSSL Inc.
 *
 * This file is part of wolfSSH.
 *
 * wolfSSH is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfSSH is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

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
