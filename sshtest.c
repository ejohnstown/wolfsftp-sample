/* sshtest.c
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
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <wolfssl/options.h>
#include <wolfssh/wolfsftp.h>
#include "sshtest.h"


WOLFSSH_CTX* gSshCtx = NULL;


#ifdef SSHTEST_LOG
    #define TLOG(...) do { printf(__VA_ARGS__); } while (0)
#else
    #define TLOG(...) do { ; } while (0)
#endif


static const char SSH_Test_Username[] = "username";
static const char SSH_Test_Password[] = "password";
static const char SSH_Test_IPv4[] = "127.0.0.1";
static const int SSH_Test_Port = 22;
static const char SSH_Test_SrcName[] = "A";
static const char SSH_Test_DstName[] = "B";
static const char SSH_Test_RemoteDirName[] = "./";
static const char SSH_Test_LocalDirName[] = "./";


static
int SSH_Test_UserAuthCb(
        byte authType,
        WS_UserAuthData* authData,
        void* ctx)
{
    int ret = WOLFSSH_USERAUTH_INVALID_AUTHTYPE;

    if (authType == WOLFSSH_USERAUTH_PASSWORD) {
        const char* password = (const char*)ctx;
        word32 passwordSz = 0;

        ret = WOLFSSH_USERAUTH_SUCCESS;
        if (password != NULL) {
            passwordSz = (word32)strlen(password);
        }

        if (ret == WOLFSSH_USERAUTH_SUCCESS) {
            authData->sf.password.password = (const byte*)password;
            authData->sf.password.passwordSz = passwordSz;
        }
    }
    return ret;
}


void wolfSSH_Debugging_ON(void);


int SSH_Test_Init(void)
{
    int ret;

    TLOG("Entering SSH_Test_Init()\n");

    ret = wolfSSH_Init();

    if (0 == ret) {
        gSshCtx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_CLIENT, NULL);
        ret = NULL == gSshCtx;
    }
    if (0 == ret) {
        ret = wolfSSH_CTX_SetBanner(gSshCtx, NULL);
    }

    if (0 == ret) {
        wolfSSH_SetUserAuth(gSshCtx, SSH_Test_UserAuthCb);
    }

    TLOG("Leaving SSH_Test_Init(), ret = %d\n", ret);
    return ret;
}


int SSH_Test_Cleanup(void)
{
    int ret = 0;
    TLOG("Entering SSH_Test_Cleanup()\n");

    wolfSSH_CTX_free(gSshCtx);

    ret = wolfSSH_Cleanup();

    TLOG("Leaving SSH_Test_Cleanup(), ret = %d\n", ret);
    return ret;
}


static
int SSH_Test_GetWorkingDir(WOLFSSH* ssh, char* dir, size_t dirSz)
{
    WS_SFTPNAME* name = NULL;
    int ret, err;

    TLOG("Entering SSH_Test_GetWorkingDir()\n");

    if (dir != NULL) {
        do {
            name = wolfSSH_SFTP_RealPath(ssh, (char*)".");
            err = wolfSSH_get_error(ssh);
        } while (err == WS_WANT_READ || err == WS_WANT_WRITE);
    }
    ret = (NULL == name);

    if (ret == 0) {
        if (name->fSz < dirSz) {
            memcpy(dir, name->fName, name->fSz);
            dir[name->fSz] = '\0';
        }
        else
            ret = -1;
    }

    wolfSSH_SFTPNAME_list_free(name);

    TLOG("Leaving SSH_Test_GetWorkingDir(), ret = %d\n", ret);
    return ret;
}


static
int SSH_Test_StartupSession(WOLFSSH** ssh)
{
    WOLFSSH* newSsh;
    int ret = -1, socketFd;

    TLOG("Entering SSH_Test_StartupSession()\n");

    if (ssh != NULL) {
        newSsh = wolfSSH_new(gSshCtx);
        if (newSsh != NULL)
            ret = 0;
    }

    if (ret == 0) {
        wolfSSH_SetUserAuthCtx(newSsh, (void*)SSH_Test_Password);

        /* The following is how wolfSSH checks the public key presented
         * by the server. On the command line, one usually has a list
         * of public keys associated with servers and just looks it up. 
         * This demo is going to just accept the key.
        wolfSSH_CTX_SetPublicKeyCheck(gSshCtx, wsPublicKeyCheck);
        wolfSSH_SetPublicKeyCheckCtx(newSsh, (void*)"You've been sampled!"); */

        ret = wolfSSH_SetUsername(newSsh, SSH_Test_Username);
    }

    if (ret == 0) {
        socketFd = socket(AF_INET, SOCK_STREAM, 0);
        ret = (socketFd < 0);
    }

    if (ret == 0) {
        struct sockaddr_in peerAddr;

        memset(&peerAddr, 0, sizeof(peerAddr));

        peerAddr.sin_family = AF_INET;
        peerAddr.sin_port = htons(SSH_Test_Port);
        peerAddr.sin_addr.s_addr = inet_addr(SSH_Test_IPv4);

        ret = connect(socketFd,
                (const struct sockaddr *)&peerAddr, sizeof(peerAddr));
    }

    if (ret == 0)
        ret = wolfSSH_set_fd(newSsh, socketFd);

    if (ret == 0)
        ret = wolfSSH_SFTP_connect(newSsh);

    if (ssh != NULL && ret != 0)
        wolfSSH_free(newSsh);

    if (ret == 0)
        *ssh = newSsh;

    TLOG("Leaving SSH_Test_StartupSession(), ret = %d\n", ret);
    return ret;
}


static
int SSH_Test_ShutdownSession(WOLFSSH* ssh)
{
    int ret = -1, socketFd;

    TLOG("Entering SSH_Test_ShutdownSession()\n");

    if (ssh != NULL) {
        socketFd = wolfSSH_get_fd(ssh);
        ret = 0;
    }
    if (ret == 0)
        ret = wolfSSH_shutdown(ssh);

    wolfSSH_free(ssh);
    close(socketFd);

    TLOG("Leaving SSH_Test_ShutdownSession(), ret = %d\n", ret);
    return ret;
}


int SSH_Test_Get(void)
{
    WOLFSSH* ssh;
    char workingDir[32];
    char localPath[40];
    char remotePath[40];
    int ret, err;

    TLOG("Entering SSH_Test_Get()\n");

    ret = SSH_Test_StartupSession(&ssh);

    if (ret == WS_SUCCESS)
        ret = SSH_Test_GetWorkingDir(ssh, workingDir, sizeof(workingDir));

    if (ret == WS_SUCCESS) {
        strncpy(remotePath, workingDir, sizeof(remotePath));
        strncat(remotePath, "/",
                sizeof(remotePath) - strlen(remotePath) - 1);
        strncat(remotePath, SSH_Test_RemoteDirName,
                sizeof(remotePath) - strlen(remotePath) - 1);
        strncat(remotePath, SSH_Test_SrcName,
                sizeof(remotePath) - strlen(remotePath) - 1);

        strncpy(localPath, SSH_Test_LocalDirName, sizeof(localPath));
        strncat(localPath, SSH_Test_DstName,
                sizeof(localPath) - strlen(localPath) - 1);

        TLOG("get %s %s\n", remotePath, localPath);

        do {
            err = 0;
            ret = wolfSSH_SFTP_Get(ssh, remotePath, localPath, 0, NULL);
            if (ret != WS_SUCCESS)
                err = wolfSSH_get_error(ssh);
        } while ((err == WS_WANT_READ || err == WS_WANT_WRITE) &&
                ret != WS_SUCCESS);
    }

    ret |= SSH_Test_ShutdownSession(ssh);

    TLOG("Leaving SSH_Test_Get(), ret = %d\n", ret);
    return ret;
}


int SSH_Test_Put(void)
{
    WOLFSSH* ssh;
    char workingDir[32];
    char localPath[40];
    char remotePath[40];
    int ret, err;

    TLOG("Entering SSH_Test_Put()\n");

    ret = SSH_Test_StartupSession(&ssh);

    if (ret == WS_SUCCESS)
        ret = SSH_Test_GetWorkingDir(ssh, workingDir, sizeof(workingDir));

    if (ret == WS_SUCCESS) {
        strncpy(localPath, SSH_Test_LocalDirName, sizeof(localPath));
        strncat(localPath, SSH_Test_SrcName,
                sizeof(localPath) - strlen(localPath) - 1);

        strncpy(remotePath, workingDir, sizeof(remotePath));
        strncat(remotePath, "/",
                sizeof(remotePath) - strlen(remotePath) - 1);
        strncat(remotePath, SSH_Test_RemoteDirName,
                sizeof(remotePath) - strlen(remotePath) - 1);
        strncat(remotePath, SSH_Test_DstName,
                sizeof(remotePath) - strlen(remotePath) - 1);

        TLOG("put %s %s\n", localPath, remotePath);

        do {
            err = 0;
            ret = wolfSSH_SFTP_Put(ssh, localPath, remotePath, 0, NULL);
            if (ret != WS_SUCCESS)
                err = wolfSSH_get_error(ssh);
        } while ((err == WS_WANT_READ || err == WS_WANT_WRITE) &&
                ret != WS_SUCCESS);
    }

    ret |= SSH_Test_ShutdownSession(ssh);

    TLOG("Leaving SSH_Test_Put(), ret = %d\n", ret);
    return ret;
}
