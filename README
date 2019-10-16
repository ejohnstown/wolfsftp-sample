wolfsftp automated sample client
================================

This is a sample wolfSFTP client that performs an alternating get or put every
10 seconds. The actions are self-contained from connect to close, but they do
share a WOLFSSH_CTX object.


prerequisites
-------------

The sample application requires both wolfSSL and wolfSSH to be installed.
Configure wolfSSL with the following options:

    $ cd wolfssl
    $ ./configure --enable-ssh --enable-cryptonly --enable-aesctr
    $ make
    $ sudo make install

After wolfSSL is installed, configure and build wolfSSH:

    $ cd wolfssh
    $ ./configure --enable-sftp
    $ make
    $ sudo make install


configuration
-------------

The sample is configured with the strings in the file sshtest.c.

    static const char SSH_Test_Username[] = "username";
    static const char SSH_Test_Password[] = "password";
    static const char SSH_Test_IPv4[] = "127.0.0.1";
    static const int SSH_Test_Port = 22;
    static const char SSH_Test_SrcName[] = "A";
    static const char SSH_Test_DstName[] = "B";
    static const char SSH_Test_RemoteDirName[] = "./";
    static const char SSH_Test_LocalDirName[] = "./";

The username, password, address, and port are straightforward. Files are always
copied from src to dst. The source file should always exist both the local
and remote directories. The start of the remote path is provided by the
remote endpoint. On a usual machine, the remote path would be the home
directory name for username, "/home/username". The local path starts with the
current directory the sample is run from.

Using the above settings, the put and get commands look like:

    put ./A /home/username/./B
    get /home/username/./A ./B

In either case, the file "A" must exist on both endpoints. File "B" will be
overwritten on both endpoints.

There is a compile flag that can be deleted from the Makefile,
"-DSSHTEST_LOG". This enables the logging, which is sparse.

Last, there is a define in main.c, TEST_TIMEOUT, that is set to 10 seconds.


build and run
-------------

And now, build and run the sample:

    $ cd wolfsftp-sample
    $ make
    $ ./sample

If logging isn't enabled, you shouldn't see anything. Ctrl-C should stop it.
You can look at the files and delete the "B" files and they'll repopulate
eventually.
