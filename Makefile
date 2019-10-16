all: sample

sshtest.o: sshtest.c sshtest.h
	gcc -DSSHTEST_LOG -c -o sshtest.o sshtest.c

main.o: main.c sshtest.h
	gcc -c -o main.o main.c

sample: main.o sshtest.o
	gcc -o sample main.o sshtest.o -lwolfssl -lm -lwolfssh

clean:
	rm -rf *.o sample

.PHONY: clean all
