icmp_shell : buffer.o icmpshell.o
	gcc buffer.o icmpshell.o -lpthread -lm -o icmp_shell
buffer.o : buffer.c  buffer.h
	gcc -c -g -Wall buffer.c -o buffer.o
icmpshell.o : icmp_shell.c icmp_shell.h
	gcc -c -g -Wall icmp_shell.c -o icmpshell.o

clean :
	rm icmpshell.o buffer.o icmp_shell

