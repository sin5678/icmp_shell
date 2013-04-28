OBJ = buffer.o icmp_shell.o
icmp_shell : $(OBJ)
	gcc $(OBJ) -lpthread -lm -o icmp_shell
buffer.o :  buffer.h
icmp_shell.o :  icmp_shell.h buffer.h

clean :
	rm $(OBJ) icmp_shell
