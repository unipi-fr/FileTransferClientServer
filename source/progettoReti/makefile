all: client_msg server_msg

client_msg: client_msg.o libreria_comune.o

server_msg: server_msg.o libreria_comune.o

.c.o:
	gcc -Wall -c $<

cleanAll:
	rm client_msg server_msg *.o 

clean:
	rm *.o
