LIBS = my_crypto_lib.h socket_lib.h
OBJ = my_crypto_lib.o socket_lib.o

all: client_ftp server_ftp

client_ftp: $(OBJ)
	g++ -o client_ftp client_ftp.cpp $(OBJ) $(LIBS) -lcrypto
	
server_ftp: $(OBJ)
	g++ -o server_ftp server_ftp.cpp $(OBJ) $(LIBS) -lcrypto

.c.o:
	g++ -c $< -lcrypto

clean:
	rm client_ftp server_ftp *.o
