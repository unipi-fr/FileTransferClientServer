LIBS = my_crypto_lib.cpp socket_lib.cpp

all: client_ftp server_ftp

client_ftp:
	g++ -o client_ftp client_ftp.cpp $(LIBS) -lcrypto
	
server_ftp: 
	g++ -o server_ftp server_ftp.cpp $(LIBS) -lcrypto

clean:
	rm client_ftp server_ftp
