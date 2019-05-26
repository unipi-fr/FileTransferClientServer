COMMON_LIBS = SecureConnection.h SecureMessageCreator.h CertificationValidator.h Sanitizator.h socket_lib.h 
COMMON_OBJ = SecureConnection.o SecureMessageCreator.o CertificationValidator.o Sanitizator.o socket_lib.o
CLIENT_LIBS = $(COMMON_LIBS) ClientTCP.h 
CLIENT_OBJ = $(COMMON_OBJ) ClientTCP.o 
SERVER_LIBS = $(COMMON_LIBS) ServerTCP.h 
SERVER_OBJ = $(COMMON_OBJ) ServerTCP.o 
all: client_ftp server_ftp
	rm *.o
client_ftp: $(CLIENT_OBJ) 
	g++ -o client_ftp client_ftp.cpp $(CLIENT_LIBS) $(CLIENT_OBJ) -lcrypto
	
server_ftp: $(SERVER_OBJ)
	mkdir -p server
	g++ -o server/server_ftp server_ftp.cpp $(SERVER_LIBS) $(SERVER_OBJ) -lcrypto
	
.cpp.o:
	g++ -c $<

clean:
	rm client_ftp server/server_ftp
