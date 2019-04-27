#include "socket_lib.h"
#include <time.h> //per la select()
class ServerTCP{
private:
	unsigned short _portNumber;	
	
	fd_set _mainSet;
	fd_set _readingSet;

	int _maxDescriptor;

	struct sockaddr_in _localAddrStruct;
	struct sockaddr_in _clientAddrStruct;
		
	int _listenerSocket;

	void localAddrStructInit();
	void listenerSocketInit();
	void acceptNewConnecction();
	void clientDisconected(int socket);
public: 
	ServerTCP(unsigned short portNumber);
//ritorna -1 se arriva una nuova connessione e l'accetta
//altrimenti ritorna il numero del socket da gestire
	int waitForRequest();
	int recvMsg(int socketRecvFrom,void** buffer);
	void sendMsg(int socketRecvFrom,void *buffer, size_t bufferSize);
};