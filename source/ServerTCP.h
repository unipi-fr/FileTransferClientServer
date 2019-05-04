#include "socket_lib.h"
#include "IClientServerTCP.h"
#include <netinet/in.h>	//socket (strutture)

class ServerTCP : public IClientServerTCP{
private:
	unsigned short _portNumber;	

	struct sockaddr_in _localAddrStruct;
	struct sockaddr_in _clientAddrStruct;
		
	int _listenerSocket, _comunicationSocket;

	void localAddrStructInit();
	void listenerSocketInit();
	void listenerSocketClose();
	void clientDisconnected();
public: 
	ServerTCP(unsigned short portNumber);
//ritorna -1 se arriva una nuova connessione e l'accetta
//altrimenti ritorna il numero del socket da gestire
	int acceptNewConnecction();
	int recvMsg(void** buffer);
	void sendMsg(void *buffer, size_t bufferSize);
	void forceClientDisconnection();
};