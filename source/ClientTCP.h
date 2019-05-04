#include "socket_lib.h"
#include "IClientServerTCP.h"
#include <netinet/in.h>	//socket (strutture)

class ClientTCP : public IClientServerTCP{
private:
    unsigned short _serverPortNumber;
    char _ipServer[DIM_IP];
    struct sockaddr_in _serverStructAddr;
    int _socketTCP;

    void serverStructInit();
    void socketTCPInit(); 

public:
    ClientTCP(const char* ipServer, unsigned short serverPortNumber);
    bool serverTCPconnection();
    void closeConnection();
    void sendMsg(void *buffer, size_t bufferSize);
    int recvMsg(void** buffer);
};