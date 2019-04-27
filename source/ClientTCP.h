#include "socket_lib.h"
class ClientTCP{
private:
    unsigned short _serverPortNumber;
    char _ipServer[DIM_IP];
    struct sockaddr_in _serverStructAddr;
    int _socketTCP;

    void serverStructInit();
    void socketTCPInit(); 

public:
    ClientTCP(char* ipServer, unsigned short serverPortNumber);
    bool serverTCPconnection();
    void closeConnection();
    void sendMsg(void *buffer, size_t bufferSize);
    int recvMsg(void** buffer);
};