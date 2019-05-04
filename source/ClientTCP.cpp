#include "ClientTCP.h"

void ClientTCP::serverStructInit()
{
    /*creazione indirizzo*/
    memset(&_serverStructAddr, 0, sizeof(_serverStructAddr)); //pulizia struttura
    _serverStructAddr.sin_family = AF_INET;
    _serverStructAddr.sin_port = htons(_serverPortNumber);      //setta il numero di porta nella struttura
    inet_pton(AF_INET, _ipServer, &_serverStructAddr.sin_addr); //setta l'indirizzo IP nella struttura
}

void ClientTCP::socketTCPInit()
{
    serverStructInit();
    /*creazione socket*/
    _socketTCP = socket(AF_INET, SOCK_STREAM, 0);
}

ClientTCP::ClientTCP(const char *ipServer, unsigned short serverPortNumber)
{
    //TODO: Da decontaminare
    memset(_ipServer, 0, DIM_IP);
    memcpy(_ipServer, ipServer, DIM_IP - 1);
    _serverPortNumber = serverPortNumber;

    socketTCPInit();
}

bool ClientTCP::serverTCPconnection()
{
    //Return true on succcessful connection false otherwise
    return connect(_socketTCP, (struct sockaddr *)&_serverStructAddr, sizeof(_serverStructAddr)) >= 0;
}

void ClientTCP::sendMsg(void *buffer, size_t bufferSize)
{
    sendTCP(_socketTCP, buffer, bufferSize);
}

int ClientTCP::recvMsg(void **buffer)
{
    int numberOfBytes = recvTCP(_socketTCP, buffer);
    return numberOfBytes;
}

void ClientTCP::closeConnection()
{
    close(_socketTCP);
}
