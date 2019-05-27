#include "ServerTCP.h"
#include "Printer.h"
#include <time.h>   //per la select()
#include <unistd.h> //close(socket)

#include <string.h>	//per gestire le stringhe
#include <sys/types.h> //socket (costantie valori)
#include <sys/socket.h>	//socket (funzioni)
#include <arpa/inet.h>	//standard per l'ordine dei byte

void ServerTCP::localAddrStructInit(void)
{
    memset(&_localAddrStruct, 0, sizeof(_localAddrStruct)); // Pulizia
    _localAddrStruct.sin_family = AF_INET;
    _localAddrStruct.sin_port = htons(_portNumber);
    _localAddrStruct.sin_addr.s_addr = INADDR_ANY;
}

void ServerTCP::listenerSocketInit()
{
    int ret;
    _listenerSocket = socket(AF_INET, SOCK_STREAM, 0);
    ret = bind(_listenerSocket, (struct sockaddr *)&_localAddrStruct, sizeof(_localAddrStruct));
    if (ret < 0)
    {
        Printer::printError("Not possible binding the address.");
        exit(-1);
    }

    ret = listen(_listenerSocket, 1);
    if (ret < 0)
    {
        Printer::printError("Not possible switching in listening mode.");
        exit(-1);
    }
}

void ServerTCP::listenerSocketClose()
{
    close(_listenerSocket);
}

void ServerTCP::clientDisconnected()
{
    close(_comunicationSocket);
    _comunicationSocket = -1;
}

ServerTCP::ServerTCP(unsigned short portNumber)
{
    _portNumber = portNumber;
    _comunicationSocket = -1;
    localAddrStructInit();
    listenerSocketInit();
}

int ServerTCP::acceptNewConnecction()
{
    //listenerSocketInit();
    socklen_t len = sizeof(_clientAddrStruct);
    memset(&_clientAddrStruct, 0, len);
    _comunicationSocket = accept(_listenerSocket, (struct sockaddr *)&_clientAddrStruct, &len);
    if (_comunicationSocket < 0)
    {
        Printer::printError("Not possible accept new connection.");
    }
    
    return _comunicationSocket;
}

int ServerTCP::recvMsg(void **buffer)
{
    if (_comunicationSocket < 0)
    {
        Printer::printWaring("recvMsg called without a client connected.");
    }
    int numberOfBytes = recvTCP(_comunicationSocket, buffer);

    return numberOfBytes;
}

void ServerTCP::sendMsg(void *buffer, size_t bufferSize)
{
    if (_comunicationSocket < 0)
    {
        Printer::printWaring("SendMsg called without a client connected");
    }
    sendTCP(_comunicationSocket, buffer, bufferSize);
}

void ServerTCP::forceClientDisconnection()
{
    close(_comunicationSocket);
}
