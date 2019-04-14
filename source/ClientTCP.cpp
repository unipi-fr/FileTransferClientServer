#include "ClientTCP.h"
#include <iostream>
using namespace std;

void ClientTCP::serverStructInit(){
    /*creazione indirizzo*/
    memset(&_serverStructAddr,0,sizeof(_serverStructAddr)); //pulizia struttura
    _serverStructAddr.sin_family = AF_INET;
    _serverStructAddr.sin_port = htons(_serverPortNumber); //setta il numero di porta nella struttura
    inet_pton(AF_INET,_ipServer,&_serverStructAddr.sin_addr);//setta l'indirizzo IP nella struttura
}

void ClientTCP::socketTCPInit(){
    serverStructInit();
    /*creazione socket*/
    _socketTCP = socket(AF_INET, SOCK_STREAM, 0);
}

ClientTCP::ClientTCP(char* ipServer, unsigned short serverPortNumber){
    //TODO: Da decontaminare
    memset(_ipServer,0,DIM_IP);
    memcpy(_ipServer,ipServer,DIM_IP - 1);
    _serverPortNumber = serverPortNumber;
    
    socketTCPInit();
}

bool ClientTCP::serverTCPconnection(){
    if(connect(_socketTCP, (struct sockaddr*)&_serverStructAddr, sizeof(_serverStructAddr))){
        cout<<"\nERROR connect(): Failed connect to the server.";
        return false;
    }
    cout<<"Successfull connected to the server "<<_ipServer<<" (PORT: "<<_serverPortNumber<<")\n";
    return true;
}

void ClientTCP::sendMsg(void *buffer, size_t bufferSize){
    sendTCP(_socketTCP, buffer, bufferSize);
}

int ClientTCP::recvMsg(void** buffer){
    int numberOfBytes = recvTCP(_socketTCP,buffer);
    return numberOfBytes;
}
