#include "ServerTCP.h"
#include <iostream>
#include <time.h> //per la select()
using namespace std;

void ServerTCP::localAddrStructInit(void){
    memset(&_localAddrStruct, 0, sizeof(_localAddrStruct)); // Pulizia 
    _localAddrStruct.sin_family = AF_INET;
    _localAddrStruct.sin_port = htons(_portNumber);
    _localAddrStruct.sin_addr.s_addr = INADDR_ANY;
}

void ServerTCP::listenerSocketInit(){
    int ret;
    _listenerSocket = socket(AF_INET, SOCK_STREAM, 0);
    ret = bind(_listenerSocket, (struct sockaddr*)&_localAddrStruct, sizeof(_localAddrStruct) );
    if(ret < 0){
        cout<<"[ERROR] not possible binding the address."<<endl;
        exit(-1);
    }
    ret = listen(_listenerSocket, 0);
    if(ret < 0){
        cout<<"[ERROR] not possible switching in listening mode."<<endl;
        exit(-1);
    }
}

void ServerTCP::listenerSocketClose(){
    close(_listenerSocket);
}

void ServerTCP::clientDisconnected(){
    close(_comunicationSocket);
    _comunicationSocket = -1;
}

ServerTCP::ServerTCP(unsigned short portNumber){
    _portNumber = portNumber;
    _comunicationSocket = -1;
    localAddrStructInit();
    cout<<"[INFO]Server successfull listening on port "<<_portNumber<<endl;
}

int ServerTCP::acceptNewConnecction(){
    listenerSocketInit();
    socklen_t len = sizeof(_clientAddrStruct);
    memset(&_clientAddrStruct,0,len);
    _comunicationSocket = accept(_listenerSocket, (struct sockaddr*) &_clientAddrStruct, &len);
    if(_comunicationSocket<0){
        cout<<"[ERROR] not possible accept new connection."<<endl;
    }else{
        listenerSocketClose();
    }
    return _comunicationSocket;
}

int ServerTCP::recvMsg(void** buffer){
    if(_comunicationSocket<0){
        cout<<"[ERROR] recvMsg called without a client connected."<<endl;
    }
    int numberOfBytes = recvTCP(_comunicationSocket,buffer);
    if(numberOfBytes == 0){
        clientDisconnected();
    }
    return numberOfBytes;
}

void ServerTCP::sendMsg(void *buffer, size_t bufferSize){
    if(_comunicationSocket<0){
        cout<<"[ERROR] sendMsg called without a client connected"<<endl;
    }
    sendTCP(_comunicationSocket, buffer, bufferSize);
}

void ServerTCP::forceClientDisconnection(){
    close(_comunicationSocket);
}

