#include "ServerTCP.h"
#include <iostream>
using namespace std;

ServerTCP::ServerTCP(unsigned short portNumber){
    _portNumber = portNumber;

    /*Azzeramento set*/
    FD_ZERO(&_mainSet);
    FD_ZERO(&_readingSet);
    
    localAddrStructInit();
    listenerSocketInit();
    std::cout<<"Server pronto a ricevere sulla porta "<<_portNumber<<std::endl;
}

//ritorna -1 se arriva una nuova connessione e l'accetta
//altrimenti ritorna il numero del socket da gestire
int ServerTCP::waitForRequest(){	
    _readingSet = _mainSet;//copio per la modifica
    //mi metto in attesa finchè un socket non è pronto
    select(_maxDescriptor+1, &_readingSet, NULL, NULL, NULL);
    /*CONTROLLO TUTTO IL SET*/
    for(int i=0; i<= _maxDescriptor; i++){
        //cerco queli pronti
        if(FD_ISSET(i,&_readingSet)){
            //se è pronto il socket d'ascolto allora c'è una nuova connessione
            if(i == _listenerSocket){
                acceptNewConnecction();
                return -1;
            }else{
                //è un altro socket
                return i;
            }
        }
    }
    return -1;
}

int ServerTCP::recvMsg(int socketRecvFrom,void** buffer){
    int numberOfBytes = recvTCP(socketRecvFrom,buffer);
    if(numberOfBytes == 0){
        clientDisconected(socketRecvFrom);
        return numberOfBytes;
    }
    return numberOfBytes;
}

void ServerTCP::localAddrStructInit(){
    _localAddrStruct.sin_family = AF_INET;
    _localAddrStruct.sin_addr.s_addr = INADDR_ANY;
    _localAddrStruct.sin_port = htons(_portNumber);
}

void ServerTCP::listenerSocketInit(){
    _listenerSocket = socket(AF_INET,SOCK_STREAM,0);
    if(_listenerSocket == -1){
        std::cout<<"ERRORE socket() nella creazione del socket di ascolto: ";
        exit(-1);
    }
    if(bind(_listenerSocket, (struct sockaddr*)&_localAddrStruct, sizeof(_localAddrStruct)) == -1){
        std::cout<<"ERRORE bind(): ";
        exit(-1);
    }
    if(listen(_listenerSocket,10)){
        std::cout<<"ERRORE listen(): ";
        exit(-1);
    }

    FD_SET(_listenerSocket, &_mainSet);//aggiorno il socket d'ascolto al set principale
    _maxDescriptor = _listenerSocket;//tengo traccia del socket con l'id più alto 
}

void ServerTCP::acceptNewConnecction(){
    socklen_t addressSize;
    int newSocket;
    addressSize = sizeof(_clientAddrStruct);
    //accetto la connessione
    newSocket = accept(_listenerSocket, (struct sockaddr*)&_clientAddrStruct, &addressSize);
    if(newSocket == -1){
        perror("ERRORE accept() sulla nuova connessione: ");
        exit(-1);
    }
    //aggiungo il nuovo socket al set principale per controllarlo successivamente
    FD_SET(newSocket,&_mainSet);
    //se il suo id è maggiore aggiorno anche il _maxDescriptor
    if(newSocket>_maxDescriptor){
        _maxDescriptor = newSocket;
    }
    printf("[%d]",newSocket);
    printf("Nuovo client connesso.\n");
}

void ServerTCP::clientDisconected(int socket){
    close(socket);
    FD_CLR(socket,&_mainSet);
    printf("[%d]",socket);
    printf("Client disconnesso.\n");
}