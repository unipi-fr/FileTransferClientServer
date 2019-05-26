#include "socket_lib.h"
#include <arpa/inet.h>	//standard per l'ordine dei byte
#include <stdlib.h> 
//#include <iostream>



void sendTCP(int sendSocket, void *buffer, size_t bufferSize){
    uint16_t standardSize;
    int numberOfBytes;
    
    standardSize = htons(bufferSize);
    
    //invio numero di dati
    numberOfBytes = send(sendSocket,(void*)&standardSize, sizeof(uint16_t),0);
    if(numberOfBytes == -1){
        throw DisconnectionException();
    }
    
    //invio dati
    numberOfBytes = send(sendSocket, (void*)buffer, bufferSize, 0);
    if(numberOfBytes == -1){
        throw DisconnectionException();
    }
}

int recvTCP(int listenSocket, void** buffer){
    uint16_t standardSize;
    int numberOfBytes;
    int bufferSize;
    
    //ricevo la standardSize
    numberOfBytes = recv(listenSocket, (void*)&standardSize, sizeof(uint16_t), MSG_WAITALL);
    if(numberOfBytes == 0){
        throw DisconnectionException();
    }
    if(numberOfBytes == -1){
        throw NetworkException();
    }
    if(numberOfBytes != sizeof(uint16_t)){
        //std::cout<<"[DEBUGbytesRecived ]"<<numberOfBytes<<" [expectedSize] "<<bufferSize<<std::endl;
        throw NetworkException();
    }
    
    //riconverto i dati
    bufferSize = ntohs(standardSize);
    
    //alloco il buffer
    (*buffer) = malloc(bufferSize);
    if((*buffer) == NULL ){
        throw MallocException();
    }

    //uso la lunghezzaPrecisa per ricevere la stringa
    numberOfBytes = recv(listenSocket, (void*)(*buffer), bufferSize, MSG_WAITALL);
    if(numberOfBytes == -1){
        throw NetworkException();
    }
    if(numberOfBytes != bufferSize){
        //std::cout<<"[DEBUGbytesRecived ]"<<numberOfBytes<<" [expected] "<<bufferSize<<std::endl;
        throw NetworkException();
    }

    return numberOfBytes;
}