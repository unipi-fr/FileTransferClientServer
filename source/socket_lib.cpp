#include "socket_lib.h"

void sendTCP(int sendSocket, void *buffer, size_t bufferSize){
    uint16_t standardSize;
    int numberOfBytes;
    
    standardSize = htons(bufferSize);
    
    //invio numero di dati
    numberOfBytes = send(sendSocket,(void*)&standardSize, sizeof(uint16_t),0);
    if(numberOfBytes == -1){
        std::cout<<"ERRORE send()"<<std::endl;
        exit(-5);
    }
    
    //invio dati
    numberOfBytes = send(sendSocket, (void*)buffer, bufferSize, 0);
    if(numberOfBytes == -1){
        std::cout<<"ERRORE send()"<<std::endl;
        exit(-5);
    }
}

int recvTCP(int listenSocket, void** buffer){
    uint16_t standardSize;
    int numberOfBytes;
    int bufferSize;
    
    //ricevo la standardSize
    numberOfBytes = recv(listenSocket, (void*)&standardSize, sizeof(uint16_t), 0);
    if(numberOfBytes == 0){
        return 0;
    }
    if(numberOfBytes == -1){
        std::cout<<"ERRORE recv() (1)"<<std::endl;
        exit(-5);
    }
    
    //riconverto i dati
    bufferSize = ntohs(standardSize);
    
    //alloco il buffer
    (*buffer) = malloc(bufferSize);
    //uso la lunghezzaPrecisa per ricevere la stringa
    numberOfBytes = recv(listenSocket, (void*)(*buffer), bufferSize, 0);
    if(numberOfBytes == -1){
        std::cout<<"ERRORE recv() (2)"<<std::endl;
        exit(-5);
    }
    return numberOfBytes;
}