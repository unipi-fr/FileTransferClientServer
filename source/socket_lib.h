#include<string.h>	//per gestire le stringhe
#include<stdlib.h> 	//funzioni dilibreria standard (atoi,)
#include<sys/types.h>	//socket (costantie valori)
#include<sys/socket.h>	//socket (funzioni)
#include<netinet/in.h>	//socket (strutture)
#include<arpa/inet.h>	//standard per l'ordine dei byte
#include<unistd.h>		//close(socket)
#include<iostream>

#define DIM_IP 16

void sendTCP(int sendSocket, void *buffer, size_t bufferSize);
int recvTCP(int listenSocket, void** buffer);