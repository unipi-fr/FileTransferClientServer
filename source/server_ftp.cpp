#include "my_crypto_lib.h"
#include "socket_lib.h"
#include<time.h> //per la select()
#include <iostream>
#include <fstream>

using namespace std;

int portNumber;	
	
fd_set mainSet;
fd_set readingSet;

int maxDescriptor;

struct sockaddr_in localAddrStruct;
struct sockaddr_in clientAddrStruct;
	
int listenerSocket;


void writeFile (char *input){
    ofstream file("file.txt");
    
    if (file.is_open()){
        file << input;
        file.close();
    }
    else 
        cout << "Unable to open file"<<endl;
}

void localAddrStructInit(){
	localAddrStruct.sin_family = AF_INET;
	localAddrStruct.sin_addr.s_addr = INADDR_ANY;
	localAddrStruct.sin_port = htons(portNumber);
}

void listenerSocketInit(){
	listenerSocket = socket(AF_INET,SOCK_STREAM,0);
	if(listenerSocket == -1){
		std::cout<<"ERRORE socket() nella creazione del socket di ascolto: ";
		exit(-1);
	}
	if(bind(listenerSocket, (struct sockaddr*)&localAddrStruct, sizeof(localAddrStruct)) == -1){
		std::cout<<"ERRORE bind(): ";
		exit(-1);
	}
	if(listen(listenerSocket,10)){
		std::cout<<"ERRORE listen(): ";
		exit(-1);
	}
	
	FD_SET(listenerSocket, &mainSet);//aggiorno il socket d'ascolto al set principale
	maxDescriptor = listenerSocket;//tengo traccia del socket con l'id più alto 
	
}

void inizializza_variabili_globali(char* args[]){
	portNumber = atoi(args[1]);

	/*Azzeramento set*/
	FD_ZERO(&mainSet);
	FD_ZERO(&readingSet);
	
	localAddrStructInit();
	listenerSocketInit();
	std::cout<<"Server pronto a ricevere sulla porta "<<portNumber<<std::endl;
}



void acceptNewConnecction(){
	socklen_t addressSize;
	int newSocket;
	addressSize = sizeof(clientAddrStruct);
	//accetto la connessione
	newSocket = accept(listenerSocket, (struct sockaddr*)&clientAddrStruct, &addressSize);
	if(newSocket == -1){
		perror("ERRORE accept() sulla nuova connessione: ");
		exit(-1);
	}
	//aggiungo il nuovo socket al set principale per controllarlo successivamente
	FD_SET(newSocket,&mainSet);
	//se il suo id è maggiore aggiorno anche il maxDescriptor
	if(newSocket>maxDescriptor){
		maxDescriptor = newSocket;
	}
	printf("[%d]",newSocket);
	printf("Nuovo client connesso.\n");
}

void clientDisconected(int socket){
	close(socket);
	FD_CLR(socket,&mainSet);
    printf("[%d]",socket);
	printf("Client disconnesso.\n");
}

void manageConnection(int socketToManage){
	int numberOfBytes;
	char* buffer;
	numberOfBytes = recvTCP(socketToManage,(void**)&buffer);
    if(numberOfBytes == 0){
		clientDisconected(socketToManage);
		return;
	}
    cout<<"[FILE CONTENT]"<<buffer<<endl;
    writeFile(buffer);
}
int main(int num_args, char* args[]){
	int i;
	
	if(num_args != 2){
		printf("\nERRORE: Numero dei parametri non valido.\nUsage: %s <portNumber>\nchiusura programma...\n",args[0]);
		exit(-2);
	}
	inizializza_variabili_globali(args);
	
	for(;;){
		readingSet = mainSet;//copio per la modifica
		//mi metto in attesa finchè un socket non è pronto
		select(maxDescriptor+1, &readingSet, NULL, NULL, NULL);
		/*CONTROLLO TUTTO IL SET*/
		for(i=0; i<= maxDescriptor; i++){
			//cerco queli pronti
			if(FD_ISSET(i,&readingSet)){
				//se è pronto il socket d'ascolto allora c'è una nuova connessione
				if(i == listenerSocket){
					acceptNewConnecction();
				}else{
					//è un altro socket
					manageConnection(i);
				}
			}
		}
	}
	
return 0;
}
