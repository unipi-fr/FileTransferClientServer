#include "my_crypto_lib.h"
#include "socket_lib.h"
#include <time.h> //per la select()
#include <iostream>
#include <fstream>

using namespace std;

class ServerTCP{
public: 
	ServerTCP(unsigned short portNumber){
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
	int waitForRequest(){	
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
	int recvMsg(int socketRecvFrom,void** buffer){
		int numberOfBytes = recvTCP(socketRecvFrom,buffer);
		if(numberOfBytes == 0){
			clientDisconected(socketRecvFrom);
			return numberOfBytes;
		}
		return numberOfBytes;
	}

private:
	unsigned short _portNumber;	
	
	fd_set _mainSet;
	fd_set _readingSet;

	int _maxDescriptor;

	struct sockaddr_in _localAddrStruct;
	struct sockaddr_in _clientAddrStruct;
		
	int _listenerSocket;

	void localAddrStructInit(){
		_localAddrStruct.sin_family = AF_INET;
		_localAddrStruct.sin_addr.s_addr = INADDR_ANY;
		_localAddrStruct.sin_port = htons(_portNumber);
	}
	void listenerSocketInit(){
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

	void acceptNewConnecction(){
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

	void clientDisconected(int socket){
		close(socket);
		FD_CLR(socket,&_mainSet);
		printf("[%d]",socket);
		printf("Client disconnesso.\n");
	}

};

ServerTCP* server;

void writeFile (char *input){
    ofstream file("file.txt");
    
    if (file.is_open()){
        file << input;
        file.close();
    }
    else 
        cout << "Unable to open file"<<endl;
}

void manageConnection(int socketToManage){
		int numberOfBytes;
		unsigned char* buffer;
		numberOfBytes = server->recvMsg(socketToManage, (void**) &buffer);
		if(numberOfBytes == 0){
			return;
		}
		
		cout<<"[chiperText]"<<buffer<<endl;
		
		unsigned char *decryptedText = (unsigned char*)malloc(numberOfBytes);
		int decryptLen = decrypt(buffer, numberOfBytes, NULL, decryptedText);
		
		//declaring the hash function we want to use
		const EVP_MD* md = EVP_sha256();
		int hashSize; //size of the digest
		hashSize = EVP_MD_size(md);
		
		unsigned char *msg = decryptedText + hashSize;
		unsigned char *hash = (unsigned char*) malloc(hashSize);
		memcpy(decryptedText, hash, hashSize);
		
		if(check_hash(msg, decryptLen - hashSize, hash)){
			cout<<"firma Valida"<<endl;
		} else {
			cout<<"Errore nella Firma"<<endl;
			return;
		}
		
		cout<<"[FILE CONTENT]"<<msg<<endl;
		writeFile((char*)msg);
	}

int main(int num_args, char* args[]){	
	if(num_args != 2){
		printf("\nERRORE: Numero dei parametri non valido.\nUsage: %s <portNumber>\nchiusura programma...\n",args[0]);
		exit(-2);
	}
	server = new ServerTCP(atoi(args[1]));
	int activeSocket;
	for(;;){
		activeSocket = server->waitForRequest(); //se è una nuova connessione l'accetta e ritorna -1, altrimenti restituisce il socket da gestire
		if(activeSocket >= 0){
			manageConnection(activeSocket);
		}
	}	
return 0;
}
