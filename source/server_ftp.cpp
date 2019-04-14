#include "SecureMessageCreator.h"
#include "ServerTCP.h"
#include <iostream>
#include <fstream>

using namespace std;

ServerTCP* server;
SecureMessageCreator* msgCreator;

void writeFile (char *input){
    ofstream file("file.txt");
    
    if (file.is_open()){
        file << input;
        file.close();
    }
    else 
        cout << "Unable to open file"<<endl;
}

void uploadCommand(int socketToManage){
	int numberOfBytes;
	unsigned char* buffer;
	numberOfBytes = server->recvMsg(socketToManage, (void**) &buffer);
	if(numberOfBytes == 0){
		return;
	}
	unsigned char* message;
	int messageSize;
	cout<<"["<<socketToManage<<"]";
	cout<<"[secureMessage]"<<buffer<<endl;
	bool check = msgCreator->DecryptAndCheckSign(buffer,numberOfBytes,&message,messageSize);
	cout<<"["<<socketToManage<<"]";
	cout<<"[message]"<<message<<endl;
	if (!check)
	{
		cout<<"["<<socketToManage<<"]";
		cout<<"[ERROR] not valid Hash"<<endl;
	}
	cout<<"["<<socketToManage<<"]";
	cout<<"[INFO] hash OK!"<<endl;

	cout<<"["<<socketToManage<<"]";
	cout<<"[FILE CONTENT]"<<message<<endl;
	writeFile((char*)message);
	free(buffer);
	free(message);
}

void manageConnection(int socketToManage){
		uploadCommand(socketToManage);
}



int main(int num_args, char* args[]){	
	if(num_args != 2){
		printf("\nERRORE: Numero dei parametri non valido.\nUsage: %s <portNumber>\nchiusura programma...\n",args[0]);
		exit(-2);
	}
	server = new ServerTCP(atoi(args[1]));
	msgCreator = new SecureMessageCreator();
	int activeSocket;
	for(;;){
		activeSocket = server->waitForRequest(); //se è una nuova connessione l'accetta e ritorna -1, altrimenti restituisce il socket da gestire
		if(activeSocket >= 0){
			manageConnection(activeSocket);
		}
	}	
return 0;
}
