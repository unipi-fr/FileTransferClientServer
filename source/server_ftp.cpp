#include "SecureMessageCreator.h"
#include "ServerTCP.h"
#include <iostream>
#include <fstream>
#include <sstream>

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

void uploadCommand(string fileName,size_t fileSize){
	cout<<"[DEBUG] upload command called succefull with filename="<<fileName<<" and fileSize="<<fileSize<<".\n unfurtnally not implemented yet :("<<endl;
	return;
	int numberOfBytes;
	unsigned char* buffer;
	numberOfBytes = server->recvMsg((void**) &buffer);
	if(numberOfBytes == 0){
		return;
	}
	unsigned char* message;
	int messageSize;
	cout<<"[secureMessage]"<<buffer<<endl;
	bool check = msgCreator->DecryptAndCheckSign(buffer,numberOfBytes,&message,messageSize);
	cout<<"[message]"<<message<<endl;
	if (!check)
	{
		cout<<"[ERROR] not valid Hash"<<endl;
	}
	cout<<"[INFO] hash OK!"<<endl;

	cout<<"[FILE CONTENT]"<<message<<endl;
	writeFile((char*)message);
	free(buffer);
	free(message);
}

stringstream reciveCommad(int &socketToManage){
	stringstream res;
	char* rcvBuffer;
	char* command;
	int commandSize;
	int bytesRecived;
	bytesRecived = server->recvMsg((void**)&rcvBuffer);
	if(bytesRecived == 0){//connessione chiusa dal client
		cout<<"[INFO] Client disconnected."<<endl;
		socketToManage = -1;
		return res;
	}
	if(!msgCreator->DecryptAndCheckSign((unsigned char*)rcvBuffer,bytesRecived,(unsigned char**)&command,commandSize)){
		//errore
		return res;
	}
	cout<<"[DEBUG msg]"<<command<<endl;
	res<<command;
	free((void*)rcvBuffer);
	free((void*)command);
	return res;
}

void manageConnection(int &socketToManage){
	stringstream commandStream;
	string command;
	commandStream = reciveCommad(socketToManage);
	commandStream>>command;
	cout<<"[DEBUG command]'"<<command<<"'"<<endl;
	if(command=="u"){
		string filename;
		size_t fileSize;
		commandStream>>filename>>fileSize;
		cout<<"[DEBUG filename]"<<filename<<endl;
		cout<<"[DEBUG filesize]"<<fileSize<<endl;
		uploadCommand(filename,fileSize);
	}
	if(command=="rl"){
		//retriveListCommand();
	}
	if(command=="rf"){
		//retriveFileCommand();
	}
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
		cout<<"[INFO] Wainting for the client."<<endl;
		activeSocket = server->acceptNewConnecction(); //se è una nuova connessione l'accetta e ritorna -1, altrimenti restituisce il socket da gestire
		if(activeSocket>=0){
			cout<<"[INFO] New client connected."<<endl;
		}
		while(activeSocket>=0){
			manageConnection(activeSocket);
		}
	}	
return 0;
}
