#include "SecureplainTextCreator.h"
#include "ServerTCP.h"
#include <iostream>
#include <fstream>
#include <sstream>

using namespace std;

ServerTCP* server;
int activeSocket;
SecureplainTextCreator* msgCreator;

int receiveApart(unsigned char** plainText){
	int numberOfBytes;
	unsigned char* encryptedText;
	numberOfBytes = server->recvMsg((void**) &encryptedText);

	if(numberOfBytes == 0){
		return -1;
	}

	int plainTextSize;
	cout<<"[secureplainText]"<<encryptedText<<endl;
	bool check = msgCreator->DecryptAndCheckSign(encryptedText, numberOfBytes, plainText, plainTextSize);
	
	cout<<"[plainText]"<<plainText<<endl;
	if (!check)
	{
		cout<<"[ERROR] not valid Hash"<<endl;
		return -1;
	}
	cout<<"[INFO] hash OK!"<<endl;

	free(encryptedText);

	return plainTextSize;
}

void uploadCommand(string fileName,size_t fileSize){
	cout<<"[DEBUG] upload command called succefull with filename="<<fileName<<" and fileSize="<<fileSize<<endl;
	//return;
	ofstream writeFile;
	unsigned char* writer;
	int lenght;
	writeFile.open(fileName.c_str(), ios::in|ios::binary);

	if (!writeFile.is_open()) {
		//TODO: errore aprire il file
	}
	
	for(sizte_t writedBytes = 0; writedBytes < fileSize;){
		lenght = receiveApart(&writer);
		if(lenght <0){
			break;
		}
		writeFile.write(writer, lenght);
		free(writer);
	}
	
	if(lenght <0){
		cout<<"[ERROR] Could not receive a part of the file ---> Client will be disconnected."<<endl;
		server->forceClientDisconnection();
	}

}

stringstream reciveCommad(){
	stringstream res;
	char* rcvEncryptedPlainText;
	char* command;
	int commandSize;
	int bytesRecived;
	bytesRecived = server->recvMsg((void**)&rcvEncryptedPlainText);
	if(bytesRecived == 0){//connessione chiusa dal client
		cout<<"[INFO] Client disconnected."<<endl;
		socketToManage = -1;
		return res;
	}
	if(!msgCreator->DecryptAndCheckSign((unsigned char*)rcvEncryptedPlainText,bytesRecived,(unsigned char**) &command,commandSize)){
		//errore
		return res;
	}
	cout<<"[DEBUG msg]"<<command<<endl;
	res<<command;
	free((void*)rcvEncryptedPlainText);
	free((void*)command);
	return res;
}

void manageConnection(){
	stringstream commandStream;
	string command;
	commandStream = reciveCommad();
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
	msgCreator = new SecureplainTextCreator();
	activeSocket = -1;
	for(;;){
		cout<<"[INFO] Wainting for the client."<<endl;
		activeSocket = server->acceptNewConnecction();
		if(activeSocket>=0){
			cout<<"[INFO] New client connected."<<endl;
		}
		while(activeSocket>=0){
			manageConnection();
		}
	}	
return 0;
}
