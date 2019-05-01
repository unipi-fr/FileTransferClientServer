#include "SecureConnection.h"
#include "ServerTCP.h"
#include <iostream>
#include <fstream>
#include <sstream>

using namespace std;

SecureConnection *_secureConnection;
ServerTCP * _server;
int _activeSocket;


void uploadCommand(string fileName)
{
	system("mkdir -p uploadedFiles");
	string pathFileName = "uploadedFiles/" + fileName;
	int res = _secureConnection->receiveFile(pathFileName.c_str());
	if(res < 0){
		_activeSocket = -1;
		_server->forceClientDisconnection();
	}
}

void retriveListCommand()
{
	cout << "[DEBUG] retrive list command successfull called" << endl;
	cout << "[INFO] creating list" << endl;
	system("stat -c \"%n - %s Bytes\" uploadedFiles/* > fileList.txt");

	cout << "[DEBUG] opening file" << endl;
	ifstream readFile;
	readFile.open("fileList.txt", ios::in | ios::binary);
	if (readFile.is_open())
	{
		cout << "[DEBUG] file open" << endl;
	}
	else
	{
		cerr << "[ERROR] could not open the file." << endl;
		readFile.close();
		return;
	}
	cout << "[DEBUG] sending fileList.txt" << endl;
	int ret = _secureConnection->sendFile(readFile, false);
	if (ret < 0)
    {
        cerr << "[ERROR] sending the list of file" << endl;
    }

	cout << "[DEBUG] fileList.txt sended" << endl;
}

void retriveFileCommand(string fileName) 
{
	string pathFileName = "uploadedFiles/" + fileName;
	ifstream readStream;
	readStream.open(pathFileName.c_str(),ios::in | ios::binary);
	if(!readStream.is_open()){
		//TODO: avvisare il server che il file non esiste
		cerr<<"[ERROR] not possible open the file."<<endl;
		return;
	}
	int res = _secureConnection->sendFile(readStream, false);
	if(res < 0){
		_activeSocket = -1;
		_server->forceClientDisconnection();
	}
}

stringstream receiveCommad()
{
	stringstream res;
	char *command;
	int bytesRecived;
	
	bytesRecived = _secureConnection->recvSecureMsg((void**)&command);
	if(bytesRecived < 0){
		cout << "[ERROR] not possible retrive the command"<< endl;
		return res;
	}
	if(bytesRecived == 0){
		cout << "[INFO] Client isconnected"<< endl;
		_activeSocket = -1;
		return res;
	}	
	cout << "[DEBUG msg]" << command << endl;
	res << command;
	
	free((void *)command);
	
	return res;
}

void manageConnection()
{
	stringstream commandStream;
	string command;
	string filename;

	cout << "[INFO] Ready to receive a command" << endl;
	commandStream = receiveCommad();
	commandStream >> command;
	cout << "[DEBUG command]'" << command << "'" << endl;
	if (command == "u")
	{
		commandStream >> filename;
		//cout<<"[DEBUG filename]"<<filename<<endl;
		//cout<<"[DEBUG filesize]"<<fileSize<<endl;
		uploadCommand(filename);
	}
	if (command == "rl")
	{
		retriveListCommand();
	}
	if (command == "rf")
	{
		commandStream >> filename;
		retriveFileCommand(filename);
	}
}

int main(int num_args, char *args[])
{
	if (num_args != 2)
	{
		printf("\nERRORE: Numero dei parametri non valido.\nUsage: %s <portNumber>\nchiusura programma...\n", args[0]);
		exit(-2);
	}
	unsigned short portNumber = atoi(args[1]);
	
	_server = new ServerTCP(portNumber);
	_secureConnection = new SecureConnection(_server);
	
	_activeSocket = -1;
	for (;;)
	{
		cout << "[INFO] Wainting for the client." << endl;
		_activeSocket = _server->acceptNewConnecction();
		if (_activeSocket >= 0)
		{
			cout << "[INFO] New client connected." << endl;
		}
		while (_activeSocket >= 0)
		{
			manageConnection();
		}
	}
	return 0;
}
