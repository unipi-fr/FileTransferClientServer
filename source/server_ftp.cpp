#include "SecureConnection.h"
#include "ServerTCP.h"
#include <iostream>
#include <fstream>
#include <sstream>

using namespace std;

SecureConnection *_secureConnection;
ServerTCP *_server;
int _activeSocket;

void disconnectClient()
{
	_server->forceClientDisconnection();
	_activeSocket = -1;
	cout << "[INFO] Client Disconnected" << endl;
}

void uploadCommand(string fileName)
{
	string cmd;
	system("mkdir -p uploadedFiles");
	string tmpFile  = "tmp.txt";

	try
	{
		_secureConnection->receiveFile(tmpFile.c_str(), true);
	}
	catch (const NetworkException &ne)
	{
		cerr << "[ERROR] A network error has occoured downloading the file" << endl;
		cmd = "rm " + tmpFile;
		system(cmd.c_str());
		disconnectClient();
		return;
	}
	catch (const HashNotValidException &hnve)
	{
		cerr << "[ERROR] Failed to download a part of the file (Hash was not valid)" << endl;
		cmd = "rm " + tmpFile;
		system(cmd.c_str());
		disconnectClient();
		return;
	}

	cmd = "mv " + tmpFile + " uploadedFiles/" + fileName;
	system(cmd.c_str());
}

void retriveListCommand()
{
	cout << "[INFO] creating list" << endl;
	//system("stat -c "%n |  %s Bytes" uploadedFiles/*  | awk -F/ '{print $NF}'");
	system("ls -s -h -1 uploadedFiles/ > fileList.txt");

	ifstream readFile;

	readFile.open("fileList.txt", ios::in | ios::binary);
	if (!readFile.is_open())
	{
		cerr << "[ERROR] could not open the file." << endl;
		readFile.close();
		return;
	}

	cout << "[DEBUG] file open" << endl;

	cout << "[DEBUG] sending fileList.txt" << endl;
	try
	{
		_secureConnection->sendFile(readFile, false);
	}
	catch (const NetworkException &ne)
	{
		cerr << "[ERROR] A network error has occoured sending the dile list" << endl;
		disconnectClient();
	}/*
	catch (const ErrorOnOtherPartException &eope)
	{
		cerr << "[ERROR] Failed to upload a part of the file list (Hash was not valid)" << endl;
		disconnectClient();
	}*/
	catch(const SecureConnectionException &sce){
		cerr<<"[ERROR] "<<sce.what()<<endl;
		disconnectClient();
	}

	system("rm fileList.txt");

	cout << "[INFO] fileList sended" << endl;
}

void retriveFileCommand(string fileName)
{
	string pathFileName = "uploadedFiles/" + fileName;
	cout<<"[DEBUGpathfileRF]"<<pathFileName<<endl;
	ifstream readFile;
	readFile.open(pathFileName.c_str(), ios::in | ios::binary);
	if (!readFile.is_open())
	{
		//TODO: avvisare il clien che il file non esiste
		cerr << "[ERROR] not possible open the file." << endl;
		return;
	}

	try
	{
		_secureConnection->sendFile(readFile, false);
	}
	catch (const NetworkException &ne)
	{
		cerr << "[ERROR] A network error has occoured sending the file" << endl;
		disconnectClient();
	}
	catch (const ErrorOnOtherPartException &eope)
	{
		cerr << "[ERROR] Failed to upload a part of the file (Hash was not valid)" << endl;
		disconnectClient();
	}

	readFile.close();
}

stringstream receiveCommad()
{
	stringstream res;
	char *command;
	int bytesRecived;

	bytesRecived = _secureConnection->recvSecureMsg((void **)&command);

	//cout << "[DEBUG msg]" << command << endl;
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
	try
	{
		commandStream = receiveCommad();
	}
	catch (const NetworkException &ne)
	{
		cerr << "[ERROR] A network error has occoured receiving the command" << endl;
		disconnectClient();
		return;
	}catch(const SecureConnectionException &se){
		cerr<<"[ERROR] "<<se.what()<<endl;
		disconnectClient();
		return;
	}

	commandStream >> command;
	cout << "[DEBUG command] '" << command << "'" << endl;

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
	srand(time(NULL));
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
		cout << "[INFO] Wainting for a connection." << endl;
		_activeSocket = _server->acceptNewConnecction();
		try
		{
			//_secureConnection->establishConnectionServer();
		}
		catch(const exception& e)
		{
			cerr << e.what() << '\n';
			continue;
		}
		
		if (_activeSocket >= 0)
		{
			cout << "[INFO] New client connected." << endl;
		}

		while (_activeSocket >= 0)
		{
			try
			{
				manageConnection();
			}
			catch (const DisconnectionException &de)
			{
				_activeSocket = -1;
				cout << "[INFO] Client Disconnected" << endl;
			}
			catch (const exception &e)
			{
				cout << "[ERROR] An Unexpected exceptions occours:" << endl;
				cerr << e.what() << endl;

				disconnectClient();				
			}
		}
	}
	return 0;
}
