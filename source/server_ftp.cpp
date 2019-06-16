#include "SecureConnection.h"
#include "Sanitizator.h"
#include "ServerTCP.h"
#include "Printer.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <unistd.h>

using namespace std;

SecureConnection *_secureConnection;
ServerTCP *_server;
int _activeSocket;

void disconnectClient()
{
	_server->forceClientDisconnection();
	_secureConnection->destroyKeys();
	_activeSocket = -1;
	Printer::printInfo((char*)"Client Disconnected");
}

void uploadCommand(string fileName, unsigned long nonce)
{
	try
	{
		Sanitizator::checkFilename(fileName.c_str());
	}
	catch (const exception &e)
	{
		Printer::printError(e.what());
		return;
	}

	string cmd;
	system("/bin/mkdir -p uploadedFiles");
	string tmpFile = "tmp.txt";

	try
	{
		_secureConnection->receiveFile(tmpFile.c_str(), true, nonce);
	}
	catch (const NetworkException &ne)
	{
		Printer::printError((char*)"A network error has occured downloading the file");
		cmd = "/bin/rm " + tmpFile;
		system(cmd.c_str());
		disconnectClient();
		return;
	}
	catch (const HashNotValidException &hnve)
	{
		Printer::printErrorWithReason((char*)"Failed to download a part of the file", (char*)"Hash not valid");
		cmd = "/bin/rm " + tmpFile;
		system(cmd.c_str());
		disconnectClient();
		return;
	}

	cmd = "/bin/mv " + tmpFile + " uploadedFiles/" + fileName;
	system(cmd.c_str());
}

void retriveListCommand(unsigned long nonce)
{
	Printer::printInfo((char*) "Creating List");
	system("/bin/ls -sh1 uploadedFiles/ > fileList.txt");

	ifstream readFile;

	readFile.open("fileList.txt", ios::in | ios::binary);
	if (!readFile.is_open())
	{
		Printer::printError((char*)"Could not open the file");
		readFile.close();
		return;
	}

	try
	{
		_secureConnection->sendFile(readFile, false, nonce);
	}
	catch (const NetworkException &ne)
	{
		Printer::printError((char*)"A network error has occured sending the file list");
		disconnectClient();
	}
	catch (const SecureConnectionException &sce)
	{
		Printer::printError(sce.what());
		disconnectClient();
	}

	system("/bin/rm fileList.txt");

	Printer::printInfo((char*)"FileList sended");
}

void retriveFileCommand(string fileName, unsigned long nonce)
{
	try
	{
		Sanitizator::checkFilename(fileName.c_str());
	}
	catch (const exception &e)
	{
		Printer::printError(e.what());
		return;
	}

	string pathFileName = "uploadedFiles/" + fileName;

	ifstream readFile;
	readFile.open(pathFileName.c_str(), ios::in | ios::binary);
	if (!readFile.is_open())
	{
		Printer::printWaring("not possible open the file or the file demanded doesn't exist");

		// saying to client that file does not exists
		string strFileSize = to_string((long)-1);
		_secureConnection->sendSecureMsg((void *)strFileSize.c_str(), strFileSize.length() + 1, true, nonce);

		return;
	}

	try
	{
		_secureConnection->sendFile(readFile, true, nonce);
	}
	catch (const NetworkException &ne)
	{
		Printer::printError("A network error has occured sendig the file");
		disconnectClient();
	}
	catch (const ErrorOnOtherPartException &eope)
	{
		Printer::printErrorWithReason("Failed to upload a part of the file", "Hash not valid");
		disconnectClient();
	}

	readFile.close();
}

stringstream receiveCommad()
{
	stringstream res;
	char *command;
	int bytesRecived;

	bytesRecived = _secureConnection->recvSecureMsg((void **)&command, false, 0);

	res << command;

	delete command;

	return res;
}

void manageConnection()
{
	stringstream commandStream;
	string command;
	string filename;

	Printer::printInfo("Ready to receive a command");
	try
	{
		commandStream = receiveCommad();
	}
	catch (const NetworkException &ne)
	{
		Printer::printError("A network error has occured reeceiving the command");
		disconnectClient();
		return;
	}
	catch (const SecureConnectionException &se)
	{
		Printer::printError(se.what());
		disconnectClient();
		return;
	}
	
	commandStream >> command;
	stringstream mess;
	mess<<"\n[COMMAND] '"<<command<<"'";
	Printer::printMsg(mess.str().c_str());

	unsigned long nonce = _secureConnection->generateNonce();

	if (command == "u")
	{
		_secureConnection->sendSecureMsg((void*) &nonce, sizeof(unsigned long), false, 0);

		char* filenameBuf;
		_secureConnection->recvSecureMsg((void**) &filenameBuf, true, nonce);
		filename = string(filenameBuf);

		delete filenameBuf;

		uploadCommand(filename, nonce);
	}
	if (command == "rl")
	{
		_secureConnection->sendSecureMsg((void*) &nonce, sizeof(unsigned long), false, 0);

		unsigned char* grb;
		_secureConnection->recvSecureMsg((void**) &grb, true, nonce);
		delete grb;

		retriveListCommand(nonce);
	}
	if (command == "rf")
	{
		_secureConnection->sendSecureMsg((void*) &nonce, sizeof(unsigned long), false, 0);

		char* filenameBuf;
		_secureConnection->recvSecureMsg((void**) &filenameBuf, true, nonce);
		filename = string(filenameBuf);

		delete filenameBuf;
		
		retriveFileCommand(filename, nonce);
	}
}

int main(int num_args, char *args[])
{
	Printer::printNormal("\n");
	Printer::printMsg("--- WELCOME ON SECURE FILE TRANSFER SERVER ---");
	// check parameter
	if (num_args != 2)
	{
		Printer::printError("Number of parameters are not valid.");
        Printer::printNormal(string("Usage: " + string(args[0]) + " <PORT_NUMBER>").c_str());
        Printer::printNormal("Closing program...\n\n");
		return -1;
	}

	unsigned short portNumber;

	try
	{
		portNumber = Sanitizator::checkPortNumber(args[1]);
	}
	catch (const PortNumberException &pne)
	{
		Printer::printError(pne.what());
		Printer::printMsg("Closing program\n");
		return -1;
	}
	// end check param

	_server = new ServerTCP(portNumber);

	stringstream mess;
	mess << "Succesfull listening on port " << portNumber;
	Printer::printMsg(mess.str().c_str());

	_secureConnection = new SecureConnection(_server);

	_activeSocket = -1;
	for (;;)
	{
		Printer::printInfo("Waiting for a connection");
		_activeSocket = _server->acceptNewConnecction();

		try
		{
			Printer::printInfo("Enstablishing secure connection with the client.");
			_secureConnection->establishConnectionServer();
		}
		catch(const CertificateNotValidException &cnve){
			Printer::printErrorWithReason("Failed to establish a secure connection", cnve.what());
			_server->forceClientDisconnection();
			continue;
		}
		catch (const exception &e)
		{
			Printer::printErrorWithReason("Failed to establish a secure connection", e.what());
			continue;
		}
		Printer::printMsg("Secure connection established");

		if (_activeSocket >= 0)
		{
			Printer::printInfo("New client connected");
		}

		while (_activeSocket >= 0)
		{
			try
			{
				manageConnection();
			}catch (const FileSizeException &fse){
				Printer::printError(fse.what());
			}
			catch (const DisconnectionException &de)
			{
				_activeSocket = -1;
				_secureConnection->destroyKeys();
				Printer::printWaring("Client Disconnected");
			}
			catch (const exception &e)
			{
				Printer::printError("A unexpected error has occured");
				Printer::printError(e.what());

				disconnectClient();
			}
		}
	}
	return 0;
}
