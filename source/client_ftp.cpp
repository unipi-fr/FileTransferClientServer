#include "SecureConnection.h"
#include "ClientTCP.h"
#include "Sanitizator.h"
#include "Printer.h"
#include <limits.h>
#include <string.h>
#include <iostream>
#include <sstream>
using namespace std;

SecureConnection *_secureConnection;
ClientTCP *_client;

unsigned long sendUploadCommand(string file)
{
    unsigned long nonce;
    unsigned char* nonceBuf;

    string msg = "u";
    _secureConnection->sendSecureMsg((void *)msg.c_str(), msg.length() + 1, false, 0);

    _secureConnection->recvSecureMsg((void **) &nonceBuf, false, 0);
    memcpy(&nonce, nonceBuf, sizeof(unsigned long));
    delete nonceBuf;

    _secureConnection->sendSecureMsg((void *)file.c_str(), file.length() + 1, true, nonce);
    
    return nonce;
}

unsigned long sendRetriveListCommand()
{
    unsigned long nonce;
    unsigned char* nonceBuf;
    
    string msg = "rl";
    _secureConnection->sendSecureMsg((void *)msg.c_str(), msg.length() + 1, false, 0);

    _secureConnection->recvSecureMsg((void **) &nonceBuf, false, 0);
    memcpy(&nonce, nonceBuf, sizeof(unsigned long));
    delete nonceBuf;

    _secureConnection->sendSecureMsg((void*) &nonce, sizeof(unsigned long), true, nonce);

    return nonce;
}

unsigned long sendRetriveFileCommand(string file)
{
    unsigned long nonce;
    unsigned char* nonceBuf;

    string msg = "rf ";
    _secureConnection->sendSecureMsg((void *)msg.c_str(), msg.length() + 1, false, 0);

    _secureConnection->recvSecureMsg((void **) &nonceBuf, false, 0);
    memcpy(&nonce, nonceBuf, sizeof(unsigned long));
    delete nonceBuf;
    
    _secureConnection->sendSecureMsg((void *)file.c_str(), file.length() + 1, true, nonce);

    return nonce;
}

void uploadCommand(string filename) //changed argument with filename
{
    ifstream readFile;

    try
    {
        Sanitizator::checkFilename(filename.c_str());
    }
    catch(const exception& e)
    {
        Printer::printError(e.what());
        return;
    }
    

    readFile.open(filename.c_str(), ios::in | ios::binary | ios::ate);
    if (!readFile.is_open())
    {
        Printer::printError("File doesn't exists");
        return;
    }

    unsigned long nonce;

    try
    {
        nonce = sendUploadCommand(filename);
    }
    catch (const NetworkException &e)
    {
        Printer::printError("A network error has occoured sending the command");
        readFile.close();
        return;
    }

    try
    {
        Printer::printNormal("\n");
        _secureConnection->sendFile(readFile, true, nonce);
    }
    catch (const NetworkException &ne)
    {
        Printer::printError("A network error has occoured sending the file");
    }
    catch(const FileSizeException &fse){
        Printer::printError(fse.what());
    }

    readFile.close();
}

void retriveListCommand()
{
    unsigned long nonce;

    try
    {
        nonce = sendRetriveListCommand();
    }
    catch (const NetworkException &e)
    {
        Printer::printError("A network error has occoured sending the command");
        return;
    }

    try
    {
        Printer::printNormal("\n");
        _secureConnection->reciveAndPrintBigMessage(nonce);
    }
    catch (const FileSizeException &fse){
		Printer::printError(fse.what());
	}
    catch (const NetworkException &ne)
    {
        Printer::printError("A network error has occoured downloading the message");
    }
}

void retriveFileCommand(string filename)
{
    unsigned long nonce;

    try
    {
        Sanitizator::checkFilename(filename.c_str());
    }
    catch(const exception& e)
    {
        Printer::printError(e.what());
        return;
    }

    try
    {
        nonce = sendRetriveFileCommand(filename);
    }
    catch (const NetworkException &e)
    {
        Printer::printError("A network error has occoured sending the command");
        return;
    }

    system("/bin/mkdir -p tmp");
    string tmpFile = "tmp/tmp.txt";
    string cmd;

    try
    {
        Printer::printNormal("\n");
        _secureConnection->receiveFile(tmpFile.c_str(), true, nonce);
    }
    catch (const FileSizeException &fse){
		Printer::printError(fse.what());
        system("/bin/rm -r tmp");
        return;
	}
    catch (const DisconnectionException &de)
    {
        system("/bin/rm -r tmp");
        throw de;
    }
    catch (const NetworkException &ne)
    {
        Printer::printError("A network error has occoured downloading the file");
        system("/bin/rm -r tmp");
        return;
    }
    catch (const HashNotValidException &hnve)
    {
        system("/bin/rm -r tmp");
        throw hnve;
    }
    catch (const FileDoesNotExistsException &fdnee)
    {
        Printer::printError(fdnee.what());
        system("/bin/rm -r tmp");
        return;
    }

    cmd = "/bin/mv " + tmpFile + " " + filename;
    system(cmd.c_str());
    system("/bin/rm -r tmp");
}

void helpCommand()
{
    Printer::printTag("   u |       upload" , "<filename>: upload <filename> to the server" , CYAN);
    Printer::printTag("  rl | retrive-list" , ": retrive the list of files available from the server." , CYAN);
    Printer::printTag("  rf | retrive-file" , "<filename>: per ricevere un file dal server digitare" , CYAN);
    Printer::printTag("quit |     exit | q" , ": for closing the program" , CYAN);
    Printer::printNormal("\n");
    
}

void quitCommand()
{
    _client->closeConnection();
    Printer::printNormal("Closing program.. \n\n");
}

int main(int num_args, char *args[])
{
    Printer::printNormal("\n");
    Printer::printMsg("--- WELCOME ON SECURE FILE TRANSFER CLIENT ---");
    // 0 comando
    // 1 parametro indirizzo ip;
    // 2 parametro numero di porta;
    // 3 nome file da trasferire;

    /*LETTURA PARAMETRI*/
    if (num_args != 3)
    {
        Printer::printError("Number of parameters are not valid.");
        Printer::printNormal(string("Usage: " + string(args[0]) + " <ipServer> <SERVER_PORT_#>").c_str());
        Printer::printNormal("Closing program...\n\n");
        return -1;
    }
    string ipServer;
    unsigned short portNumber;
    try
    {
        ipServer = Sanitizator::checkIpAddress(args[1]);
        portNumber = Sanitizator::checkPortNumber(args[2]);
    }
    catch(const exception& e)
    {
        Printer::printError(e.what());
        return -1;
    }
    // end parameter read

    _client = new ClientTCP(ipServer.c_str(), portNumber);

    if (!_client->serverTCPconnection())
    {
        Printer::printError("connect(): Failed connect to the server.");
        return -1;
    }
    
    stringstream mess;
    mess << "Successfull connected to the server " << ipServer  << " (PORT: " << portNumber << ")";
    Printer::printMsg(mess.str().c_str())  ;

    _secureConnection = new SecureConnection(_client);

    try
    {
        Printer::printInfo((char*)"Establishing secure connection with the server");
        _secureConnection->establishConnectionClient();
    }
    catch (const std::exception &e)
    {
        Printer::printErrorWithReason("Secure connection with server failed:",e.what());
        return -1;
    }
    Printer::printMsg("Secure connection established\n");

    string command;
    string argument;
    string garb;

    size_t pos = 0;

    bool exit = false;
    Printer::printNormal("Insert the command (digit 'help' or 'h' for the command list):\n");
    try
    {
        for (;;)
        {
            Printer::printPrompt("$>");
            cin >> command;
            
            if (command == "u" || command == "upload")
            {
                cin >> argument;
                uploadCommand(argument);
            }
            if (command == "rl" || command == "retrive-list")
            {
                retriveListCommand();
            }
            if (command == "rf" || command == "retrive-file")
            {
                cin >> argument;
                retriveFileCommand(argument);
            }
            if (command == "h" || command == "help")
            {
                helpCommand();
            }
            if (command == "q" || command == "quit" || command == "exit")
            {
                quitCommand();
                break;
            }
            getline(cin, garb);
        }
    }
    catch (const DisconnectionException &de)
    {
        Printer::printError("Server disconnected.");
        
    }
    catch (const HashNotValidException &hnve)
    {
        Printer::printError("Failed to download a part of the message (Hash was not valid)");
        _client->closeConnection();
    }
    catch (const exception &e)
    {
        Printer::printErrorWithReason("An Unexpected exceptions occours:",e.what());
        Printer::printNormal("Closing program...\n\n");
    }

    return 0;
}