#include "SecureConnection.h"
#include "ClientTCP.h"
#include <iostream>
#include <fstream>
#include <sstream>
using namespace std;

SecureConnection *_secureConnection;
ClientTCP *_client;

void sendUploadCommand(string file)
{
    string msg = "u " + file;
    _secureConnection->sendSecureMsg((void*)msg.c_str(),msg.length());
}

void sendRetriveListCommand()
{
    string msg = "rl";
    _secureConnection->sendSecureMsg((void*)msg.c_str(),msg.length());
}

void uploadCommand(string argument)
{
    cout << "[DEBUG] entering uppload command" << endl;
    
    sendUploadCommand(argument);
    cout << "[DEBUG] command sended" << endl;
    
    int ret = _secureConnection->sendFile(argument.c_str(), true);
    if(ret == 0){
        cout<<"[ERROR] server sended an empty file"<<endl;
    }
    if(ret < 0 ){
        cout<<"[ERROR] uploading the file"<<endl;
    }
}

void retriveListCommand()
{
    cout << "Called 'Retrive-List'" << endl;
    sendRetriveListCommand();
}

void retriveFileCommand()
{
    cout << "Called 'Retrive-File', not implemented yet :(" << endl
         << endl;
}

void helpCommand()
{
    cout << "  - [u | upload] <filename>: upload <filename> to the server" << endl;
    cout << "  - [rl | retrive-list]: retrive the list of files available from the server." << endl;
    cout << "  - [rf | retrive-file] <filename>: per ricevere un file dal server digitare" << endl;
    cout << "  - [quit | exit | q]: for closing the program" << endl;
    cout << " ------------------------------------------------------------" << endl
         << endl;
}

void quitCommand()
{
    _client->closeConnection();
    cout << "Closing program... Bye bye :)" << endl
         << endl;
}

int main(int num_args, char *args[])
{
    // 0 comando
    // 1 parametro indirizzo ip;
    // 2 parametro numero di porta;
    // 3 nome file da trasferire;

    /*LETTURA PARAMETRI*/
    if (num_args != 3)
    {
        cout << "ERROR: Number of parameters are not valid." << endl;
        cout << "Usage: " << args[0] << " <_ipServer> <SERVER_PORT_#>" << endl;
        cout << "Closing program..." << endl
             << endl;
        return -1;
    }

    string ipServer = args[1];
    unsigned short portNumber = atoi(args[2]);
    // end parameter read

    _client = new ClientTCP(ipServer.c_str(), portNumber);

    if (!_client->serverTCPconnection())
    {
        cout<<endl<<"ERROR connect(): Failed connect to the server."<<endl;
        exit(-5);
    }
    cout<<"Successfull connected to the server "<<ipServer<<" (PORT: "<<portNumber<<")"<<endl;

    _secureConnection = new SecureConnection(_client);

    string input;
    string command;
    string argument;
    size_t pos = 0;

    bool exit = false;
    cout << "Insert the command (digit 'help' or 'h' for the command list):" << endl;
    for (;;)
    {

        cout << "$> ";
        cin >> command;
        cout << endl;

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
            retriveFileCommand();
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
    }

    return 0;
}
