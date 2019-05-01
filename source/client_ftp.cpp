#include "SecureConnection.h"
#include "ClientTCP.h"
#include <limits.h>
using namespace std;

SecureConnection *_secureConnection;
ClientTCP *_client;

void sendUploadCommand(string file)
{
    string msg = "u " + file;
    _secureConnection->sendSecureMsg((void *)msg.c_str(), msg.length());
}

void sendRetriveListCommand()
{
    string msg = "rl";
    _secureConnection->sendSecureMsg((void *)msg.c_str(), msg.length());
}

void sendRetriveFileCommand(string file)
{
    string msg = "rf " + file;
    _secureConnection->sendSecureMsg((void *)msg.c_str(), msg.length());
}

void uploadCommand(string argument)
{
    cout << "[DEBUG] entering uppload command" << endl;

    ifstream readFile;
    readFile.open(argument.c_str(), ios::in | ios::binary | ios::ate);
    if (!readFile.is_open())
    {
        //error open
        cerr << "[ERORR] file doesn't exists"<<endl;
        return;
    }

    sendUploadCommand(argument);
    cout << "[DEBUG] command sended" << endl;

    int ret = _secureConnection->sendFile(readFile, true);
    if (ret == 0)
    {
        cerr << "[ERROR] server sended an empty file" << endl; // ??
    }
    if (ret < 0)
    {
        cerr << "[ERROR] uploading the file" << endl;
    }
}


void retriveListCommand()
{
    cout << "Called 'Retrive-List'" << endl;

    sendRetriveListCommand();
    cout << "[DEBUG] command sended" << endl;
    
    int ret = _secureConnection->reciveAndPrintBigMessage();
    if (ret < 0)
    {
        cerr << "[ERROR] receiving the list of file" << endl;
    }
}

void retriveFileCommand(string filename)
{
    /*cout << "Called 'Retrive-File', not implemented yet :(" << endl
         << endl;*/
    cout << "Called 'Retrive-File'" << endl;

    sendRetriveFileCommand(filename);
    cout << "[DEBUG] command sended" << endl;

    int ret = _secureConnection->receiveFile(filename.c_str());
    if (ret == 0)
    {
        cerr << "[ERROR] server sended an empty file" << endl; // ??
    }
    if (ret < 0)
    {
        cerr << "[ERROR] downloading the file" << endl;
    }
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
        cerr << "[ERROR] Number of parameters are not valid." << endl;
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
        cout << endl
             << "[ERROR] connect(): Failed connect to the server." << endl;
        exit(-5);
    }
    cout << "Successfull connected to the server " << ipServer << " (PORT: " << portNumber << ")" << endl;

    _secureConnection = new SecureConnection(_client);

    string command;
    string argument;
    string garb;
    size_t pos = 0;

    bool exit = false;
    cout << "Insert the command (digit 'help' or 'h' for the command list):" << endl;
    for (;;)
    {

        cout << "$> ";
        cin>>command;
        cout<<"[DEBUG|command]"<<command<<endl;
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
        getline(cin,garb);
    }

    return 0;
}