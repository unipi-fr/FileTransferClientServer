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
        cerr << "[ERORR] file doesn't exists" << endl;
        return;
    }
    try
    {
        sendUploadCommand(argument);
    }
    catch (const NetworkException &e)
    {
        cerr << "[ERROR] A network error has occoured sending the command" << endl;
        readFile.close();
        return;
    }

    //cout << "[DEBUG] command sended" << endl;

    try
    {
        _secureConnection->sendFile(readFile, true);
    }
    catch (const NetworkException &ne)
    {
        cerr << "[ERROR] A network error has occoured sending the file" << endl;
    }

    readFile.close();
}

void retriveListCommand()
{
    //cout << "Called 'Retrive-List'" << endl;
    try
    {
        sendRetriveListCommand();
    }
    catch (const NetworkException &e)
    {
        cerr << "[ERROR] A network error has occoured sending the command" << endl;
        return;
    }
    //cout << "[DEBUG] command sended" << endl;
    try
    {
        _secureConnection->reciveAndPrintBigMessage();
    }
    catch (const NetworkException &ne)
    {
        cerr << "[ERROR] A network error has occoured downloading the message" << endl;
    }
}

void retriveFileCommand(string filename)
{
        //cout << "Called 'Retrive-File'" << endl;
    try
    {
        sendRetriveFileCommand(filename);
    }
    catch (const NetworkException &e)
    {
        cerr << "[ERROR] A network error has occoured sending the command" << endl;
        return;
    }
    //cout << "[DEBUG] command sended" << endl;
    system("mkdir -p tmp");
	string tmpFile  = "tmp/tmp.txt";
    string cmd;

    try
    {
        _secureConnection->receiveFile(tmpFile.c_str(), true);
    }
    catch (const DisconnectionException &de)
    {
        system("rm -r tmp");
        throw de;
    }
    catch (const NetworkException &ne)
    {
        cerr << "[ERROR] A network error has occoured downloading the file" << endl;
        system("rm -r tmp");
        return;
    }
    catch (const HashNotValidException &hnve)
    {     
        system("rm -r tmp");
        throw hnve;
    }
    cmd = "mv " + tmpFile+ " " + filename;
	system(cmd.c_str());
    system("rm -r tmp");
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
        cout << "Usage: " << args[0] << " <ipServer> <SERVER_PORT_#>" << endl;
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
    try
    {
        for (;;)
        {
            cout << "$> ";
            cin >> command;
            //cout<<"[DEBUG|command]"<<command<<endl;
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
        cerr << "Server disconnected." << endl;
        cout << "Closing program...  Bye bye :)" << endl;
    }
    catch(const HashNotValidException &hnve){
        cerr << "[ERROR] Failed to download a part of the message (Hash was not valid)" << endl;
        _client->closeConnection();
    }
    catch (const exception &e)
    {
        cout << "[ERROR] An Unexpected exceptions occours:" << endl;
        cerr << e.what() << endl;
        cout << "Closing program...  Bye bye :)" << endl;
    }

    return 0;
}