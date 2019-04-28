#include "SecureMessageCreator.h"
#include "ClientTCP.h"
#include <iostream>
#include <fstream>
#include <sstream>
using namespace std;

ClientTCP *client;
SecureMessageCreator *msgCreator;

void uploadApart(const char* buffer, const size_t buffSize)
{
    unsigned char *secureMessage;
    size_t msgSize = msgCreator->EncryptAndSignMessage((unsigned char*)buffer, buffSize , &secureMessage);
    client->sendMsg(secureMessage, msgSize);
    free(secureMessage);
}

void sendUploadCommand(string file, size_t fileSize)
{
    unsigned char *secureMessage;
    stringstream ss;
    ss << "u " << file << " " << fileSize;
    string msg = ss.str();
    size_t msgSize = msgCreator->EncryptAndSignMessage((unsigned char *)msg.c_str(), msg.length(), &secureMessage);
    client->sendMsg(secureMessage, msgSize);
}

void sendFile(ifstream &readFile)
{
    string reader;
    int fileSize =  readFile.tellg();;
    readFile.seekg(0, ios::beg);
    size_t buffSize = 1024;
    char* buffer = new char[buffSize];

    size_t whenPrintCharacter = fileSize / 80;
    size_t partReaded = 0;
    size_t fileSended = 0;

    size_t pos = 0;
    if (readFile.is_open())
    {

        while (!readFile.eof())
        {
            readFile.read(buffer,buffSize);
            size_t readedBytes = readFile.gcount();
            uploadApart(buffer,readedBytes);
            
            //the following code prints * characters
            partReaded += readedBytes;
            fileSended += readedBytes;
            if (whenPrintCharacter > 0 && partReaded >= whenPrintCharacter)
            {
                for (int i = 0; i < partReaded / whenPrintCharacter; i++)
                    cout << "*" << flush;
                partReaded = partReaded % whenPrintCharacter;
                sleep(1);
            }
            // *** :P :o 8====D {()} ***
        }
        cout << endl;
    }

    readFile.close();
}

void uploadCommand(string argument)
{
    cout<<"[DEBUG] entering uppload command"<<endl;
    string reader;
    ifstream readFile;
    const char *fileName = argument.c_str();
    long fileSize;
    cout<<"[DEBUG] opening file"<<endl;
    readFile.open(fileName, ios::in | ios::binary | ios::ate);
    if (readFile.is_open())
    {
        cout<<"[DEBUG] file open"<<endl;
        fileSize = readFile.tellg();
        if (fileSize <= 0)
        {
            //if 0 file is empty
            //if <0 file doesn't exists
            cout << "[ERROR] file doesn't exist or it's empty" << endl;
            readFile.close();
            return;
        }
    }
    else
    {
        cout << "[ERROR] could not open the file." << endl;
        readFile.close();
        return;
    }
    cout<<"[DEBUG] sending command"<<endl;
    sendUploadCommand(argument, fileSize);
    cout<<"[DEBUG] command sended"<<endl;
    sendFile(readFile);
}

void retriveListCommand()
{
    cout << "Called 'Retrive-List', not implemented yet :(" << endl
         << endl;
    //client->sendMsg("rl","rl".length());
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
    client->closeConnection();
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

    msgCreator = new SecureMessageCreator();
    client = new ClientTCP(args[1], atoi(args[2]));
    /*FINE LETTURA PARAMETRI*/
    if (!client->serverTCPconnection())
    {

        exit(-5);
    }

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
