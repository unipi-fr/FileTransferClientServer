#include "SecureConnection.h"
#include <iostream>
#include <string>
#include <fstream>
#include <sstream>
using namespace std;

SecureConnection::SecureConnection(IClientServerTCP *csTCP)
{
    _csTCP = csTCP;
    _sMsgCreator = new SecureMessageCreator();
}

void SecureConnection::sendSecureMsg(void *buffer, size_t bufferSize)
{
    unsigned char *secureMessage;
    size_t msgSize = _sMsgCreator->EncryptAndSignMessage((unsigned char *)buffer, bufferSize, &secureMessage);
    _csTCP->sendMsg(secureMessage, msgSize);
    free(secureMessage);
}

int SecureConnection::recvSecureMsg(void **plainText)
{
    int numberOfBytes;
    unsigned char *encryptedText;
    numberOfBytes = _csTCP->recvMsg((void **)&encryptedText);

    if (numberOfBytes == 0)
    {
        return 0;
    }

    int plainTextSize;
    //cout<<"[secureplainText]"<<encryptedText<<endl;
    bool check = _sMsgCreator->DecryptAndCheckSign(encryptedText, numberOfBytes, (unsigned char **)plainText, plainTextSize);

    //cout<<"[plainText]"<<(*plainText)<<endl;
    if (!check)
    {
        cout << "[ERROR] not valid Hash" << endl;
        return -1;
    }
    //cout<<"[INFO] hash OK!"<<endl;

    free(encryptedText);

    return plainTextSize;
}

int SecureConnection::sendFile(const char *filename, bool stars)
{
    ifstream readFile;
    readFile.open(filename, ios::in | ios::binary | ios::ate);
    if (!readFile.is_open())
    {
        //error open
        cout << "[DEBUG] Error open file";
        return -1;
    }

    // obtain and send file size
    int fileSize = readFile.tellg();
    if (fileSize == 0)
    {
        cout << "[DEBUG] attempt to send an Empty file" << endl;
        return 0;
    }
    string strFileSize = to_string(fileSize);
    sendSecureMsg((void*)strFileSize.c_str(), strFileSize.length());

    readFile.seekg(0, ios::beg);
    size_t buffSize = 1024;
    char *buffer = new char[buffSize];

    size_t whenPrintCharacter = fileSize / 80;
    size_t partReaded = 0;
    size_t fileSended = 0;

    while (!readFile.eof())
    {
        readFile.read(buffer, buffSize);
        size_t readedBytes = readFile.gcount();
        sendSecureMsg(buffer, readedBytes);

        //the following code prints * characters
        if (stars)
        {
            partReaded += readedBytes;
            fileSended += readedBytes;
            if (whenPrintCharacter > 0 && partReaded >= whenPrintCharacter)
            {
                for (int i = 0; i < partReaded / whenPrintCharacter; i++)
                    cout << "*" << flush;
                partReaded = partReaded % whenPrintCharacter;
            }
            // *** :P :o 8====D {()} ***
        }
    }
    if(stars)
        cout << endl;

    readFile.close();
    return fileSended;
}

int SecureConnection::receiveFile(const char *filename)
{
    ofstream writeFile;
    char *writer;
    int lenght;
    lenght = recvSecureMsg((void **)&writer);

    if (lenght < 0)
    {
        cout << "[DEBUG] errore recv FileSize" << endl;
        return -1;
    }

    size_t fileSize;
    stringstream ss;
    ss << writer;
    ss>>fileSize;
    cout<<"[DEBUG] fileSize="<<writer<<" converted="<<fileSize<<endl;
    free(writer);

    writeFile.open(filename, ios::binary);
    if (!writeFile.is_open())
    {
        //TODO: errore aprire il file
        cout << "[ERROR|reciveFile] could not open the file" << endl;
        return -1;
    }

    size_t writedBytes;
    for (writedBytes = 0; writedBytes < fileSize; writedBytes += lenght)
    {
        cout << "[DEBUG] writedBites = " << writedBytes << endl;
        lenght = recvSecureMsg((void **)&writer);
        if (lenght < 0)
        {
            cout << "[ERROR] Could not receive a part of the file ---> Client will be disconnected." << endl;
            return -1;
        }
        writeFile.write(writer, lenght);
        free(writer);
    }
    cout << "[DEBUG] writedBites = " << writedBytes << endl;

    return writedBytes;
}