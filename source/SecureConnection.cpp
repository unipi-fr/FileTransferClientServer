#include "SecureConnection.h"
#include <string>
#include <sstream>
#include <unistd.h>
#include <string.h>
using namespace std;

SecureConnection::SecureConnection(IClientServerTCP *csTCP)
{
    _csTCP = csTCP;
    _sMsgCreator = new SecureMessageCreator();
}

void SecureConnection::sendSecureMsg(void *buffer, size_t bufferSize)
{
    unsigned char *secureMessage;
    //cout<<"[DEBUGsendMSG]"<<(char*)buffer<<endl;
    size_t msgSize = _sMsgCreator->EncryptAndSignMessage((unsigned char *)buffer, bufferSize, &secureMessage);
    _csTCP->sendMsg(secureMessage, msgSize);
    free(secureMessage);
}

void SecureConnection::sendSecureMsgWithAck(void *buffer, size_t bufferSize)
{
    sendSecureMsg(buffer, bufferSize);

    char *ack;
    recvSecureMsg((void **)&ack);
    string ackStr = ack;
    free(ack);
    if(ackStr != "OK"){
        throw ErrorOnOtherPartException();
    }
}

int SecureConnection::recvSecureMsg(void **plainText)
{
    int numberOfBytes;
    unsigned char *encryptedText;
    numberOfBytes = _csTCP->recvMsg((void **)&encryptedText);

    int plainTextSize;
    //cout<<"[secureplainText]"<<encryptedText<<endl;
    bool check = _sMsgCreator->DecryptAndCheckSign(encryptedText, numberOfBytes, (unsigned char **)plainText, plainTextSize);

    free(encryptedText);

    //cout<<"[plainText]"<<(*plainText)<<endl;
    if (!check)
    {
        throw HashNotValidException();
    }
    //cout<<"[INFO] hash OK!"<<endl;

    return plainTextSize;
}

int SecureConnection::recvSecureMsgWithAck(void **plainText)
{
    int ret;
    try
    {
        ret = recvSecureMsg(plainText);
    }
    catch (const HashNotValidException &hnve)
    {
        sendSecureMsg((void *)"ERROR Hash is not valid", 24);
        throw hnve;
    }

    sendSecureMsg((void *)"OK", 3);
    return ret;
}

int SecureConnection::sendFile(ifstream &file, bool stars)
{
    if (!file.is_open())
    {
        throw FileNotOpenException();
    }

    // obtain and send file size
    file.seekg(0, ios::end);
    int fileSize = file.tellg();
    if (fileSize == 0)
    {
        cout << "[INFO] attempt to send an Empty file" << endl;
    }
    string strFileSize = to_string(fileSize);
    sendSecureMsg((void *)strFileSize.c_str(), strFileSize.length());

    file.seekg(0, ios::beg);
    char buffer[BUFF_SIZE];

    size_t whenPrintCharacter = fileSize / 80;
    size_t partReaded = 0;
    size_t fileSended = 0;

    cout << "[INFO] fileSize=" << fileSize << endl;
    if (fileSize == 0)
    {
        return fileSended;
    }

    while (!file.eof() && fileSended < fileSize)
    {
        memset(buffer, 0, BUFF_SIZE);
        file.read(buffer, BUFF_SIZE);
        size_t readedBytes = file.gcount();


        //sendSecureMsgWithAck(buffer, readedBytes);
        sendSecureMsg(buffer, readedBytes);

        fileSended += readedBytes;
        cout << "[INFO] fileSended = " << fileSended << endl;
        //the following code prints * characters
        /*if (stars)
        {
            partReaded += readedBytes;
            
            if (whenPrintCharacter > 0 && partReaded >= whenPrintCharacter)
            {
                for (int i = 0; i < partReaded / whenPrintCharacter; i++)
                    cout << "*" << flush;
                partReaded = partReaded % whenPrintCharacter;
            }
            // *** :P :o 8====D {()} ***
        }*/
        //sleep(1);
    }
    /*
    if (stars)
        cout << endl;*/

    return fileSended;
}

int SecureConnection::receiveFile(const char *filename)
{
    ofstream writeFile;

    char *writer;
    int lenght;

    lenght = recvSecureMsg((void **)&writer);

    size_t fileSize;
    stringstream ss;
    ss << writer;
    ss >> fileSize;
    free(writer);

    cout << "[INFO] fileSize=" << fileSize << endl;

    writeFile.open(filename, ios::binary);
    if (!writeFile.is_open())
    {
        throw FileNotOpenException();
    }

    size_t writedBytes;
    for (writedBytes = 0; writedBytes < fileSize; writedBytes += lenght)
    {
        //lenght = recvSecureMsgWithAck((void **)&writer);
        lenght = recvSecureMsg((void **)&writer);

        cout << "[DEBUG] writedBites = " << writedBytes + lenght << endl;

        writeFile.write(writer, lenght);
        free(writer);
    }

    writeFile.close();

    return writedBytes;
}

int SecureConnection::reciveAndPrintBigMessage()
{
    char *writer;
    char *ack;
    int lenght;
    
    lenght = recvSecureMsg((void **)&writer);

    size_t fileSize;
    stringstream ss;
    ss << writer;
    ss >> fileSize;
    free(writer);
    
    cout << "[INFO] fileSize = "<<fileSize << endl;
    

    size_t writedBytes;
    for (writedBytes = 0; writedBytes < fileSize; writedBytes += lenght)
    {
        //lenght = recvSecureMsgWithAck((void **)&writer);
        lenght = recvSecureMsg((void **)&writer);
        
        cout << writer;
        free(writer);
    }
    cout << endl;

    cout << "[DEBUG] writedBites = " << writedBytes << endl;
    
    return writedBytes;
}