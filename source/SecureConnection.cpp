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

int SecureConnection::sendFile(ifstream &file, bool stars)
{
    if (!file.is_open())
    {
        cout << "[ERROR|sendFile] file is not open" << endl;
        return -2;
    }
    file.seekg(0, ios::end);
    // obtain and send file size
    int fileSize = file.tellg();
    if (fileSize == 0)
    {
        cout << "[INFO] attempt to send an Empty file" << endl;
        //return 0;
    }
    string strFileSize = to_string(fileSize);
    sendSecureMsg((void *)strFileSize.c_str(), strFileSize.length());

    file.seekg(0, ios::beg);
    char buffer[BUFF_SIZE];
    char* ack;

    size_t whenPrintCharacter = fileSize / 80;
    size_t partReaded = 0;
    size_t fileSended = 0;

    cout << "[DEBUG] fileSize="<< fileSize << endl;
    if(fileSize == 0){
        return fileSended;
    }
    while (!file.eof() && fileSended<fileSize)
    {
        memset(buffer,0,BUFF_SIZE);
        file.read(buffer, BUFF_SIZE);
        size_t readedBytes = file.gcount();
        sendSecureMsg(buffer, readedBytes);
        int ret =  recvSecureMsg((void**) &ack);
        //cout<<"[DEBUGsendfile-ack - ret]"<<ack<<" - "<<ret<<endl;
        if(ret == 0){
            //server/client disconnected
            cout<<"[INFO] server/client disconnected."<<endl;
            free(ack);
            return -1;
        }
        if(ret < 0){
            //Error RCV
            cerr<<"[ERROR] recive secure message falied."<<endl;
            free(ack);
            return -2;
        }
        
        string ackStr = string(ack);
        if(ackStr != "OK"){
            cerr<<"[ERROR] Error sending file part."<<endl;
            free(ack);
            return -3;
        }
        free(ack);
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

    if (lenght < 0)
    {
        cout << "[DEBUG] errore recv FileSize" << endl;
        return -1;
    }

    size_t fileSize;
    stringstream ss;
    ss << writer;
    ss >> fileSize;
    cout << "[DEBUG] fileSize=" << writer << " converted=" << fileSize << endl;
    free(writer);

    writeFile.open(filename, ios::binary);
    if (!writeFile.is_open())
    {
        //TODO: errore aprire il file
        cerr << "[ERROR|reciveFile] could not open the file" << endl;
        writeFile.close();
        return -2;
    }

    size_t writedBytes;
    for (writedBytes = 0; writedBytes < fileSize; writedBytes += lenght)
    {
        lenght = recvSecureMsg((void **)&writer);
        if(lenght == 0){
            //server/client disconnected
            cout<<"[INFO] server/client disconnected."<<endl;
            return -1;
        }
        cout << "[DEBUG] writedBites = " << writedBytes+lenght << endl;
        if (lenght < 0)
        {
            cerr << "[ERROR] Could not receive a part of the file." << endl;
            writeFile.close();
            cout<<"[DEBUGrecvFile] sending ERROR"<<endl;
            sendSecureMsg((void*)"ERROR Hash not valid",21);   
            return -2;
        }else{
            cout<<"[DEBUGrecvFile] sending OK"<<endl;
            sendSecureMsg((void*)"OK",3);
            
        }
        writeFile.write(writer, lenght);
        free(writer);
        
    }
    writeFile.close();
    return writedBytes;
}

int SecureConnection::reciveAndPrintBigMessage()
{
    char *writer;
    char* ack;
    int lenght;
    lenght = recvSecureMsg((void **)&writer);

    if (lenght < 0)
    {
        cerr << "[ERROR] errore recv message size" << endl;
        return -1;
    }

    size_t fileSize;
    stringstream ss;
    ss << writer;
    ss >> fileSize;
    cout << "[DEBUG] fileSize=" << writer << " converted=" << fileSize << endl;
    free(writer);

    size_t writedBytes;
    for (writedBytes = 0; writedBytes < fileSize; writedBytes += lenght)
    {
        lenght = recvSecureMsg((void **)&writer);
        if (lenght == 0)
        {
            cout << "[INFO] client/server disconnected." << endl;
            return 0;
        }
        if (lenght < 0)
        {
            cerr << "[ERROR] Could not receive a part of the message." << endl;
            sendSecureMsg((void*)"ERROR Hash not valid",21);
            return -2;
        }else{
            sendSecureMsg((void*)"OK",3);
        }
        
        cout<<writer;
        free(writer);
    }
    cout<<endl;
    
    cout << "[DEBUG] writedBites = " << writedBytes << endl;
    return writedBytes;
}