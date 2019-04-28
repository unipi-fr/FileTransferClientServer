#include "SecureConnection.h"

SecureConnection::SecureConnection(IClientServerTCP *csTCP)
{
    _csTCP = csTCP;
    _sMsgCreator = new SecureMessageCreator();
}

void SecureConnection::sendSecureMsg(void *buffer, size_t bufferSize)
{
    unsigned char *secureMessage;
    size_t msgSize = msgCreator->EncryptAndSignMessage((unsigned char *)buffer, buffSize, &secureMessage);
    client->sendMsg(secureMessage, msgSize);
    free(secureMessage);
}

int SecureConnection::recvSecureMsg(void **plainText)
{
    int numberOfBytes;
    unsigned char *encryptedText;
    numberOfBytes = server->recvMsg((void **)&encryptedText);

    if (numberOfBytes == 0)
    {
        return -1;
    }

    int plainTextSize;
    //cout<<"[secureplainText]"<<encryptedText<<endl;
    bool check = msgCreator->DecryptAndCheckSign(encryptedText, numberOfBytes, (unsigned char **)plainText, plainTextSize);

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

void sendUploadCommand(string file, size_t fileSize)
{
    unsigned char *secureMessage;
    stringstream ss;
    ss << "u " << file << " " << fileSize;
    string msg = ss.str();
    size_t msgSize = msgCreator->EncryptAndSignMessage((unsigned char *)msg.c_str(), msg.length(), &secureMessage);
    client->sendMsg(secureMessage, msgSize);
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
    sendSecureMsg(strFileSize.c_str(), strFileSize.length());

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
                sleep(1);
            }
            cout << endl;
            // *** :P :o 8====D {()} ***
        }
    }

    readFile.close();
}

int SecureConnection::receiveFile(const char *filename)
{
    ofstream writeFile;
    char *writer;
    int lenght;
    int lenght = recvSecureMsg((void **)&writer);

    if (lenght < 0)
    {
        cout << "[DEBUG] errore recv FileSize" << endl;
        return -1;
    }

    size_t fileSize;
    string str = string(writer);
    fileSize = str.strtoull();
    free(writer);

    writeFile.open(fileName, ios::binary);
    if (!writeFile.is_open())
    {
        //TODO: errore aprire il file
        cout << "[ERROR|upload] could not open the file" << endl;
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