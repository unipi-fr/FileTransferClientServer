#include "SecureConnection.h"
#include <string>
#include <sstream>
#include <unistd.h>
#include <string.h>
#include <openssl/rand.h>
//#include <stdlib.h> // for random nonce
//#include <time.h>   // for random nonce
#include <iostream>
using namespace std;

SecureConnection::SecureConnection(IClientServerTCP *csTCP)
{
    _csTCP = csTCP;
    _sMsgCreator = new SecureMessageCreator();
}

int SecureConnection::sendCertificate(X509* cert)
{
    unsigned char* buf = NULL;
    
    int size = i2d_X509(cert, &buf);
    if(size < 0)
    {
        cerr << "[ERROR] i2d_X509() error"<<endl;
        return -1;
    }

    _csTCP->sendMsg(buf, size);

    OPENSSL_free(buf);

    return size;
}

int SecureConnection::rcvCertificate(X509* cert)
{
    unsigned char *buf;
    long size;

    size = _csTCP->recvMsg((void**) &buf);
    
    cert = d2i_X509(NULL, (const unsigned char**)&buf, size);
    if(!cert)
    {
        cerr << "[ERROR] d2i_X509() error"<<endl;
        return -1;
    }

    return size;
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

int SecureConnection::randomInteger(){
    RAND_poll();
    
    int rndNumber; 

    RAND_bytes((unsigned char*) &rndNumber, sizeof(int)); 
    return rndNumber;  
}

int SecureConnection::concatenate(unsigned char* src1, uint32_t len1, unsigned char* src2, uint32_t len2, unsigned char* &dest)
{
    int destSize = len1 + len2 + 2*sizeof(uint32_t);

    dest = (unsigned char*) malloc(destSize);

    int currentPos = 0;

    memcpy(dest, &len1, sizeof(uint32_t));
    currentPos += sizeof(uint32_t);

    memcpy(dest + currentPos, src1, len1);
    currentPos += len1;

    memcpy(dest + currentPos, &len2, sizeof(uint32_t));
    currentPos += sizeof(uint32_t);

    memcpy(dest + currentPos, src2, len2);
    currentPos += len2;

    return currentPos;
}

void SecureConnection::establishConnectionServer()
{
    DH *dh_session; //alloco la struttura 
    dh_session = _sMsgCreator->get_dh2048();
    
    DH_generate_key(dh_session);

    cout<<"[DEBUG] PrivateKey generated"<<endl;

    unsigned char* Yc;
    int YcLen;

    YcLen = _csTCP->recvMsg((void**)&Yc);

    BIGNUM *bnYc;
    bnYc = BN_bin2bn(Yc, YcLen, NULL);

    free(Yc);

    unsigned char *sharedkey;
    int sharedkey_size;
    
    sharedkey = (unsigned char*) malloc(sizeof(unsigned char) *DH_size(dh_session));

    sharedkey_size = DH_compute_key(sharedkey, bnYc, dh_session);
    
    _sMsgCreator->derivateKeys(sharedkey,sharedkey_size);
    free(sharedkey);
    
    BN_free(bnYc);

    BIGNUM *bnYs = (BIGNUM *) DH_get0_pub_key(dh_session);
    
    unsigned char* Ys = new unsigned char[BN_num_bytes(bnYs)];
    int YsLen;
    
    YsLen = BN_bn2bin(bnYs, Ys); 

    _csTCP->sendMsg(Ys, YsLen);

/*
    unsigned char *msg;
    int msgLen;

    msgLen = concatenate(Ys, YsLen, Yc, YcLen, msg);

    EVP_PKEY* privKey = _sMsgCreator->ExtractPrivateKey("rsa_privkey.pem");

    unsigned char *signature;
    int signatureLen;

    signatureLen = _sMsgCreator->sign(msg, msgLen, privKey, signature);

    sendSecureMsg(signature, signatureLen);

    X509* cert = _sMsgCreator->loadCertificateFromFile("server_cert.pem");
    int ret = sendCertificate(cert);
    if(ret < 0)
    {
        return;
    }*/

    free(Ys);
    BN_free(bnYs);
    //DH_free(dh_session);

    //unsigned char* iv;
    //int ivSize = _csTCP->recvMsg((void **)&iv);
    //
    //unsigned char* encryptedKey;
    //int encryptedKeySize = _csTCP->recvMsg((void **)&encryptedKey);
    //
    //unsigned char* encryptedNonce;
    //int encryptedNonceSize = _csTCP->recvMsg((void **)&encryptedNonce);
    //
    //EVP_PKEY* privateKey =  _sMsgCreator->ExtractPrivateKey("rsa_privkey.pem");
    //throw exception();
} 

void SecureConnection::establishConnectionClient()
{
    DH *dh_session; //alloco la struttura 
    dh_session = _sMsgCreator->get_dh2048();

    DH_generate_key(dh_session);

    cout<<"[DEBUG] PrivateKey generated"<<endl;

    BIGNUM *bnYc = (BIGNUM *) DH_get0_pub_key(dh_session);
    if(!bnYc)
    {
        cout<<"[ERROR] bnYc is NULL"<<endl;
    }
    
    unsigned char* Yc = new unsigned char[BN_num_bytes(bnYc)];
    int YcLen;
    
    YcLen = BN_bn2bin(bnYc, Yc);

    BN_free(bnYc);

    cout<<"[_csTCP]"<<(void*)_csTCP<<endl;
    _csTCP->sendMsg((void*) Yc,YcLen);
    free(Yc);

    cout<<"[DEBUG] Yc sended"<<endl;

    unsigned char* Ys;
    int YsLen;

    YsLen = _csTCP->recvMsg((void**)&Ys); 

    BIGNUM *bnYs;
    bnYs = BN_bin2bn(Ys, YsLen, NULL);

    free(Ys);

    unsigned char *sharedkey;
    int sharedkey_size;
    
    sharedkey = (unsigned char*) malloc(sizeof(unsigned char) *DH_size(dh_session));

    sharedkey_size = DH_compute_key(sharedkey, bnYs, dh_session);
    
    _sMsgCreator->derivateKeys(sharedkey,sharedkey_size);
    free(sharedkey);
    BN_free(bnYs);
    //DH_free(dh_session);
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
        //usleep(500);

        fileSended += readedBytes;
        //cout << "[INFO] fileSended = " << fileSended << endl;
        //the following code prints * characters
        if (stars)
        {
            partReaded += readedBytes;
            
            if (whenPrintCharacter > 0 && partReaded >= whenPrintCharacter)
            {
                for (int i = 0; i < partReaded / whenPrintCharacter; i++)
                    cout << "*" << flush;
                partReaded = partReaded % whenPrintCharacter;
            }
        }
    }
    if (stars)
        cout << endl;

    return fileSended;
}

int SecureConnection::receiveFile(const char *filename, bool stars)
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

    size_t whenPrintCharacter = fileSize / 80;
    size_t partReaded = 0;

    size_t writedBytes;
    for (writedBytes = 0; writedBytes < fileSize; writedBytes += lenght)
    {
        //lenght = recvSecureMsgWithAck((void **)&writer);
        lenght = recvSecureMsg((void **)&writer);

        //cout << "[DEBUG] writedBites = " << writedBytes + lenght << endl;
        //the following code prints * characters
        if (stars)
        {
            partReaded += lenght;
            
            if (whenPrintCharacter > 0 && partReaded >= whenPrintCharacter)
            {
                for (int i = 0; i < partReaded / whenPrintCharacter; i++)
                    cout << "*" << flush;
                partReaded = partReaded % whenPrintCharacter;
            }
        }

        writeFile.write(writer, lenght);
        free(writer);
    }
    if (stars)
        cout << endl;

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
    
    //cout << "[INFO] fileSize = "<<fileSize << endl;
    

    size_t writedBytes;
    for (writedBytes = 0; writedBytes < fileSize; writedBytes += lenght)
    {
        //lenght = recvSecureMsgWithAck((void **)&writer);
        lenght = recvSecureMsg((void **)&writer);
        
        cout << writer;
        free(writer);
    }
    cout << endl;

    //cout << "[DEBUG] writedBites = " << writedBytes << endl;
    
    return writedBytes;
}