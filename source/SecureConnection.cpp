#include "SecureConnection.h"
#include "Printer.h"
#include "socket_lib.h"
#include <string>
#include <sstream>
#include <unistd.h>
#include <string.h>


using namespace std;

SecureConnection::SecureConnection(IClientServerTCP *csTCP)
{
    _csTCP = csTCP;

    _sMsgCreator = new SecureMessageCreator();

    string* names;
    int numberOfNames = readNamesFromFile("certificateSettings/names.txt", names);

    _certVal = new CertificationValidator(names,numberOfNames);

    X509* caCert = _certVal->loadCertificateFromFile("certificateSettings/CA_CybersecurityUniPi.pem");
    if(caCert == NULL){
        Printer::printWaring("not possible load CA certificate from file, all certificate cloud not be verify properly");
    }else{
        _certVal->addCertificationAut(caCert);
    }
}
unsigned long SecureConnection::generateNonce()
{
    return _sMsgCreator->getNonce();
}

void SecureConnection::destroyKeys(){
    _sMsgCreator->destroyKeysIfSetted();
}

int SecureConnection::readNamesFromFile(const char* filename, string* &names){
	ifstream is;
	is.open(filename);
    
    if(!is.is_open()){
        throw FileNotOpenException();
    }
    
    int numberOfNames = 0;

    is.seekg(0, ios::end);
    int fileSize = is.tellg();
    if (fileSize == 0)
    {
        names = new string[1];
        names[0] = "";
        numberOfNames = 1;

        return -1;
    }

    is.seekg(0, ios::beg);

    string grb;

    while(!is.eof())
    {
	    getline(is, grb);
        numberOfNames += 1;
    }

    names = new string[numberOfNames];

    is.seekg(0, ios::beg);

    int i = 0;
    while(!is.eof())
    {
	    getline(is,names[i++]);
    }

	is.close();

    return numberOfNames;
}

int SecureConnection::sendCertificate(X509* cert)
{
    unsigned char* buf = NULL;
    
    int size = i2d_X509(cert, &buf);
    if(size < 0)
    {
        Printer::printError("i2d_X509()");
        return -1;
    }

    _csTCP->sendMsg(buf, size);

    OPENSSL_free(buf);

    return size;
}

int SecureConnection::rcvCertificate(X509* &cert)
{
    unsigned char *buf;
    long size;

    size = _csTCP->recvMsg((void**) &buf);
    
    cert = d2i_X509(NULL, (const unsigned char**)&buf, size);
    if(!cert)
    {
        Printer::printError("d2i_X509()");
        return -1;
    }

    return size;
}

void SecureConnection::sendSecureMsg(void *buffer, size_t bufferSize, bool useNonce, unsigned long nonce)
{
    unsigned char *secureMessage;
    _sMsgCreator->initEncryptContext(NULL);
    size_t msgSize = _sMsgCreator->EncryptAndSignMessageFinal((unsigned char *)buffer, bufferSize, &secureMessage, useNonce, nonce);
    _csTCP->sendMsg(secureMessage, msgSize);
    delete secureMessage;
}

int SecureConnection::recvSecureMsg(void **plainText, bool useNonce, unsigned long nonce)
{
    int numberOfBytes;
    unsigned char *encryptedText;
    numberOfBytes = _csTCP->recvMsg((void **)&encryptedText);

    _sMsgCreator->initDecryptContext(NULL);

    int plainTextSize;
    bool check = _sMsgCreator->DecryptAndCheckSignFinal(encryptedText, numberOfBytes, (unsigned char **)plainText, plainTextSize, useNonce, nonce);

    delete encryptedText;

    if (!check)
    {
        throw HashNotValidException();
    }

    return plainTextSize;
}

int SecureConnection::concatenate(unsigned char* src1, uint32_t len1, unsigned char* src2, uint32_t len2, unsigned char* &dest)
{
    int destSize = len1 + len2 + 2*sizeof(uint32_t);

    dest = new unsigned char[destSize];

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

void SecureConnection::computeSharedKeys(DH *dh_session, BIGNUM *bn)
{   
    unsigned char*  sharedkey = new unsigned char[sizeof(unsigned char) *DH_size(dh_session)];

    int sharedkey_size = DH_compute_key(sharedkey, bn, dh_session);

    _sMsgCreator->derivateKeys(sharedkey,sharedkey_size);
    
    //cleaning sharedkey
    explicit_bzero(sharedkey, sharedkey_size);
    delete sharedkey;
}

void SecureConnection::sendAutenticationAndFreshness(unsigned char* expectedMsg,int msgLen, EVP_PKEY* privKey, X509* cert){
    unsigned char *signature;
    int signatureLen;

    signatureLen = _sMsgCreator->sign(expectedMsg, msgLen, privKey, signature);
    sendSecureMsg(signature, signatureLen, false, 0);

    int ret = sendCertificate(cert);
    
    delete signature;
}

bool SecureConnection::recvAutenticationAndVerify(unsigned char* expectedMsg, int expectedMsgLen)
{
    unsigned char *signature;
    int signatureLen;

    X509* cert;
    int certSize;

    signatureLen = recvSecureMsg((void**)&signature, false, 0);

    certSize = rcvCertificate(cert);

    string mess = "Recived certificate: "+_certVal->getCertName(cert);
    Printer::printInfo(mess.c_str());
    bool validCertificate = _certVal->verifyCertificate(cert);
    if(!validCertificate){
        throw CertificateNotValidException();
    }

    EVP_PKEY* pubKey = _certVal->extractPubKeyFromCertificate(cert);

    bool  signResult = _sMsgCreator->verify(expectedMsg, expectedMsgLen, signature, signatureLen, pubKey);
    //bool signResult = false;
    
    delete signature;
    
    return signResult;
}

void SecureConnection::establishConnectionServer()
{
    DH *dh_session; //alloco la struttura 
    dh_session = _sMsgCreator->get_dh2048();
    
    DH_generate_key(dh_session);

    unsigned char* Yc;
    int YcLen;

    YcLen = _csTCP->recvMsg((void**)&Yc);

    BIGNUM *bnYc;
    bnYc = BN_bin2bn(Yc, YcLen, NULL);

    computeSharedKeys(dh_session, bnYc);

    BN_free(bnYc);

    BIGNUM *bnYs = (BIGNUM *) DH_get0_pub_key(dh_session);
    
    unsigned char* Ys = new unsigned char[BN_num_bytes(bnYs)];
    int YsLen;
    
    YsLen = BN_bn2bin(bnYs, Ys); 

    _csTCP->sendMsg(Ys, YsLen);
    
    unsigned char* msg;
    int msgLen;

    msgLen = concatenate(Yc,YcLen,Ys,YsLen,msg);

    delete Yc;
    delete Ys;
    
    X509* cert = _certVal->loadCertificateFromFile("certificateSettings/my_certificate.pem");
    EVP_PKEY* privKey = _sMsgCreator->ExtractPrivateKey("certificateSettings/rsa_privkey.pem");
    sendAutenticationAndFreshness(msg,msgLen,privKey,cert);
    EVP_PKEY_free(privKey);

    X509_free(cert);

    bool verifySing = recvAutenticationAndVerify(msg,msgLen);
    
    delete msg;
    DH_free(dh_session);
    
    if(!verifySing)
    {
        throw InvalidDigitalSignException();
    }

    sendSecureMsg((void*)"ok",3, false, 0); // for Atu verification
} 

void SecureConnection::establishConnectionClient()
{
    DH *dh_session; //alloco la struttura 
    dh_session = _sMsgCreator->get_dh2048();

    DH_generate_key(dh_session);

    BIGNUM *bnYc = (BIGNUM *) DH_get0_pub_key(dh_session);
    
    unsigned char* Yc = new unsigned char[BN_num_bytes(bnYc)];
    int YcLen;
    
    YcLen = BN_bn2bin(bnYc, Yc);

    //BN_free(bnYc); se lasciata DH_free() da errore di segmentazione

    _csTCP->sendMsg((void*) Yc,YcLen);

    unsigned char* Ys;
    int YsLen;

    YsLen = _csTCP->recvMsg((void**)&Ys); 

    BIGNUM *bnYs;
    bnYs = BN_bin2bn(Ys, YsLen, NULL);

    computeSharedKeys(dh_session, bnYs);

    BN_free(bnYs);

    unsigned char* msg;
    int msgLen;

    msgLen = concatenate(Yc,YcLen,Ys,YsLen,msg);

    delete Yc;
    delete Ys;

    bool verifySing = recvAutenticationAndVerify(msg,msgLen);

    if(!verifySing)
    {
        delete msg;
        throw InvalidDigitalSignException(); 
    }

    X509* cert = _certVal->loadCertificateFromFile("certificateSettings/my_certificate.pem");
    
    EVP_PKEY* privKey = _sMsgCreator->ExtractPrivateKey("certificateSettings/rsa_privkey.pem");
    sendAutenticationAndFreshness(msg,msgLen,privKey,cert);
    
    //cleaning privatekey
    EVP_PKEY_free(privKey);
    X509_free(cert);
    delete msg;
    
    DH_free(dh_session);

    // for Atu verification //////////////////////////////////////////
    unsigned char* checkConnectionEnstablished;
    int checkSize = recvSecureMsg((void**) &checkConnectionEnstablished, false, 0);
    delete checkConnectionEnstablished;
    //////////////////////////////////////////////////////////////////
} 

int SecureConnection::sendFile(ifstream &file, bool stars, unsigned long nonce)
{
    if (!file.is_open())
    {
        throw FileNotOpenException();
    }

    // obtain and send file size
    file.seekg(0, ios::end);
    long fileSize = file.tellg();
    if (fileSize == 0)
    {
        Printer::printInfo("Attempt to send and empy file");
    }
    string strFileSize = to_string(fileSize);

    if(fileSize > MAX_FILE_SIZE)
    {
    	sendSecureMsg((void *)"-2", 3, true, nonce);
        throw FileSizeException();
    }

    sendSecureMsg((void *)strFileSize.c_str(), strFileSize.length(), true, nonce);

    size_t fileSended = 0;

    if (fileSize == 0)
    {
        return fileSended;
    }

    file.seekg(0, ios::beg);
    char buffer[BUFF_SIZE];

    string mess = "fileSize = " + strFileSize;
    Printer::printInfo(mess.c_str());

    nonce += 1; 
    while (!file.eof() && fileSended < fileSize)
    {
        memset(buffer, 0, BUFF_SIZE);
        file.read(buffer, BUFF_SIZE);
        size_t readedBytes = file.gcount();

        sendSecureMsg(buffer, readedBytes, true, nonce);
        nonce += 1;

        fileSended += readedBytes;
        if (stars)
            Printer::printLoadBar(fileSended, fileSize,false);
    }

    return fileSended;
}

int SecureConnection::receiveFile(const char *filename, bool stars, unsigned long nonce)
{
    ofstream writeFile;

    char *writer;
    int lenght;

    lenght = recvSecureMsg((void **)&writer, true, nonce);

    long fileSize;
    stringstream ss;
    ss << writer;
    ss >> fileSize;

    delete writer;

    if(fileSize == -1)
    {
        throw FileDoesNotExistsException();
    }

    if(fileSize == -2)
    {
        throw FileSizeException();
    }

    stringstream mess;
    mess << "fileSize = " << fileSize;
    Printer::printInfo(mess.str().c_str());

    writeFile.open(filename, ios::binary);
    if (!writeFile.is_open())
    {
        throw FileNotOpenException();
    }

    size_t whenPrintCharacter = fileSize / 80;
    size_t partReaded = 0;

    size_t writedBytes;
    nonce += 1;
    
    for (writedBytes = 0; writedBytes < fileSize; writedBytes += lenght)
    {
        lenght = recvSecureMsg((void **)&writer, true, nonce); 
        nonce += 1;       

        //the following code prints * characters
        if (stars)
            Printer::printLoadBar(writedBytes + lenght, fileSize,false);

        writeFile.write(writer, lenght);
        delete writer;
    }

    writeFile.close();

    return writedBytes;
}

int SecureConnection::reciveAndPrintBigMessage(unsigned long nonce)
{
    char *writer;
    char *ack;
    int lenght;
    
    lenght = recvSecureMsg((void **)&writer, true, nonce);

    size_t fileSize;
    stringstream ss;
    ss << writer;
    ss >> fileSize;
    delete writer;
    if(fileSize == -2)
    {
        throw FileSizeException();
    }
    
    size_t writedBytes;
    nonce += 1;
    for (writedBytes = 0; writedBytes < fileSize; writedBytes += lenght)
    {
        lenght = recvSecureMsg((void **)&writer, true, nonce);
        nonce += 1;
        unsigned char* writer2 = new unsigned char[lenght+1];

        memcpy(writer2,writer,lenght);
        writer2[lenght] = '\0';
        Printer::printNormal((char*)writer2);
        delete writer;
    }
    
    Printer::printNormal("\n");
    
    return writedBytes;
}