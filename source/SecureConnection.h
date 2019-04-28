#include "IClientServerTCP.h"
#include "SecureMessageCreator.h"

class SecureConnection
{
private:
    IClientServerTCP *_csTCP;
    SecureMessageCreator *_sMsgCreator;

public:
    SecureConnection(IClientServerTCP *csTCP);
    void sendSecureMsg(void *buffer, size_t bufferSize);
    int recvSecureMsg(void **plainText);
    int sendFile(const char *filename, bool stars);
    int receiveFile(const char *filename);
};