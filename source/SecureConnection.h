#include "IClientServerTCP.h"
#include "SecureMessageCreator.h"
#include <fstream>

#define BUFF_SIZE 16335

class SecureConnection
{
private:
    IClientServerTCP *_csTCP;
    SecureMessageCreator *_sMsgCreator;

public:
    SecureConnection(IClientServerTCP *csTCP);
    void sendSecureMsg(void *buffer, size_t bufferSize);
    int recvSecureMsg(void **plainText);

    /**
     * sendFile send a file.
     *
     * @file need an open filestream.
     * @stars if true prints 80 * on the screen
     * @return the fileSize on success or -1 on error.
     * 
     * A call with a stream closed will return -1
     */
    int sendFile(std::ifstream &file, bool stars);
    int receiveFile(const char *filename);
    int reciveAndPrintBigMessage();
};