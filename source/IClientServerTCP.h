#ifndef ICLIENTSERVER
#define ICLIENTSERVER

#include <stdlib.h>

class IClientServerTCP
{
public:
	virtual void sendMsg(void *buffer, size_t bufferSize) = 0;
	virtual int recvMsg(void **buffer) = 0;
};

#endif