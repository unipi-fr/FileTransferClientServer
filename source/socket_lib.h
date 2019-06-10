#include <exception>
#define DIM_IP 16

class SocketLibException : public std::exception
{
   virtual const char *what() const throw() = 0;
};

class DisconnectionException : public SocketLibException
{
   const char *what() const throw()
   {
      return "Other part in the comunication is disconnected.";
   }
};

class NetworkException : public SocketLibException
{
   const char *what() const throw()
   {
      return "Error during sending/receiving message.";
   }
};

void sendTCP(int sendSocket, void *buffer, size_t bufferSize);
int recvTCP(int listenSocket, void **buffer);