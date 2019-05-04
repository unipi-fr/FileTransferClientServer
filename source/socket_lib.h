#include <exception>
#define DIM_IP 16

class DisconnectionException : public std::exception {
   const char * what () const throw () {
      return "Other part in the comunication is disconnected.";
   }
};

class NetworkException : public std::exception {
   const char * what () const throw () {
      return "Error during sending/receiving message.";
   }
};

void sendTCP(int sendSocket, void *buffer, size_t bufferSize);
int recvTCP(int listenSocket, void** buffer);