#include <exception>
#include <string>

#define MAX_PORT_NUMBER 65535
#define MIN_PORT_NUMBER 1024
#define MAX_IP_ADDRESS_SUBNUM 255
#define MIN_IP_ADDRESS_SUBNUM 0
#define MAX_IP_ADDRESS_NUM 4

class SanitizatorException : public std::exception
{
    public:
    virtual const char *what() const throw() = 0;
};

class PortNumberException : public SanitizatorException
{
    public:
    const char *what() const throw()
    {
        return "Port number not valid (port number should be between 1024 and 65535)";
    }
};

class IpAddressException : public SanitizatorException
{
    public:
    const char *what() const throw()
    {
        return "Ip address not valid";
    }
};

class DangerousFilenameException : public SanitizatorException
{
    public:
    const char *what() const throw()
    {
        return "filename not Valid";
    }
};

class Sanitizator{
    private:
        static const char* numbersValidator;
        static const char* ipAddressValidator;
        static const char* filenameValidator;
    
    public:
        static unsigned short checkPortNumber(const char* param);
        static std::string checkIpAddress(std::string param);
        static void checkFilename(const char* param);
};