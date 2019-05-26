#include <exception>
#define MAX_PORT_NUMBER 65535
#define MIN_PORT_NUMBER 1024

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

class Sanitizator{
    private:
        static const char* numbers;
    
    public:
        static unsigned short checkPortNumber(char* param);
};