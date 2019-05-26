#include"Sanitizator.h"
#include <cstring>
#include <string>


#include<iostream>
using namespace std;

const char* Sanitizator::numbersValidator = "1234567890";
const char* Sanitizator::ipAddressValidator = "1234567890.";
const char* Sanitizator::osCommandValidator = "qwertyuiopasdfghjklzxcvbnm"
                                            "QWERTYUIOPASDFGHJKLZXCVBNM"
                                            "1234567890_-.@";

unsigned short Sanitizator::checkPortNumber(char* param)
{
    if(strspn(param, numbersValidator) < strlen(param))
        throw PortNumberException();

    int portNumber = atoi(param);

    if(portNumber > MAX_PORT_NUMBER || portNumber < MIN_PORT_NUMBER)
        throw PortNumberException();

    return portNumber;
}

string Sanitizator::checkIpAddress(char* param)
{
    if(strspn(param, ipAddressValidator) < strlen(param))
        throw IpAddressException();

    char* token;

    token = strtok (param, ".");
    int tokenNumber = atoi(token);
    if(tokenNumber > MAX_IP_ADDRESS_SUBNUM || tokenNumber < MIN_IP_ADDRESS_SUBNUM)
        throw IpAddressException();

    int numToken = 1;
        
    while (token != NULL)
    {
        token = strtok (NULL, ".");
        tokenNumber = atoi(token);
        if(tokenNumber > MAX_IP_ADDRESS_SUBNUM || tokenNumber < MIN_IP_ADDRESS_SUBNUM)
            throw IpAddressException();

        numToken += 1; 
    }

    if(numToken != MAX_IP_ADDRESS_NUM)
        throw IpAddressException();

    return param;
}

void Sanitizator::checkOsCommand(char* param)
{
    if(strspn(param, numbersValidator) < strlen(param))
        throw DangerousNameException();
}