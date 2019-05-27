#include"Sanitizator.h"
#include <cstring>
#include <string>

#include<iostream>
using namespace std;

const char* Sanitizator::numbersValidator = "1234567890";
const char* Sanitizator::ipAddressValidator = "1234567890.";
const char* Sanitizator::filenameValidator = "qwertyuiopasdfghjklzxcvbnm"
                                            "QWERTYUIOPASDFGHJKLZXCVBNM"
                                            "1234567890_-.@";

unsigned short Sanitizator::checkPortNumber(const char* param)
{
    if(strspn(param, numbersValidator) < strlen(param))
        throw PortNumberException();

    int portNumber = atoi(param);

    if(portNumber > MAX_PORT_NUMBER || portNumber < MIN_PORT_NUMBER)
        throw PortNumberException();

    return portNumber;
}

string Sanitizator::checkIpAddress(string param)
{
    if(strspn(param.c_str(), ipAddressValidator) < strlen(param.c_str()))
        throw IpAddressException();

    string tmp = param;
    char* token;
    token = strtok ((char*)tmp.c_str(), ".");
    int tokenNumber = atoi(token);
    if(tokenNumber > MAX_IP_ADDRESS_SUBNUM || tokenNumber < MIN_IP_ADDRESS_SUBNUM)
        throw IpAddressException();

    int numToken = 1;  

    while (true)
    {   
        token = strtok (NULL, ".");
        if(token == NULL){
            break;
        }
        tokenNumber = atoi(token);  
        if(tokenNumber > MAX_IP_ADDRESS_SUBNUM || tokenNumber < MIN_IP_ADDRESS_SUBNUM)
            throw IpAddressException();

        numToken += 1; 
    }
  
    if(numToken != MAX_IP_ADDRESS_NUM)
        throw IpAddressException();

    return param;
}

void Sanitizator::checkFilename(const char* param)
{
    if(strspn(param, filenameValidator) < strlen(param))
        throw DangerousFilenameException();
}