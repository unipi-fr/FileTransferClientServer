#include"Sanitizator.h"
#include <cstring>
#include <string>


#include<iostream>
using namespace std;

const char* Sanitizator::numbers = "0123456789";

unsigned short Sanitizator::checkPortNumber(char* param)
{
    if(strspn(param, numbers) < strlen(param))
        throw PortNumberException();

    int portNumber = atoi(param);

    if(portNumber > MAX_PORT_NUMBER || portNumber < MIN_PORT_NUMBER)
        throw PortNumberException();

    return portNumber;
}