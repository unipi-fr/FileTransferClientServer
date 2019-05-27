#include "Printer.h"
#include <iostream>

using namespace std;

void Printer::printInfo(char* info)
{
    cout<<"["<<CYAN<<"INFO"<<RESET<<"] "<<info<<endl;
}

void Printer::printWaring(char* warning)
{
    cout<<"["<<YELLOW<<"INFO"<<RESET<<"] "<<warning<<endl;
}

void Printer::printError(char* error)
{
    cerr<<"["<<RED<<"INFO"<<RESET<<"] "<<error<<endl;
}

void Printer::printErrorWithReason(char* error, char* reason)
{
    cerr<<"["<<RED<<"INFO"<<RESET<<"] "<<error<<endl;
    cerr<<"\t"<<RED<<"Reason: "<<RESET<<reason<<endl;
}

void Printer::printMsg(char* msg)
{
    cout<<"["<<GREEN<<"INFO"<<RESET<<"] "<<msg<<endl;
}

void Printer::printPrompt(char* prompt)
{
    cout<<MAGENTA<<prompt<<RESET<<" ";
}