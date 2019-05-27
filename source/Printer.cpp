#include "Printer.h"
#include <iostream>
#include <sys/ioctl.h>
#include <stdio.h>

using namespace std;

void Printer::printInfo(const char* info)
{
    cout<<"["<<CYAN<<"INFO"<<RESET<<"] "<<info<<endl;
}

void Printer::printWaring(const char* warning)
{
    cout<<endl;
    cout<<"["<<YELLOW<<"WARNING"<<RESET<<"] "<<warning<<endl<<endl;
}

void Printer::printError(const char* error)
{
    cerr<<endl;
    cerr<<"["<<RED<<"ERROR"<<RESET<<"] "<<error<<endl<<endl;
}

void Printer::printErrorWithReason(const char* error, const char* reason)
{
    cerr<<endl;
    cerr<<"["<<RED<<"ERROR"<<RESET<<"] "<<error<<endl;
    cerr<<"\t"<<RED<<"Reason: "<<RESET<<reason<<endl<<endl;
}

void Printer::printMsg(const char* msg)
{
    cout<<GREEN<<msg<<RESET<<endl;
}

void Printer::printPrompt(const char* prompt)
{
    cout<<MAGENTA<<prompt<<RESET<<" ";
}

void Printer::printLoadBar(double current, double end, bool error)
{
    if(current >= end)
        cout<<GREEN;
    else
        cout<<YELLOW;

    if(error)
        cout<<RED;

    cout<<"[";

    struct winsize w;
    ioctl(0, TIOCGWINSZ, &w);

    double actualPercentage = current/end;
    int charToPrint = w.ws_col - 7;

    double stopPrintingHash = actualPercentage * charToPrint;

    size_t partReaded = 0;
    
    for (int i = 0; i < charToPrint; i++)
    {
        if(i < stopPrintingHash)
            cout << "#";
        else
            cout<<" ";
    }

    cout<<"] "<<(long)(actualPercentage*100)<<"%"<<RESET;

    if(current >= end)
        cout<<endl<<endl;
    else
        cout<<"\r";

    if(error)
        cout<<endl;

    cout<<flush;
}

void Printer::printNormal(const char* msg)
{
    cout<<msg;
}


