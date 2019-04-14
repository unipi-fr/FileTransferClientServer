#include "SecureMessageCreator.h"
#include "ClientTCP.h"
#include "string.h"
#include <iostream>
#include <fstream>
using namespace std;

unsigned char output[100];
ClientTCP* client;

void readFile(char* fileName){
    memset(output,0,100);
    ifstream readFile;
    readFile.open(fileName);

    if (readFile.is_open()) {

        while (!readFile.eof()) {
            readFile >> output;
        }
    }

    readFile.close();
}
SecureMessageCreator* msgCreator;

void uploadCommand(string command){
    readFile(&command[0]);
          cout<<"[FILE CONTENT]"<<output<<endl;
          unsigned char* secureMessage;
          int hashSize;
    
          size_t msgSize = msgCreator->EncryptAndSignMessage(output,100,&secureMessage);
    
          cout<<"[secureMessage] "<<secureMessage<<endl;
          client->sendMsg(secureMessage,msgSize);
}

void retriveListCommand(){
    cout<<"Chiamato comando Retrive-List, Attualmente non implementato :)"<<endl<<endl;
    //client->sendMsg("rl","rl".length());
}

void retriveFileCommand(){
    cout<<"Chiamato comando Retrive-File, Attualmente non implementato :)"<<endl<<endl;
}

void helpCommand(){
    cout<<"  - per fare l'upload di un file digitare - u [nome file]"<<endl;
    cout<<"  - per ottenere la lista dei file nel server digitare - rl"<<endl;
    cout<<"  - per ricevere un file dal server digitare - rf [nome file]"<<endl;
    cout<<"  - per uscire dal programma digitare - q"<<endl;
    cout<<" ------------------------------------------------------------"<<endl<<endl;
}


int main(int num_args, char* args[]){
    // 0 comando
    // 1 parametro indirizzo ip;
    // 2 parametro numero di porta;
    // 3 nome file da trasferire;

    /*LETTURA PARAMETRI*/
    if(num_args != 4){
        cout<<"ERROR: Number of parameters not valid."<<endl;
        cout<<"Usage: "<<args[0]<<" <_ipServer> <SERVER_PORT_#> <FILE>"<<endl;
        cout<<"Closing program."<<endl<<endl;
        return -1;
    }

    msgCreator = new SecureMessageCreator();
    client = new ClientTCP(args[1],atoi(args[2]));
    /*FINE LETTURA PARAMETRI*/
    if(!client->serverTCPconnection()){
        
        exit(-5);
    }

    string command;
    string c;
    size_t pos = 0;

    bool exit = false;

    for(;;) {

      cout<<"Inserisci il comando (Digita h per avere la lista dei comandi):\n$> ";
      cin>>command;
      cout<<endl;

      pos = command.find(" ");
      c = command.substr(0, pos);
      command.erase(0, pos+1);
    
        if(c=="u"){
            uploadCommand(command);
        }
        if(c=="rl"){
            retriveListCommand();
        }
        if(c=="rf"){
            retriveFileCommand();
        }
        if(c=="q"){
            break;
        }
    }
    
    return 0;
}
