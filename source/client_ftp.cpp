#include "my_crypto_lib.h"
#include "socket_lib.h"
#include <iostream>
#include <fstream>
using namespace std;

int clientPortNumber = 5555;
int serverPortNumber = 5000;

char ipServer[DIM_IP];

struct sockaddr_in serverStructAddr;

int socketTCP;


unsigned char output[100];

void serverStructInit(){
    /*creazione indirizzo*/
    memset(&serverStructAddr,0,sizeof(serverStructAddr)); //pulizia struttura
    serverStructAddr.sin_family = AF_INET;
    serverStructAddr.sin_port = htons(serverPortNumber); //setta il numero di porta nella struttura
    inet_pton(AF_INET,ipServer,&serverStructAddr.sin_addr);//setta l'indirizzo IP nella struttura
}

void socketTCPInit(){
    serverStructInit();
    /*creazione socket*/
    socketTCP = socket(AF_INET, SOCK_STREAM, 0);
}

void globalInit(char* args[]){
    //TODO: Da decontaminare
    memset(ipServer,0,DIM_IP);
    memcpy(ipServer,args[1],DIM_IP - 1);
    serverPortNumber = atoi(args[2]);
    
    socketTCPInit();
}

void serverTCPconnection(){
	if(connect(socketTCP, (struct sockaddr*)&serverStructAddr, sizeof(serverStructAddr))){
		perror("\nERRORE connect() Connessione al server non riuscita: ");
		exit(-5);
	}
	printf("Connessione al server %s (PORTA: %d) avvenuta con successo.\n",ipServer,serverPortNumber);
}

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



int main(int num_args, char* args[]){
    // 0 comando
    // 1 parametro indirizzo ip;
    // 2 parametro numero di porta;
    // 3 nome file da trasferire;
          
    /*LETTURA PARAMETRI*/
    if(num_args != 4){
        cout<<"ERROR: Number of parameters not valid."<<endl;
        cout<<"Usage: "<<args[0]<<" <ipServer> <SERVER_PORT_#> <FILE>"<<endl;
        cout<<"Closing program."<<endl<<endl;
        return -1;
    }
    
    globalInit(args);
    /*FINE LETTURA PARAMETRI*/
    serverTCPconnection();
    readFile(args[3]);
    cout<<"[FILE CONTENT]"<<output<<endl;
    
    int hashSize;
    
    unsigned char *hashSign = sign(output, 100, hashSize);
    cout<<"[HASH SIGN]"<<hashSign<<endl;    
 
    unsigned char *plainText = (unsigned char*)malloc(100 + hashSize);
    
    memcpy(plainText, hashSign, hashSize);
    memcpy(plainText+hashSize, output, 100);
    
    cout<<"[PlainText] "<<plainText<<endl;
    
    unsigned char *cipherText = (unsigned char*)malloc(100 + hashSize + 16);
    
    int ctLen = encrypt(plainText, 100 + hashSize, NULL, cipherText);
    
    cout<<"[cipherText] "<<cipherText<<endl;
    
    sendTCP(socketTCP, cipherText, ctLen);
    
    return 0;
}

