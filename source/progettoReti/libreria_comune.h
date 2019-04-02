#include<stdio.h>	//Input output (printf)
#include<string.h>	//per gestire le stringhe
#include<stdlib.h> 	//funzioni dilibreria standard (atoi,)
#include<sys/types.h>	//socket (costantie valori)
#include<sys/socket.h>	//socket (funzioni)
#include<netinet/in.h>	//socket (strutture)
#include<arpa/inet.h>	//standard per l'ordine dei byte
#include<unistd.h>		//close(socket)

#define DIM_BUFFER 1024
#define DIM_IP 16
#define DIM_USERNAME 20
#define DIM_NUM_PORTA 6
#define DIM_MESSAGGIO DIM_BUFFER-DIM_USERNAME-15 
#define ONLINE 1
#define OFFLINE 0

char buffer[DIM_BUFFER];

void pulizia_buffer();
int stringa_inizia_con(const char *stringa, const char *parola);
int estrai_parola(char* parola_estratta, char* stringa);
int rimuovi_prima_del_carttere(char* stringa,const char c);
void invia_messaggio_tcp(int socket_invio);
int ricevi_messaggio_tcp(int socket_ascolto);
