#include"libreria_comune.h"

void pulizia_buffer(){
	memset(buffer,0,sizeof(buffer));
}

int stringa_inizia_con(const char *stringa, const char *parola)
{
    size_t lun_stringa = strlen(stringa),
           lun_parola= strlen(parola);
    return lun_stringa < lun_parola ? 0 : strncmp(parola, stringa, lun_parola) == 0;
}

int estrai_parola(char* parola_estratta, char* stringa){
	char* pointer;
	size_t lun;
	pointer = strchr(stringa,' ');
	if(pointer == NULL){
		strcpy(parola_estratta,stringa);
		strcpy(stringa,"");
		return 1;
		
	}
	
	lun = strlen(stringa)-strlen(pointer+1);
	//lo spazio non lo voglio
	lun = lun -1;
	//salvo la parola estratta
	strncpy(parola_estratta,stringa,lun);
	//sovrascrivo
	strcpy(stringa,pointer+1);
	return 1;
}

int rimuovi_prima_del_carttere(char* stringa,const char c){
	char* pointer;
	pointer = strchr(stringa,c);
	if(pointer == NULL){
		return 0;
	}
	strcpy(stringa,pointer+1);
	return 1;
}

void invia_messaggio_tcp(int socket_invio){
	uint16_t dimensione;
	int lunghezza_stringa;
	int num_byte;
	lunghezza_stringa = strlen(buffer);
	dimensione = htons(lunghezza_stringa);
	//invio numero di dati
	num_byte = send(socket_invio,(void*)&dimensione, sizeof(uint16_t),0);
	if(num_byte == -1){
		perror("perrore send()");
		exit(-5);
	}
	//invio dati
	num_byte = send(socket_invio, (void*)buffer, lunghezza_stringa, 0);
	if(num_byte == -1){
		perror("perrore send()");
		exit(-5);
	}
}

int ricevi_messaggio_tcp(int socket_ascolto){
	uint16_t dimensione;
	int num_byte;
	int lunghezzaStringa;
	pulizia_buffer();
	//ricevo la dimensione
	num_byte = recv(socket_ascolto, (void*)&dimensione, sizeof(uint16_t),0);
	if(num_byte == 0){
		return 0;
	}
	if(num_byte == -1){
		perror("Errore recv(): ");
		exit(-5);
	}
	//riconverto i dati
	lunghezzaStringa = ntohs(dimensione);
	//uso la lunghezzaPrecisa per ricevere la stringa
	num_byte = recv(socket_ascolto, (void*)buffer,lunghezzaStringa,0);
	if(num_byte == -1){
		perror("Errore recv(): ");
		exit(-5);
	}
	return num_byte;
}
