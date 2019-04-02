#include"libreria_comune.h"
/*VARIABILI GLOBALI*/
	char ip_locale[DIM_IP];
	int porta_locale;
	char ip_server[DIM_IP];
	int porta_server;
	
	char username[DIM_USERNAME];
	
	struct sockaddr_in st_indirizzo_server;
	struct sockaddr_in st_indirizzo_locale;
	int socket_tcp;
	int socket_udp;
/*VARIABILI GLOBALI*/

void pulizia_username(){
	memset(username,0,sizeof(username));	
}

void inizializza_struttura_indirizzo_server(){
	/*creazione indirizzo*/
	memset(&st_indirizzo_server,0,sizeof(st_indirizzo_server));	//pulizia struttura
	st_indirizzo_server.sin_family = AF_INET;
	st_indirizzo_server.sin_port = htons(porta_server);	//setta il numero di porta nella struttura
	inet_pton(AF_INET,ip_server,&st_indirizzo_server.sin_addr);//setta l'indirizzo IP nella struttura
}
void inizializza_stuttura_indirizzo_locale(){
	memset(&st_indirizzo_locale,0,sizeof(st_indirizzo_locale));	//pulizia struttura
	st_indirizzo_locale.sin_family = AF_INET;
	st_indirizzo_locale.sin_port = htons(porta_locale);
	st_indirizzo_locale.sin_addr.s_addr = INADDR_ANY;
}

void inizializza_socket_udp(){
	inizializza_stuttura_indirizzo_locale();
	socket_udp = socket(AF_INET, SOCK_DGRAM, 0);
	if(bind(socket_udp, (struct sockaddr*)&st_indirizzo_locale, sizeof(st_indirizzo_locale)) == -1){
		perror("ERRORE bind() problema ad inizializzare socket UDP: ");
		exit(-5);
	}
	printf("\nMessaggi istantanei in arrivo sulla porta <%d>\n",porta_locale);
}

void inizializza_socket_tcp(){
	inizializza_struttura_indirizzo_server();
	/*creazione socket*/
	socket_tcp = socket(AF_INET, SOCK_STREAM, 0);
}

void inizializza_variabili_globali(char* args[]){
	strcpy(ip_locale,args[1]);
	porta_locale = atoi(args[2]);
	strcpy(ip_server,args[3]);
	porta_server = atoi(args[4]);
	
	
	inizializza_socket_tcp();
	inizializza_socket_udp();
	
	pulizia_username();
	pulizia_buffer();
}

void invia_messaggio_udp(int socket_udp,char* indirizzo_ip,int numero_porta){
	struct sockaddr_in indirizzo_destinazione;
	
	indirizzo_destinazione.sin_family = AF_INET;
	indirizzo_destinazione.sin_port = htons(numero_porta);
	inet_pton(AF_INET, indirizzo_ip, &indirizzo_destinazione.sin_addr);
	
	if(sendto(socket_udp, buffer, strlen(buffer), 0, (struct sockaddr*)&indirizzo_destinazione, sizeof(indirizzo_destinazione))==-1){
		printf("ERRORE: problema ad inviare il messaggio istantaneo.\n");
		return;
	}
	//printf("MESSAGGIO INVIATO: <%s>\n",buffer);
}

void ricevi_messaggio_udp(int socket_udp){
	char buffer_locale[DIM_BUFFER];
	//char temporaneo[DIM_BUFFER];
	struct sockaddr_in indirizzo_mittente;
	socklen_t lungheza_indirizzo;
	memset(buffer_locale,0,sizeof(buffer_locale));
	//memset(temporaneo,0,sizeof(temporaneo));
	memset(&indirizzo_mittente,0,sizeof(indirizzo_mittente));
	lungheza_indirizzo = sizeof(indirizzo_mittente);
	
	//gets(temporaneo);
	//printf("[DEBUG] temp: <%s> \n",temporaneo);
	
	
	if(recvfrom(socket_udp, buffer_locale, DIM_BUFFER, 0, (struct sockaddr*)&indirizzo_mittente, &lungheza_indirizzo)==-1){
		printf("ERRORE: problema a ricevere il messaggio istantaneo.\n");
		return;
	}
	printf("\n%s\n",buffer_locale);
	

}

void connessione_server_tcp(){
	if(connect(socket_tcp, (struct sockaddr*)&st_indirizzo_server, sizeof(st_indirizzo_server))){
		perror("\nERRORE connect() Connessione al server non riuscita: ");
		exit(-5);
	}
	printf("Connessione al server %s (PORTA: %d) avvenuta con successo.\n",ip_server,porta_server);
}

void stampa_comandi(){
	printf("\nSono disponibili i seguenti comandi:\n");
	printf(" !help --> mostra l'elenco dei comandi disponibili\n");
	printf(" !register <username> --> registra il client presso il server\n");
	printf(" !deregister --> de-registra il client presso il server\n");
	printf(" !who --> mostra l'elenco degli utenti disponibili\n");
	printf(" !send <username> --> invia un messaggio ad un altro utente\n");
	printf(" !quit --> disconnette il client dal server ed esce\n\n");
}

void comando_quit(){
	printf("Chiusura connessione...\n");
	close(socket_tcp);
	printf("Chiusura programma.\n");
	exit(0);
}

void comando_deregister(){
	invia_messaggio_tcp(socket_tcp);
	if(ricevi_messaggio_tcp(socket_tcp)==0){
		printf("ERRORE: non è possibile ricevere l'esito della Deregistrazione.\nIl server ha probabilmente chiuso la connessione, esecuzione comando !quit...\n");
		comando_quit();
		return;
	}
	printf("%s\n\n",buffer);
	if(!stringa_inizia_con(buffer,"ERRORE")){
		pulizia_username();
	}
	
	
}

void comando_who(){
	char* pointer;
	pointer = &buffer[1];
	invia_messaggio_tcp(socket_tcp);
	while(1){
		pulizia_buffer();
		if(ricevi_messaggio_tcp(socket_tcp)==0){
			printf("ERRORE: problema nel ricevere la lista degli utenti registrati.\n");
			return;
		}
		printf("%s",pointer);
		if(stringa_inizia_con(buffer,"0")){
			return;
		}
	}
}
//la prepara messaggio prepara solo il messaggio locale, pronto epr essere inviato
void prepara_messaggio(char* messaggio){
	char local_buf[DIM_BUFFER];
	int lunghezza_raggiunta;
	int lunghezza_stringa;
	memset(messaggio,0,sizeof(char)*DIM_MESSAGGIO);
	lunghezza_raggiunta = strlen(messaggio);
	while(1){
		memset(local_buf,0,sizeof(local_buf));
		fgets(local_buf, sizeof(local_buf), stdin);
		//strtok(buffer, "\n");
		if(stringa_inizia_con(local_buf,".\n")){
			break;
		}
		lunghezza_stringa = strlen(buffer);
		if(lunghezza_raggiunta + lunghezza_stringa < DIM_BUFFER -2){
			lunghezza_raggiunta = lunghezza_raggiunta + lunghezza_stringa;
			strcat(messaggio,local_buf);
		}else{
			//ho sforato la dimensione del messaggio
			//mando senza l'ultimo pezzo
			printf("ATTENZIONE: il messaggio era troppo grande, è stato inviato senza l'ultima riga.\n");
			break;
		}
	}
	return;
}
//prepara il buffer scrivendoci dentro il messaggio
void prepara_messaggio_da_inviare(int on_off,char* messaggio){
	pulizia_buffer();
	strcpy(buffer,username);
	if(on_off == ONLINE){
		strcat(buffer," (ONLINE)>\n");
	}else{
		strcat(buffer," (OFFLINE)>\n");
	}
	strcat(buffer,messaggio);
	return;
}

/*
il client controlla la correttezza del comando
il client prepara il messaggio
Il Client manda il comando
il server risponde:
	-ONLINE <IP_UTENTE> <NUMERO_PORTA>
	-OFFLINE
	-ERRORE <spiegazione>
se non c'è errore 

OFFLINE):
	il client manda il messaggio al server con il TCP
ONLINE)
	il client manda il messaggio all'altro client per UDP
	
*/
void comando_send(){
	char* pointer;
	char* tmp;
	char messaggio[DIM_MESSAGGIO];
	char porta_utente[DIM_NUM_PORTA];
	char utente[DIM_USERNAME];
	char ip_utente[DIM_IP];
	memset(ip_utente,0,sizeof(ip_utente));
	memset(utente,0,sizeof(utente));
	memset(porta_utente,0,sizeof(porta_utente));
	
	//cerco il primo spazio
	if(strcmp(username,"")==0){
		printf("ERRORE: Devi essere registrato per mandare un messaggio.\n");
		return;
	}
	pointer = strchr(buffer,' ');
	if(pointer == NULL){
		printf("ERRORE: struttura del comando non valido.\nUsage: !send <username>\n");
		return;
	}
	pointer++;
	//controllo la dimensione dell'username
	if(strlen(pointer) > DIM_USERNAME - 1||strlen(pointer) == 0){
		printf("ERRORE: Username deve essere compreso fra 1 e %d caratteri.\n",DIM_USERNAME-1);
		return;
	}
	tmp = pointer;
	//cerco altri spazi
	pointer = strchr(pointer,' ');
	if(pointer != NULL){
		printf("ERRORE: L'username non può contenere spazi!\n");
		return;
	}
	//salvo l'username'
	strcpy(utente,tmp);
	if(strcmp(username,utente)==0){
		printf("ERRORE: Non puoi mandare messaggi a te stesso.\n");
		return;
	}
	prepara_messaggio(messaggio);
	/*INVIO COMANDO AL SERVER*/
	invia_messaggio_tcp(socket_tcp);
	pulizia_buffer();
	if(ricevi_messaggio_tcp(socket_tcp)==0){
		printf("ERRORE: connessione chiusa dal server.'\nEsecuzione !quit...\n");
		comando_quit();
	}
	if(stringa_inizia_con(buffer,"ERRORE")){
		printf("%s\n",buffer);
		return;
	}
	if(stringa_inizia_con(buffer,"OFFLINE")){
		prepara_messaggio_da_inviare(OFFLINE,messaggio);//SOVRASCRIVE IL BUFFER
		invia_messaggio_tcp(socket_tcp);
		return;
	}
	if(stringa_inizia_con(buffer,"ONLINE")){
		estrai_parola(ip_utente, buffer);//estraggo ONLINE
		memset(utente,0,sizeof(utente));//pulisco l'ip
		estrai_parola(ip_utente, buffer);//estraggo IP
		estrai_parola(porta_utente,buffer);//estraggo il numero di porta
		prepara_messaggio_da_inviare(ONLINE,messaggio);//SOVRASCRIVE IL BUFFER
		invia_messaggio_udp(socket_udp,ip_utente,atoi(porta_utente));
		return;
	}
	printf("ERRORE: il messaggio ricevuto dal server non ha il formato previsto.\n");
	return;
}

void ricevi_messasggi_offline(){
	char* pointer;
	pointer = &buffer[1];
	while(1){
		pulizia_buffer();
		if(ricevi_messaggio_tcp(socket_tcp)==0){
			printf("ERRORE: problema nel ricevere i messaggi offline.\n");
			return;
		}
		if(strlen(pointer)==0){
			return;
		}
		printf("%s",pointer);
		if(stringa_inizia_con(buffer,"0")){
			printf("\n");
			return;
		}
	}
}

/*
PROTOCOLLO:
client-> !register uername
server-> *esito*
	//ESITO NEGATIVO
	client->stampa esito e continua
	server->continua
	//ESITO POSITIVO
	client->aspetta i messaggi offline
	server->manda i messaggi uno alla volta
		->ultimo messaggio: server manda "0<messaggio>"
		->messaggio intermedio: server manda "1<messaggio>"
		//in caso di nessun messaggio manda comunque "0"
*/
void comando_register(){
	char* tmp;
	char* pointer;
	char num_porta[DIM_NUM_PORTA];
	int num_byte;
	//cerco il primo spazio
	if(strcmp(username,"")!=0){
		printf("ERRORE: Sei già registrato non puoi registrarti nuovamente.\n");
		return;
	}
	pointer = strchr(buffer,' ');
	if(pointer == NULL){
		printf("ERRORE: struttura del comando non valido.\nUsage: !register <username>\n");
		return;
	}
	pointer++;
	//controllo la dimensione dell'username
	if(strlen(pointer) > DIM_USERNAME - 1||strlen(pointer) == 0){
		printf("ERRORE: Username deve essere compreso fra 1 e %d caratteri.\n",DIM_USERNAME-1);
		return;
	}
	tmp = pointer;
	//cerco altri spazi
	pointer = strchr(pointer,' ');
	if(pointer != NULL){
		printf("ERRORE: L'username non può contenere spazi!\n");
		return;
	}
	strcpy(username,tmp);
	//aggiungo indirizzo_ip_locale e porta al messaggio
	sprintf(num_porta,"%d",porta_locale);
	strcat(buffer," ");
	strcat(buffer,ip_locale);
	strcat(buffer," ");
	strcat(buffer,num_porta);
	
	//invio il messaggio
	invia_messaggio_tcp(socket_tcp);
	//attendo esito
	num_byte = ricevi_messaggio_tcp(socket_tcp);
	if(num_byte == 0){
		printf("ERRORE: connessione chiusa dal server.'\nEsecuzione !quit...\n");
		comando_quit();
	}
	//stampo l'esito
	printf("%s\n\n",buffer);
	if(stringa_inizia_con(buffer,"ERRORE")){
	//esito negativo
		pulizia_username();	
	}else{
	//esito positivo
		ricevi_messasggi_offline();
	}
}

void comando_help(){
	stampa_comandi();
}

void comando_non_valido(){
	printf("Comando non riconosciuto.\n\n");
}

int main(int num_args, char* args[]){
	/*DEFINIZIONE VARIABILI*/
	int fdmax;
	fd_set set_principale;
    fd_set set_lettura;
	/*FINE DEFINIZIONE VARIABILI*/
	/*LETTURA PARAMETRI*/
	if(num_args != 5){
		printf("ERRORE: Numero dei parametri non valido.\n");
		printf("Usage: %s <IP_LOCALE> <PORTA_LOCALE> <IP_SERVER> <PORTA_SERVER>\n",args[0]);
		printf("Chiusura programma.\n\n");
		return -1;
	}
	inizializza_variabili_globali(args);
	/*FINE LETTURA PARAMETRI*/
	
	/* Azzero i set */
    FD_ZERO(&set_principale);
    FD_ZERO(&set_lettura);
    
    FD_SET(socket_udp, &set_principale);
    FD_SET(0, &set_principale);//socket standard input
	
	fdmax = socket_udp;
	
	connessione_server_tcp();
	
	//stampa_parametri();
	stampa_comandi();
	while(1){
		int test;
		int i;
		pulizia_buffer();
		printf("%s>",username);
		//TODO stampare quello che è rimasto nello stdin
		/*if(stdin->_IO_read_ptr != NULL){
			printf("%s",stdin->_IO_read_ptr);
		}*/
		fflush(stdout);
		set_lettura = set_principale;
		test = select(socket_udp + 1, &set_lettura, NULL, NULL, NULL);
		if(test == -1){
			perror("ERRORE select(): ");
		}
		for(i = 0; i <= fdmax; i++){
			if(FD_ISSET(i, &set_lettura)){
				if(i == 0){	
					//socket STDIN
					fgets(buffer, sizeof(buffer), stdin);
					strtok(buffer, "\n");
					/*
					!help
					!register <username>
					!deregister
					!who
					!send username
					!quit
					*/
					if(stringa_inizia_con(buffer,"!send ")){
						comando_send();
					}else if(stringa_inizia_con(buffer,"!who")){
						comando_who();
					}else if(stringa_inizia_con(buffer,"!register ")){
						comando_register();
					}else if(stringa_inizia_con(buffer,"!deregister")){
						comando_deregister();
					}else if(stringa_inizia_con(buffer,"!help")){
						comando_help();
					}else if(stringa_inizia_con(buffer,"!quit")){
						comando_quit();
					}else{//comando non valido
						comando_non_valido();
					}
				}else{
					//socket_udp
					ricevi_messaggio_udp(socket_udp);
				}
			}
		}
	}
	
return 0;
}
