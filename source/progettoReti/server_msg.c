#include"libreria_comune.h"
#include<time.h> //per la select()

/*DEFINIZIONE I GLOBALI*/
	/*STRUTTURE PER I MESSAGGI*/
	struct messaggio
	{
		char messaggio[DIM_BUFFER];
		struct messaggio* prossimo;
	};
	/**/	
	/*STRUTTURA PER GLI USERNAME REGISTRATI*/
	struct dati_utente
	{
		char username[DIM_USERNAME];
		char ip_utente[DIM_IP];
		char porta_utente[DIM_NUM_PORTA];
		int socket_connesso;
		struct messaggio* messaggi;
		struct dati_utente* pun_prossimo;
	};
	struct dati_utente* utenti_registrati;
	/*FINE STRUTTURA UTENTI REGISTRARI*/
	int numero_porta;	
	
	fd_set set_principale;
	fd_set set_lettura;
	int descrittore_massimo;
	
	struct sockaddr_in st_indirizzo_locale;
	struct sockaddr_in st_indirizzo_client;
	
	int socket_ascolto;
	
	int num_byte;
	int lunghezza_stringa;
/*FINE DEFINIZIONE VARIABILI GLOBALI*/

void log_socket(int socket,char* stringa_da_stampare){
	printf("[%d]%s\n",socket,stringa_da_stampare);
}

void inizializza_stuttura_indirizzo_locale(){
	st_indirizzo_locale.sin_family = AF_INET;
	st_indirizzo_locale.sin_addr.s_addr = INADDR_ANY;
	st_indirizzo_locale.sin_port = htons(numero_porta);
}

void inizializza_socket_ascolto(){
	socket_ascolto = socket(AF_INET,SOCK_STREAM,0);
	if(socket_ascolto == -1){
		perror("ERRORE socket() nella creazione del socket di ascolto: ");
		exit(-1);
	}
	if(bind(socket_ascolto, (struct sockaddr*)&st_indirizzo_locale, sizeof(st_indirizzo_locale)) == -1){
		perror("ERRORE bind(): ");
		exit(-1);
	}
	if(listen(socket_ascolto,10)){
		perror("ERRORE listen(): ");
		exit(-1);
	}
	
	FD_SET(socket_ascolto, &set_principale);//aggiorno il socket d'ascolto al set principale
	descrittore_massimo = socket_ascolto;//tengo traccia del socket con l'id più alto 
	
}

struct dati_utente* cerca_utente_socekt(int socket){
	struct dati_utente* utente;
	for(utente = utenti_registrati; utente != NULL ; utente = utente->pun_prossimo){
		if(utente->socket_connesso == socket){
			return utente;
		}
	}
	return NULL;

}

struct dati_utente* cerca_utente_username(char* username){
	struct dati_utente* utente;
	for(utente = utenti_registrati; utente != NULL ; utente = utente->pun_prossimo){
		if(strcmp(username, utente->username)==0){
			return utente;
		}
	}
	return NULL;

}

void utente_offline(int socket_connesso){
	struct dati_utente* utente;
	utente = cerca_utente_socekt(socket_connesso);
	if(utente != NULL){
		memset(utente->ip_utente,0,sizeof(utente->ip_utente));
		memset(utente->porta_utente,0,sizeof(utente->porta_utente));
		utente->socket_connesso = -1;
		printf("[%d]",socket_connesso);
		printf("L'utente <%s> è andato offline.\n",utente->username);
	}else{
		printf("[%d]",socket_connesso);
		printf("Il client non registrato è andato offline.\n");
	}
	close(socket_connesso);
	FD_CLR(socket_connesso,&set_principale);
}

void inizializza_variabili_globali(char* args[]){
	utenti_registrati = NULL;
	numero_porta = atoi(args[1]);

	/*Azzeramento set*/
	FD_ZERO(&set_principale);
	FD_ZERO(&set_lettura);
	
	inizializza_stuttura_indirizzo_locale();
	inizializza_socket_ascolto();
	printf("Server pronto a ricevere sulla porta <%d>.\n",numero_porta);
}

struct dati_utente* crea_utente(char* username,char* ip_utente,char* numero_porta, int socket_connesso){
	struct dati_utente* nuovo_utente;
		//alloco in memoria dinamica una struttura
	nuovo_utente = malloc(sizeof(struct dati_utente));
	if(nuovo_utente == NULL){
		log_socket(socket_connesso,"!ATTENZIONE! non è stata allocata memoria dinamica al nuovo utente, non è stato possibile registrarlo.");
		return NULL;
	}
	//pulisco la stuttura
	memset(nuovo_utente,0,sizeof(struct dati_utente));
	/*SETTO I CAMPI*/
	strcpy(nuovo_utente->username,username);//username
	strcpy(nuovo_utente->ip_utente,ip_utente);
	strcpy(nuovo_utente->porta_utente,numero_porta);
	nuovo_utente->socket_connesso = socket_connesso;
	nuovo_utente->messaggi = NULL;
	nuovo_utente->pun_prossimo = NULL;
	return nuovo_utente;
}

struct dati_utente* registra_utente(char* username,char* ip_utente,char* numero_porta, int socket_connesso ){
	int test;
	struct dati_utente* nuovo_utente;
	struct dati_utente* ultimo;
	struct dati_utente* penultimo;
	penultimo = utenti_registrati;
	ultimo = utenti_registrati;
	//se pila vuota inserisco in testa
	if(utenti_registrati == NULL){
		goto registra_in_testa;
	}
	//punto alla testa
	
	for(; ultimo != NULL;penultimo=ultimo, ultimo=ultimo->pun_prossimo){
		//vedo se l'username che inserisco è alfabeticamente minore
		test = strcmp(username, ultimo->username);
		//printf("[DEBUG]username: <%s> username-lista: <%s> test: %d\n",username,ultimo->username,test);
		if(test < 0){
			//è più piccolo di quello controllato -> lo inserisco
			if(ultimo == penultimo){
				//sono ancora alla testa
				goto registra_in_testa;
			}else{
				//sono nel mezzo alla lista
				goto registra_in_mezzo;
			}
		}
		if(test == 0){
			//se l'username è presente
			if(ultimo->socket_connesso == -1){
				//era offline -> lo porto online
				goto ritorno_online;	
			}else{
				//è presente un utente con lo stesso nome online -> lo blocco
				goto utente_presente;
				
			}
		}
	}
registra_in_mezzo:
	nuovo_utente = crea_utente(username,ip_utente,numero_porta,socket_connesso);
	if(nuovo_utente == NULL){
		return NULL;
	}
	nuovo_utente->pun_prossimo = ultimo;
	penultimo->pun_prossimo = nuovo_utente;
	goto registrazione_successo;
	
registra_in_testa:
	nuovo_utente = crea_utente(username,ip_utente,numero_porta,socket_connesso);
	if(nuovo_utente == NULL){
		return NULL;
	}
	nuovo_utente->pun_prossimo = ultimo;
	utenti_registrati = nuovo_utente;
	//goto registrazione_successo;
	
registrazione_successo:
	printf("[%d]",socket_connesso);
	printf("Utente <%s> registrato con successo.\n",username);
	strcpy(buffer,"OK: Utente registrato con successo.");	
	return nuovo_utente;
	
ritorno_online:
	strcpy(ultimo->ip_utente,ip_utente);
	strcpy(ultimo->porta_utente,numero_porta);
	ultimo->socket_connesso = socket_connesso;
	printf("[%d]",socket_connesso);
	printf("Utente <%s> tornato online.\n",username);
	strcpy(buffer,"OK: Utente tornato online.");	
	return ultimo;	
	
utente_presente:
	printf("[%d]",socket_connesso);
	printf("ERRORE: Utente <%s> già registrato ed online.\n",username);
	strcpy(buffer,"ERRORE: Utente già registrato ed online.");	
	return NULL;
}

struct dati_utente* estrai_utente_per_socekt(int socket){
	struct dati_utente* ultimo;
	struct dati_utente* penultimo;
	ultimo = utenti_registrati;
	penultimo = utenti_registrati;
	
	for(; ultimo != NULL; penultimo = ultimo , ultimo=ultimo->pun_prossimo){
		if(ultimo->socket_connesso == socket){
			//socket registrato trovato
			if(ultimo == penultimo){
				//sono in testa
				utenti_registrati = ultimo->pun_prossimo;
				return ultimo;
			}else{
				//sono nel mezzo
				penultimo->pun_prossimo = ultimo->pun_prossimo;
				return ultimo;
			}
		}
	}
	//fuori dal ciclo non ho trovato il socket
	return NULL;
	
}

void accetta_nuova_connessione(){
	socklen_t lun_indirizzo;
	int nuovo_socket;
	lun_indirizzo = sizeof(st_indirizzo_client);
	//accetto la connessione
	nuovo_socket = accept(socket_ascolto, (struct sockaddr*)&st_indirizzo_client, &lun_indirizzo);
	if(nuovo_socket == -1){
		perror("ERRORE accept() sulla nuova connessione: ");
		exit(-1);
	}
	//aggiungo il nuovo socket al set principale per controllarlo successivamente
	FD_SET(nuovo_socket,&set_principale);
	//se il suo id è maggiore aggiorno anche il descrittore_massimo
	if(nuovo_socket>descrittore_massimo){
		descrittore_massimo = nuovo_socket;
	}
	printf("[%d]",nuovo_socket);
	printf("Nuovo client connesso.\n");
}

struct messaggio* crea_messaggio(char* messaggio){
	struct messaggio* m;
	m = malloc(sizeof(struct messaggio));
	if(m == NULL){
		printf("!ATTENZIONE! non è stata allocata memoria dinamica al nuovo messaggio, non è stato possibile salvarlo.\n");
		return NULL;
	}
	memset(m,0,sizeof(struct messaggio));
	strcpy(m->messaggio, messaggio);
	m->prossimo = NULL;
	return m;
}

int inserisci_messaggio(struct messaggio** coda_messaggi, char* messaggio){
	//inserisco in coda
	struct messaggio* m;
	struct messaggio* scorri;
	m = crea_messaggio(messaggio);
	if(m == NULL){
		return 0;
	}
	if((*coda_messaggi) == NULL){
		(*coda_messaggi) = m;
		return 1;
	}
	for(scorri = (*coda_messaggi);
		scorri->prossimo !=NULL; 
		scorri=scorri->prossimo){
	
	}
	scorri->prossimo = m;
	return 1;
	
}

struct messaggio* estrai_messaggio(struct messaggio** coda_messaggi, int* ultimo){
	//estraggo dalla testa
	struct messaggio* m;
	if((*coda_messaggi) == NULL){
		//nessun messaggio
		(*ultimo) = 0;
		return NULL;
	}
	
	m = (*coda_messaggi);
	(*coda_messaggi) = (*coda_messaggi)->prossimo;
	
	if((*coda_messaggi) == NULL){
	//quello estratto è l'ultimo messsaggio'
		(*ultimo) = 0;
	}else{
	//altrimenti ce n'è un altro
		(*ultimo) = 1;
	}
	return m;
}

void elimina_utente(struct dati_utente* utente){
	struct messaggio* m;
	int useless;
	while((m = estrai_messaggio(&utente->messaggi,&useless)) != NULL){
		free(m);
	}
	free(utente);
}

void manda_messaggi_offline(struct dati_utente* utente){
	int ultimo;
	struct messaggio* m;
	
	while(1){
		pulizia_buffer();
		m = estrai_messaggio(&utente->messaggi, &ultimo);
		if(m == NULL){
			//nessun messaggio
			strcpy(buffer,"0");
			invia_messaggio_tcp(utente->socket_connesso);
			return;
		}
		//ultimo è sempre 1 o 0 ed occupa un carattere
		//il messaggio può esere massimo DIM_BUFFER-2 grazie alla send() del client
		sprintf(buffer,"%d%s",ultimo,m->messaggio);
		invia_messaggio_tcp(utente->socket_connesso);
		free(m);
		if(ultimo == 0){
			return;
		}
	}
}

void comando_send(int socket_connesso){
	struct dati_utente* utente;
	char username[DIM_USERNAME];
	memset(username,0,sizeof(username));
	//estraggo il comando
	estrai_parola(username,buffer);
	if(strcmp(username,"!send")!=0){
		printf("[%d]",socket_connesso);
		printf("ERRORE: comando <!send> non corretto\n" );
		/*ESITO NEGATIVO -> rispondo e finisco*/
		strcpy(buffer,"ERRORE: il comando ricevuto non era corretto.");	
		invia_messaggio_tcp(socket_connesso);
		return;
	}
	memset(username,0,sizeof(username));
	estrai_parola(username,buffer);
	if(strlen(username)>DIM_USERNAME-1){
		/*ESITO NEGATIVO -> rispondo e finisco*/
		pulizia_buffer();
		strcpy(buffer,"ERRORE: username troppo grande.");	
		invia_messaggio_tcp(socket_connesso);
		return;
	}
	printf("[%d]",socket_connesso);
	printf("Ricevuto comando <!send %s>.\n",username );
	utente = cerca_utente_username(username);
	if(utente == NULL){
		printf("[%d]",socket_connesso);
		printf("ERRORE: username <%s> non registrato.\n",username );
		pulizia_buffer();
		sprintf(buffer,"ERRORE: utente <%s> non registrato.",username);
		invia_messaggio_tcp(socket_connesso);
		return;
	}
	if(utente->socket_connesso == -1){
	//OFFLINE
		pulizia_buffer();
		strcpy(buffer,"OFFLINE");
		invia_messaggio_tcp(socket_connesso);
		//aspetto il messaggio da salvare OFFLINE
		if(ricevi_messaggio_tcp(socket_connesso)==0){
			utente_offline(socket_connesso);
			return;
		}
		inserisci_messaggio(&utente->messaggi,buffer);
		
	}else{
	//ONLINE
		pulizia_buffer();
		sprintf(buffer,"ONLINE %s %s",utente->ip_utente,utente->porta_utente);
		invia_messaggio_tcp(socket_connesso);
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
		->ultimo messaggio: server manda "1<messaggio>"
		->messaggio intermedio: server manda "2<messaggio>"
		//in caso di nessun messaggio manda comunque "1"
*/
void comando_register(int socket_connesso){
	struct dati_utente* utente;
	char username[DIM_USERNAME];
	char ip_utente[DIM_IP];
	char numero_porta[DIM_NUM_PORTA];
	memset(ip_utente,0,sizeof(ip_utente));
	memset(username,0,sizeof(username));
	memset(numero_porta,0,sizeof(numero_porta));
	//estraggo il comando
	estrai_parola(username,buffer);
	if(strcmp(username,"!register")!=0){
		printf("[%d]",socket_connesso);
		printf("ERRORE: comando <!register> non corretto\n" );
		/*ESITO NEGATIVO -> rispondo e finisco*/
		strcpy(buffer,"ERRORE: il comando ricevuto non era corretto.");	
		invia_messaggio_tcp(socket_connesso);
		return;
	}
	memset(username,0,sizeof(username));
	estrai_parola(username,buffer);
	if(strlen(username)>DIM_USERNAME-1){
		/*ESITO NEGATIVO -> rispondo e finisco*/
		strcpy(buffer,"ERRORE: username troppo grande.");	
		invia_messaggio_tcp(socket_connesso);
		return;
	}
	estrai_parola(ip_utente,buffer);
	estrai_parola(numero_porta,buffer);
	utente = registra_utente(username,ip_utente,numero_porta,socket_connesso);
	//la registra_utente prepara l'esito
 	invia_messaggio_tcp(socket_connesso);
	if(utente == NULL){
		//errore nella registrazione
		return;
	}//else
	manda_messaggi_offline(utente);
	return;
}

int prepara_messaggio_utenti_registrati(char* stringa, struct dati_utente** lista){
	int lunghezza_raggiunta;
	int lunghezza_stringa;
	char utente[DIM_USERNAME+10];
	
	strcpy(stringa,"0");
	lunghezza_raggiunta = 1;
	
	if((*lista) == NULL){	
		return 0;
	}
	for(;(*lista)!=NULL;(*lista)=(*lista)->pun_prossimo){
		memset(utente,0,sizeof(utente));
		strcpy(utente,"\t");
		strcat(utente, (*lista)->username);
		if((*lista)->socket_connesso == -1){
			strcat(utente," (offline)\n");
		}else{
			strcat(utente," (online)\n");
		}
		lunghezza_stringa = strlen(utente);
		
		if(lunghezza_raggiunta+lunghezza_stringa<DIM_BUFFER-1){
			strcat(stringa,utente);
			lunghezza_raggiunta = lunghezza_raggiunta + lunghezza_stringa;
		}else{
			stringa[0] = '1';
			return 1;
		}
	}
	return 0;
	
	
}
/*
PROTOCOLLO:
	il server manda tanti messaggi finchè ci sono username da inserire
	se la stringa non dovesse contenerli, manda i rimanenti in un secondo messaggio
	
	se la stringa inizia con 0 è l'ultimo messaggio, se iniza con 1 ce ne sono altri
*/
void comando_who(int socket_da_gestire){
	char stringa[DIM_BUFFER];
	int test;
	struct dati_utente* lista;
	lista = utenti_registrati;
	
	if(lista == NULL){
		pulizia_buffer();
		strcpy(buffer,"0\tNESSUN UTENTE REGISTRATO.\n");
		invia_messaggio_tcp(socket_da_gestire);
		return;
	}
	
	while(1){
		pulizia_buffer();
		memset(stringa,0,sizeof(stringa));
		
		test = prepara_messaggio_utenti_registrati(stringa,&lista);
		strcpy(buffer,stringa);
		invia_messaggio_tcp(socket_da_gestire);
		
		if(test==0){
			return;
		}
	}
	
}

void comando_deregister(int socket_connesso){
	struct dati_utente* utente;
	utente = estrai_utente_per_socekt(socket_connesso);
	pulizia_buffer();
	if(utente != NULL){
		//deregistrazione	
		printf("[%d]",socket_connesso);
		printf("Deregistrazione utente <%s>\n",utente->username );
		elimina_utente(utente);
		strcpy(buffer,"Deregistrazione avvenuta con successo.");
		invia_messaggio_tcp(socket_connesso);
	}else{
		strcpy(buffer,"ERRORE: sembra che tu non ti sia ancora registrato.");
		invia_messaggio_tcp(socket_connesso);
	}
}

void gestisci_connessione(int socket_da_gestire){
	int num_byte;
	pulizia_buffer();
	num_byte = ricevi_messaggio_tcp(socket_da_gestire);
	if(num_byte == 0){
		utente_offline(socket_da_gestire);
		return;
	}
	if(stringa_inizia_con(buffer,"!send")){
		comando_send(socket_da_gestire);
	}else if(stringa_inizia_con(buffer,"!who")){
		comando_who(socket_da_gestire);
	}else if(stringa_inizia_con(buffer,"!register")){
		comando_register(socket_da_gestire);
	}else if(stringa_inizia_con(buffer,"!deregister")){
		comando_deregister(socket_da_gestire);
	}else{
		printf("[%d]",socket_da_gestire);
		printf("!ATTENZIONE! non è stato riconosciuto il comando, non dovrebbe mai succedere.\n");
	}
}

int main(int num_args, char* args[]){
	int i;
	
	if(num_args != 2){
		printf("\nERRORE: Numero dei parametri non valido.\nUsage: %s <NUMERO_PORTA>\nchiusura programma...\n",args[0]);
		exit(-2);
	}
	inizializza_variabili_globali(args);
	
	for(;;){
		pulizia_buffer();
		set_lettura = set_principale;//copio per la modifica
		//mi metto in attesa finchè un socket non è pronto
		select(descrittore_massimo+1, &set_lettura, NULL, NULL, NULL);
		/*CONTROLLO TUTTO IL SET*/
		for(i=0; i<= descrittore_massimo; i++){
			//cerco queli pronti
			if(FD_ISSET(i,&set_lettura)){
				//se è pronto il socket d'ascolto allora c'è una nuova connessione
				if(i == socket_ascolto){
					accetta_nuova_connessione();
				}else{
					//è un altro socket
					gestisci_connessione(i);
				}
			}
		}
	}
	
return 0;
}


