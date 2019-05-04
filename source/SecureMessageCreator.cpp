#include "SecureMessageCreator.h"
#include <iostream>
#include <unistd.h>
#include <string.h>
using namespace std;

SecureMessageCreator::SecureMessageCreator(){
  //declaring the hash function we want to use
  _md = EVP_sha256();
  //generation keys
  _hmacKeySize = 32;
  _hmac_key=(unsigned char*)malloc(_hmacKeySize);
  memset(_hmac_key, '5',_hmacKeySize);

  _encriptKeySize = 16;
  _encrypt_key=(unsigned char*)malloc(_encriptKeySize);
  memset(_encrypt_key, '9',_encriptKeySize);

  //size of the digest
  _hashSize = EVP_MD_size(_md);
}

unsigned char* SecureMessageCreator::sign(unsigned char *inBuf, int inLen){
  unsigned char* outBuf;

  outBuf = (unsigned char*)malloc(_hashSize);

  //Creazione del messaggio contesto digest
  HMAC_CTX* mdctx;
  mdctx = HMAC_CTX_new();
  //cout<<"[DEBUG|sign] inizialization"<<endl;
  //Init,Update,Finalise digest
  HMAC_Init_ex(mdctx, _hmac_key, _hmacKeySize, _md, NULL);

  if(!HMAC_Update(mdctx, (unsigned char*) inBuf, inLen)){
    //errore
    cout<<"[SUPER ERRORE HMAC]"<<endl;
  }


  HMAC_Final(mdctx, outBuf, (unsigned int*) &_hashSize);

  //Delete context
  HMAC_CTX_free(mdctx);

  return outBuf;
}

int SecureMessageCreator::encrypt(unsigned char* plaintext, int plainTextLen, unsigned char* iv, unsigned char* chipertext){
  EVP_CIPHER_CTX* context;

  int len;
  int chiperTextLen = 0;

  /*Creazione del contesto*/
  context = EVP_CIPHER_CTX_new();
  //cout<<"[DEBUG|encrypt] Inizialization "<<endl;
  //Inizializzione
  EVP_EncryptInit(context, EVP_aes_128_ecb(), _encrypt_key, iv);
  int res = 5;
  //Encrypt update
    if(!EVP_EncryptUpdate(context, chipertext, &len, plaintext, plainTextLen)){
      cout<<"[SUPER ERRORE Encrypt]"<<endl;
    }
    chiperTextLen += len;
    
  //cout<<"[DEBUG|encrypt] final "<<endl;
  //Encrypt final: finalizza la cifratura
  EVP_EncryptFinal(context, chipertext+len, &len);
  chiperTextLen += len;

  EVP_CIPHER_CTX_free(context);

  return chiperTextLen;
}

int SecureMessageCreator::decrypt(unsigned char* cipherText, int cipherTextLen, unsigned char* iv, unsigned char* decryptedText){
  EVP_CIPHER_CTX* context;

  int len;
  int decriptedTextLen = 0;

  /*Creazione del contesto*/
  context = EVP_CIPHER_CTX_new();

  //Inizializzione
  EVP_DecryptInit(context, EVP_aes_128_ecb(), _encrypt_key, iv);

  //Encrypt update
  if(!EVP_DecryptUpdate(context, decryptedText, &len, cipherText, cipherTextLen)){
      cout<<"[SUPER ERRORE Encrypt]"<<endl;
  }
  decriptedTextLen += len;

  //Encrypt final: finalizza la cifratura
  EVP_DecryptFinal(context, decryptedText+len, &len);
  decriptedTextLen += len;

  EVP_CIPHER_CTX_free(context);

  return decriptedTextLen;
}

bool SecureMessageCreator::check_hash(unsigned char *inBuf, int bufLen, unsigned char *hash){
  unsigned char* calculatedHash;
  calculatedHash = sign(inBuf,bufLen);
  //cout<<"[calculatedHash]"<<calculatedHash<<endl;
  bool result = CRYPTO_memcmp(hash, calculatedHash, _hashSize) == 0;
  free(calculatedHash);
  return result;
}

int SecureMessageCreator::EncryptAndSignMessage(unsigned char* plainText, int plainTextLen, unsigned char** secureText){
  //cout<<"[plainText]"<<plainText<<endl;

  unsigned char *hashSign = sign(plainText, plainTextLen);

  //cout<<"[HASH SIGN]"<<hashSign<<endl;

  unsigned char *messageToEncrypt = (unsigned char*)malloc(plainTextLen + _hashSize);

  memcpy(messageToEncrypt, hashSign, _hashSize);
  memcpy(messageToEncrypt + _hashSize, plainText, plainTextLen);

  //cout<<"[messageToEncrypt] "<<messageToEncrypt<<endl;

  int messageToEncryptLen = plainTextLen + _hashSize;
  *secureText = (unsigned char*)malloc(messageToEncryptLen + 16); //consider eventually padding

  int secureTextLen = encrypt(messageToEncrypt, messageToEncryptLen, NULL, *secureText);

  //cout<<"[secureText]"<<(*secureText)<<endl;

  free(messageToEncrypt);
  free(hashSign);
  cout<<flush;
  return secureTextLen;
}

bool SecureMessageCreator::DecryptAndCheckSign(unsigned char* secureText, int secureTextLen, unsigned char** plainText, int &plainTextLen){
  //cout<<"[SecureText]"<<secureText<<endl;

  unsigned char *decryptedText = (unsigned char*)malloc(secureTextLen);
  int decryptLen = decrypt(secureText, secureTextLen, NULL, decryptedText);
  //cout<<"[dectyptedText]"<<decryptedText<<endl;

  unsigned char *msg = decryptedText + _hashSize;
  unsigned char *hash = decryptedText;
  //cout<<"[msg]"<<msg<<endl;
  //cout<<"[hash]"<<hash<<endl;

  if(!check_hash(msg, decryptLen - _hashSize, hash)){
      cout<<"[ERRORE] firma non valida"<<endl;
    return false;
  }

  //cout<<"[Message from msg]"<<msg<<endl;

  plainTextLen = decryptLen - _hashSize;
  *plainText = (unsigned char*)malloc(plainTextLen);
  memcpy(*plainText,msg,plainTextLen);

  //cout<<"[Message form plainText]"<<msg<<endl;
  free(decryptedText);
  cout<<flush;
  return true;
}