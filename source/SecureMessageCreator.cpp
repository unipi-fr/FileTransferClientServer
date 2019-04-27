#include "SecureMessageCreator.h"
#include <iostream>
using namespace std;

DH* SecureMessageCreator::get_dh2048(void)
{
    static unsigned char dhp_2048[] = {
        0xF2, 0x78, 0x9C, 0x34, 0xE2, 0xA6, 0x8A, 0x74, 0xC6, 0x6F,
        0xB3, 0xF0, 0xA3, 0x87, 0xB7, 0x6B, 0xF9, 0xAC, 0x48, 0x26,
        0x16, 0x3E, 0x2F, 0x4E, 0xEC, 0xE2, 0xE9, 0x3C, 0x44, 0xD7,
        0x73, 0x11, 0x0D, 0xA3, 0xAB, 0xDC, 0xF4, 0x3E, 0xE3, 0x24,
        0x81, 0x39, 0xD6, 0x8B, 0x7E, 0x05, 0x49, 0x73, 0x2E, 0x79,
        0x96, 0xDD, 0x78, 0xF8, 0x86, 0x21, 0xA8, 0xE5, 0x56, 0xC9,
        0x92, 0x1C, 0xE8, 0x5D, 0xA3, 0x1F, 0x4D, 0xF0, 0xF7, 0xC2,
        0xAA, 0x7A, 0x22, 0x1E, 0x3F, 0x0A, 0x53, 0xEB, 0xE9, 0x66,
        0x97, 0x59, 0x50, 0x46, 0x20, 0xBC, 0x3E, 0x6B, 0x5E, 0x5B,
        0x5B, 0xC1, 0x7B, 0x91, 0xD5, 0x12, 0x8B, 0xE2, 0x54, 0x08,
        0xA6, 0x3C, 0x95, 0x84, 0x3A, 0xBD, 0xDE, 0xFA, 0x14, 0x49,
        0x42, 0x4A, 0xBF, 0xF1, 0x28, 0x26, 0xFB, 0x1C, 0xE0, 0xDB,
        0x88, 0x35, 0x1E, 0xE8, 0x3F, 0x86, 0x42, 0x56, 0x38, 0xB8,
        0x6C, 0xD2, 0xE2, 0xFF, 0x90, 0xD2, 0x30, 0x7C, 0x13, 0x21,
        0x3C, 0x9F, 0xC2, 0x6A, 0xBA, 0x4F, 0x9A, 0x8B, 0x51, 0x28,
        0x62, 0x3E, 0xF6, 0xBD, 0x53, 0x0B, 0x57, 0x41, 0x1C, 0x25,
        0x19, 0x9E, 0x06, 0x49, 0xDF, 0xC8, 0x27, 0xCC, 0x69, 0x22,
        0x87, 0x80, 0x37, 0xEA, 0x7F, 0xD0, 0x04, 0xF3, 0x1A, 0x0C,
        0xD0, 0x48, 0xB3, 0x2F, 0x9F, 0x22, 0xEF, 0xFE, 0x2B, 0x3C,
        0x1C, 0x52, 0xCD, 0xF4, 0x85, 0x78, 0x71, 0xAB, 0x2C, 0xA2,
        0x53, 0xBC, 0xD6, 0x2E, 0x0A, 0x83, 0xC7, 0x85, 0xAD, 0x6C,
        0x89, 0x6F, 0x6B, 0x89, 0x63, 0x1B, 0x4C, 0x52, 0x35, 0x4D,
        0x6F, 0x5D, 0xEF, 0xD4, 0x5C, 0x64, 0xC7, 0x64, 0xAC, 0x7E,
        0x9B, 0x92, 0x8C, 0xA0, 0xB3, 0xFC, 0x00, 0x4D, 0x11, 0x09,
        0x2D, 0x30, 0xCD, 0xAE, 0xB9, 0x6C, 0xAF, 0x18, 0xD1, 0x2C,
        0xD6, 0x7E, 0x41, 0x71, 0x1A, 0x53
    };
    static unsigned char dhg_2048[] = {
        0x02
    };
    DH *dh = DH_new();
    BIGNUM *p, *g;

    if (dh == NULL)
        return NULL;
    p = BN_bin2bn(dhp_2048, sizeof(dhp_2048), NULL);
    g = BN_bin2bn(dhg_2048, sizeof(dhg_2048), NULL);
    if (p == NULL || g == NULL || !DH_set0_pqg(dh, p, NULL, g)) {
        DH_free(dh);
        BN_free(p);
        BN_free(g);
        return NULL;
    }
    return dh;
}


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

  //Init,Update,Finalise digest
  HMAC_Init_ex(mdctx, _hmac_key, _hmacKeySize, _md, NULL);

  while(HMAC_Update(mdctx, (unsigned char*) inBuf, inLen) == 1) {}

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

  //Inizializzione
  EVP_EncryptInit(context, EVP_aes_128_ecb(), _encrypt_key, iv);

  //Encrypt update
  while(EVP_EncryptUpdate(context, chipertext, &len, plaintext, plainTextLen) == 1){
    chiperTextLen += len;
  }
  
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
  while(EVP_DecryptUpdate(context, decryptedText, &len, cipherText, cipherTextLen) == 1){
    decriptedTextLen += len;
  }

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
  return true;
}