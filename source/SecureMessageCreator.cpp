#include "SecureMessageCreator.h"
#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/x509_vfy.h>
#include <iostream>
#include <unistd.h>
#include <string.h>
using namespace std;

DH* SecureMessageCreator::get_dh2048(void)
{
  static unsigned char dhp_2048[] = {
    0x88, 0xA8, 0x42, 0x1A, 0x58, 0xBD, 0xB0, 0xD0, 0x72, 0x22, 0x8D, 0x6F, 0x89, 0xBC, 0x08, 0xC1, 0xCC, 0x7D, 0x4D, 0xB8,
    0xF9, 0x9A, 0x0A, 0x15, 0xCD, 0x17, 0x6C, 0x8A, 0xEE, 0x2D, 0x8F, 0x01, 0xF9, 0x63, 0xC7, 0x3B, 0x55, 0xD6, 0x83, 0x63,
    0xBB, 0x0D, 0x8B, 0x94, 0xAA, 0x8C, 0x33, 0x18, 0x24, 0x09, 0x3A, 0x57, 0xD0, 0xB6, 0x2D, 0x48, 0xEF, 0x0E, 0x8C, 0xBE,
    0x88, 0x3E, 0x55, 0xF6, 0xCE, 0x2A, 0xE2, 0x1A, 0x07, 0x79, 0x75, 0xFE, 0x6D, 0xDA, 0x07, 0xCF, 0x56, 0x06, 0xF4, 0x2B,
    0xFA, 0x44, 0xA5, 0xBE, 0x58, 0x57, 0x3A, 0xA1, 0x48, 0x78, 0xF1, 0xB3, 0xCF, 0x32, 0x57, 0x18, 0x77, 0x04, 0x6C, 0xCC,
    0xD2, 0x4D, 0x78, 0x86, 0x8E, 0x1B, 0xA8, 0x3D, 0xF6, 0x95, 0x5E, 0xA2, 0x04, 0xEE, 0xF2, 0xEF, 0xE6, 0x83, 0xB4, 0x5F,
    0x89, 0x21, 0x67, 0x98, 0x57, 0x9F, 0x38, 0xD7, 0x91, 0xAB, 0xDF, 0x71, 0xFC, 0x5A, 0xED, 0x14, 0x36, 0xE5, 0x3B, 0x61,
    0x2F, 0xC4, 0xCA, 0x37, 0x2F, 0xEE, 0xB1, 0x75, 0xA8, 0xF3, 0xCF, 0x48, 0x7B, 0xC2, 0x01, 0x21, 0x83, 0xE7, 0x48, 0x1E,
    0xCC, 0x7B, 0x2A, 0x81, 0x37, 0x8A, 0x64, 0xFF, 0x01, 0x93, 0x2D, 0x35, 0x4E, 0x4E, 0x68, 0x3E, 0x14, 0xD0, 0x66, 0x0D,
    0xB6, 0x5F, 0xA2, 0x2B, 0x41, 0xEE, 0xB0, 0xAA, 0x9F, 0x97, 0x01, 0xD5, 0x9C, 0x64, 0xDB, 0x53, 0x0D, 0xB6, 0xB2, 0xEA,
    0x3E, 0x72, 0x37, 0xEB, 0x56, 0x4D, 0x51, 0xFB, 0x50, 0x28, 0x65, 0x42, 0x7E, 0x6E, 0x55, 0x22, 0x53, 0xB6, 0xE9, 0x1D,
    0xE1, 0x9D, 0xBA, 0x22, 0x26, 0xBD, 0x96, 0x9D, 0x99, 0x49, 0x27, 0x8C, 0xEF, 0x1F, 0x30, 0x1A, 0xDF, 0xA8, 0x50, 0xCE,
    0xF2, 0xE3, 0x64, 0x35, 0xE2, 0x51, 0xF7, 0x0C, 0xE1, 0xB2, 0x6F, 0xBD, 0x36, 0x00, 0x57, 0xFB
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

SecureMessageCreator::SecureMessageCreator()
{
  //declaring the hash function we want to use
  _hashAlgorithm = EVP_sha256();
  _encryptAlgorithm = EVP_aes_128_ecb();

  _hmacKeySize = 32;
  _hmac_key = NULL;

  _encriptKeySize = 16;
  _encrypt_key = NULL;

  //size of the hash
  _hashSize = EVP_MD_size(_hashAlgorithm);

  generateKeys((unsigned char*)"ciao mamma come stai?",22);
}

bool SecureMessageCreator::generateKeys(unsigned char* inizializationKey, size_t ikSize){
  cout<<"[DEBUG] generating session and HMAC keys..."<<endl;
  size_t halfSize = ikSize/2;
  unsigned char* firstPart = inizializationKey;
  unsigned char* secondPart = inizializationKey + halfSize;

  unsigned char* tmpSha256 = (unsigned char*) malloc(SHA256_DIGEST_LENGTH);

  if(!simpleHash256(firstPart,halfSize,tmpSha256)){
    cout<<"[DEBUG] error computing simple hash for generating hash key"<<endl;
    free(tmpSha256);
    return false;
  }

  _hmac_key = (unsigned char *)malloc(_hmacKeySize);
  memcpy(_hmac_key, tmpSha256, _hmacKeySize);
  
  cout<<"[DEBUG] hash key:"<<endl;
  BIO_dump_fp(stdout,(char*)_hmac_key,_hmacKeySize);

  if(!simpleHash256(secondPart,ikSize-halfSize,tmpSha256)){
    cout<<"[DEBUG] error computing simple hash for generating hash key"<<endl;
    free(tmpSha256);
    return false;
  }
  _encrypt_key = (unsigned char *)malloc(_encriptKeySize);
  memcpy(_encrypt_key, tmpSha256, _encriptKeySize);
  cout<<"[DEBUG] session key:"<<endl;
  BIO_dump_fp(stdout,(char*)_encrypt_key,_encriptKeySize);

  free(tmpSha256);
  return true;
}

bool SecureMessageCreator::simpleHash256(unsigned char* input,size_t inputLenght, unsigned char* &output){
  SHA256_CTX context;
    if(!SHA256_Init(&context))
        return false;

    if(!SHA256_Update(&context, (unsigned char*)input, inputLenght))
        return false;

    if(!SHA256_Final(output, &context))
        return false;

    return true;
}

unsigned char *SecureMessageCreator::sign(unsigned char *inBuf, int inLen)
{
  unsigned char *outBuf;

  outBuf = (unsigned char *)malloc(_hashSize);

  //Creazione del messaggio contesto digest
  HMAC_CTX *mdctx;
  mdctx = HMAC_CTX_new();
  //cout<<"[DEBUG|sign] inizialization"<<endl;
  //Init,Update,Finalise digest
  HMAC_Init_ex(mdctx, _hmac_key, _hmacKeySize, _hashAlgorithm, NULL);

  if (!HMAC_Update(mdctx, (unsigned char *)inBuf, inLen))
  {
    //errore
    cout << "[SUPER ERRORE HMAC]" << endl;
  }

  HMAC_Final(mdctx, outBuf, (unsigned int *)&_hashSize);

  //Delete context
  HMAC_CTX_free(mdctx);

  return outBuf;
}

int SecureMessageCreator::encrypt(unsigned char *plaintext, int plainTextLen, unsigned char *iv, unsigned char *chipertext)
{
  EVP_CIPHER_CTX *context;

  int len;
  int chiperTextLen = 0;

  /*Creazione del contesto*/
  context = EVP_CIPHER_CTX_new();
  //cout<<"[DEBUG|encrypt] Inizialization "<<endl;
  //Inizializzione
  EVP_EncryptInit(context, _encryptAlgorithm, _encrypt_key, iv);
  int res = 5;
  //Encrypt update
  if (!EVP_EncryptUpdate(context, chipertext, &len, plaintext, plainTextLen))
  {
    cout << "[SUPER ERRORE Encrypt]" << endl;
  }
  chiperTextLen += len;

  //cout<<"[DEBUG|encrypt] final "<<endl;
  //Encrypt final: finalizza la cifratura
  EVP_EncryptFinal(context, chipertext + len, &len);
  chiperTextLen += len;

  EVP_CIPHER_CTX_free(context);

  return chiperTextLen;
}

int SecureMessageCreator::decrypt(unsigned char *cipherText, int cipherTextLen, unsigned char *iv, unsigned char *decryptedText)
{
  EVP_CIPHER_CTX *context;

  int len;
  int decriptedTextLen = 0;

  /*Creazione del contesto*/
  context = EVP_CIPHER_CTX_new();

  //Inizializzione
  EVP_DecryptInit(context, EVP_aes_128_ecb(), _encrypt_key, iv);

  //Encrypt update
  if (!EVP_DecryptUpdate(context, decryptedText, &len, cipherText, cipherTextLen))
  {
    cout << "[SUPER ERRORE Encrypt]" << endl;
  }
  decriptedTextLen += len;

  //Encrypt final: finalizza la cifratura
  EVP_DecryptFinal(context, decryptedText + len, &len);
  decriptedTextLen += len;

  EVP_CIPHER_CTX_free(context);

  return decriptedTextLen;
}

bool SecureMessageCreator::check_hash(unsigned char *inBuf, int bufLen, unsigned char *hash)
{
  unsigned char *calculatedHash;
  calculatedHash = sign(inBuf, bufLen);
  //cout<<"[calculatedHash]"<<calculatedHash<<endl;
  bool result = CRYPTO_memcmp(hash, calculatedHash, _hashSize) == 0;
  free(calculatedHash);
  return result;
}

int SecureMessageCreator::EncryptAndSignMessage(unsigned char *plainText, int plainTextLen, unsigned char **secureText)
{
  //cout<<"[plainText]"<<plainText<<endl;

  unsigned char *hashSign = sign(plainText, plainTextLen);

  //cout<<"[HASH SIGN]"<<hashSign<<endl;

  unsigned char *messageToEncrypt = (unsigned char *)malloc(plainTextLen + _hashSize);

  memcpy(messageToEncrypt, hashSign, _hashSize);
  memcpy(messageToEncrypt + _hashSize, plainText, plainTextLen);

  //cout<<"[messageToEncrypt] "<<messageToEncrypt<<endl;

  int messageToEncryptLen = plainTextLen + _hashSize;
  *secureText = (unsigned char *)malloc(messageToEncryptLen + 16); //consider eventually padding

  int secureTextLen = encrypt(messageToEncrypt, messageToEncryptLen, NULL, *secureText);

  //cout<<"[secureText]"<<(*secureText)<<endl;

  free(messageToEncrypt);
  free(hashSign);
  //cout << flush;
  return secureTextLen;
}

bool SecureMessageCreator::DecryptAndCheckSign(unsigned char *secureText, int secureTextLen, unsigned char **plainText, int &plainTextLen)
{
  //cout<<"[SecureText]"<<secureText<<endl;

  unsigned char *decryptedText = (unsigned char *)malloc(secureTextLen);
  int decryptLen = decrypt(secureText, secureTextLen, NULL, decryptedText);
  //cout<<"[dectyptedText]"<<decryptedText<<endl;

  unsigned char *msg = decryptedText + _hashSize;
  unsigned char *hash = decryptedText;
  //cout<<"[msg]"<<msg<<endl;
  //cout<<"[hash]"<<hash<<endl;

  if (!check_hash(msg, decryptLen - _hashSize, hash))
  {
    return false;
  }

  //cout<<"[Message from msg]"<<msg<<endl;

  plainTextLen = decryptLen - _hashSize;
  *plainText = (unsigned char *)malloc(plainTextLen);
  memcpy(*plainText, msg, plainTextLen);

  //cout<<"[Message form plainText]"<<msg<<endl;
  free(decryptedText);
  //cout << flush;
  return true;
}

EVP_PKEY* SecureMessageCreator::ExtractPublicKeyFromFile(const char* filename)
{
  EVP_PKEY* pubKey = NULL;
  FILE* file = fopen(filename,"r");

  if(!file){
      return NULL;
  }

  pubKey = PEM_read_PUBKEY(file,NULL,NULL,NULL);
  
  fclose(file);

  return pubKey;
}

EVP_PKEY* SecureMessageCreator::ExtractPrivateKey(const char* filename)
{
  EVP_PKEY* privKey;
  FILE* file = fopen(filename,"r");

  if(!file){
      return NULL;
  }

  privKey = PEM_read_PrivateKey(file,NULL,NULL,NULL);
  
  fclose(file);

  return privKey;
}

int SecureMessageCreator::ExctractSessionMesssage(unsigned char *cipherText, int cipherLen,unsigned char* encryptedKey, int encryptedKeyLen, 
    unsigned char *iv, EVP_PKEY* privKey, unsigned char *&plainText)
{
  plainText = (unsigned char*) malloc(cipherLen);
  int outLen, plainTextLen;

  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  int ret = EVP_OpenInit(ctx, EVP_aes_128_cbc(), encryptedKey, encryptedKeyLen, iv, privKey);
  if(ret == 0){
      cout<<"[ERROR] not possible inizialize decryption structures"<<endl;
      exit(-5);
  }

  EVP_OpenUpdate(ctx, plainText, &outLen, cipherText, cipherLen);
  plainTextLen = outLen;

  EVP_OpenFinal(ctx, plainText + plainTextLen, &outLen);
  if(ret == 0){
      cout<<"[ERROR] EVP_OpenFinal has crashed"<<endl;
      exit(-5);
  }
  plainTextLen += outLen;

  EVP_CIPHER_CTX_free(ctx);

  return plainTextLen;
}

int SecureMessageCreator::CreateSessionMessage(const char* plaintext, size_t plaintextSize, EVP_PKEY* pubKey, unsigned char* &encryptedKey, 
    int &encryptedKeySize,unsigned char* &iv, int &ivSize,unsigned char* &chipertext)
{
  encryptedKey = (unsigned char*) malloc(EVP_PKEY_size(pubKey));
  cout<<"[DEBUG|KeySize]"<<EVP_PKEY_size(pubKey)<<endl;

  chipertext = (unsigned char*) malloc(plaintextSize+16);
  int chipertextSize, outputSize;
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  ivSize = EVP_CIPHER_iv_length(EVP_aes_128_cbc());
  iv = (unsigned char*) malloc(ivSize);
  int ret = EVP_SealInit(ctx, EVP_aes_128_cbc(), &encryptedKey, &encryptedKeySize,iv, &pubKey, 1); 
  if(ret == 0){
      cout<<"[ERROR] not possible inizialize encryption structures"<<endl;
      exit(-5);
  }
  cout<<"[DEBUG|EnKeySize]"<<encryptedKeySize<<endl;
  EVP_SealUpdate(ctx,chipertext,&outputSize, (unsigned char*)plaintext,plaintextSize);
  chipertextSize = outputSize;

  EVP_SealFinal(ctx,chipertext+chipertextSize,&outputSize);
  chipertextSize+=outputSize;
  EVP_CIPHER_CTX_free(ctx);

  return chipertextSize;
} 

void SecureMessageCreator::caStoreInit(X509* cert, X509_CRL* crl){
    _store = X509_STORE_new();
}

bool SecureMessageCreator::verifyCertificate(X509* cert){
    if(_store == NULL){
      return false;
    }
    X509_STORE_CTX* ctx= X509_STORE_CTX_new();

    X509_STORE_CTX_init(ctx, _store, cert, NULL);
    int ret = X509_verify_cert(ctx);//return 1 on success

    X509_STORE_CTX_free(ctx);

    return ret==1;
}

X509* SecureMessageCreator::loadCertificateFromFile(const char* filename){
    X509* cert;
    FILE* file = fopen(filename, "r");

    if(!file){
        cerr<<"ERROR opening file"<<endl;
        return cert;
    }
    
    cert = PEM_read_X509(file, NULL, NULL, NULL);
    
    if(!cert){
        cerr<<"ERROR pem read x509"<<endl;
        return cert;
    }

    fclose(file);
    return cert;
}

bool SecureMessageCreator::addCertificateToStore(X509* cert){
  return X509_STORE_add_cert(_store,cert) == 1;
}

unsigned int SecureMessageCreator::sign(char* msg, int msgSize, EVP_PKEY* privKey, unsigned char* &signature)
{
	unsigned int signatureLen;

	signature = (unsigned char*) malloc(EVP_PKEY_size(privKey));

	EVP_MD_CTX* ctx = EVP_MD_CTX_new();
	
	EVP_SignInit(ctx, EVP_sha256());
	EVP_SignUpdate(ctx, (unsigned char*)msg, msgSize);
	EVP_SignFinal(ctx, signature, &signatureLen, privKey);

	EVP_MD_CTX_free(ctx);

	return signatureLen;
}

bool SecureMessageCreator::verify(unsigned char *msg, int msgSize, unsigned char *signature, int signatureLen, EVP_PKEY* pubKey)
{
	EVP_MD_CTX* ctx = EVP_MD_CTX_new();
	
	EVP_VerifyInit(ctx, EVP_sha256());
	EVP_VerifyUpdate(ctx, msg, msgSize);
	int ret = EVP_VerifyFinal(ctx, signature, signatureLen, pubKey);

	EVP_MD_CTX_free(ctx);
	return ret == 1;
}