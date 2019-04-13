#include"my_crypto_lib.h"

unsigned char key_hmac[]="0123456789012345678901234567891";
unsigned char encrypt_key[]="0123456789012345";

unsigned char* sign(unsigned char *inBuf, int inLen, int &hashSize){
    unsigned char* outBuf;
    
    size_t key_hmac_size = sizeof(key_hmac);
    
    //Dichiariamo la funzione che vogliamo
    const EVP_MD* md = EVP_sha256();
    
    hashSize = EVP_MD_size(md);
    
    outBuf = (unsigned char*)malloc(hashSize);
    
    //Creazione del messaggio contesto digest
    HMAC_CTX* mdctx;
    mdctx = HMAC_CTX_new();
    
    //Init,Update,Finalise digest
    HMAC_Init_ex(mdctx, key_hmac, key_hmac_size, md, NULL);
    HMAC_Update(mdctx, (unsigned char*) inBuf, inLen);
    HMAC_Final(mdctx, outBuf, (unsigned int*) &hashSize);
    
    //Delete context
    HMAC_CTX_free(mdctx);
    
    return outBuf;
}

int encrypt(unsigned char* plaintext, int plainTextLen, unsigned char* iv, unsigned char* chipertext){
    EVP_CIPHER_CTX* context;
    
    int len;
    int chiperTextLen;
    
    /*Creazione del contesto*/
    context = EVP_CIPHER_CTX_new();
    
    //Inizializzione
    EVP_EncryptInit(context, EVP_aes_128_ecb(), encrypt_key, iv);
    
    //Encrypt update: una chiamata perchè il messaggio è corto
    EVP_EncryptUpdate(context, chipertext, &len, plaintext, plainTextLen);
    chiperTextLen = len;
    
    //Encrypt final: finalizza la cifratura
    EVP_EncryptFinal(context, chipertext+len, &len);
    chiperTextLen += len;
    
    EVP_CIPHER_CTX_free(context);
    
    return chiperTextLen;
}

int decrypt(unsigned char* cipherText, int cipherTextLen, unsigned char* iv, unsigned char* decryptedText){
    EVP_CIPHER_CTX* context;
    
    int len;
    int decriptedTextLen;
    
    /*Creazione del contesto*/
    context = EVP_CIPHER_CTX_new();
    
    //Inizializzione
    EVP_DecryptInit(context, EVP_aes_128_ecb(), encrypt_key, iv);
    
    //Encrypt update: una chiamata perchè il messaggio è corto
    EVP_DecryptUpdate(context, decryptedText, &len, cipherText, cipherTextLen);
    decriptedTextLen = len;
    
    //Encrypt final: finalizza la cifratura
    EVP_DecryptFinal(context, decryptedText+len, &len);
    decriptedTextLen += len;
    
    EVP_CIPHER_CTX_free(context);
    
    return decriptedTextLen;
}

bool check_hash(unsigned char *inBuf, int bufLen, unsigned char *hash){
    unsigned char* calculatedHash;
    int hashSize;
    calculatedHash = sign(inBuf,bufLen,hashSize);
    
    return memcmp(hash, calculatedHash, hashSize) == 0;
}