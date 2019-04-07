#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <string.h>

unsigned char* sign(unsigned char *inBuf, int inLen, int &hashSize);
bool check_hash(unsigned char *inBuf, int bufLen, unsigned char *hash);
int encrypt(unsigned char* plaintext, int plainTextLen, unsigned char* iv, unsigned char* chipertext);
int decrypt(unsigned char* cipherText, int cipherTextLen, unsigned char* iv, unsigned char* decryptedText);
