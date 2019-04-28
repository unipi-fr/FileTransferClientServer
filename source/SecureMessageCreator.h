#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/bn.h>
#include <openssl/dh.h>

class SecureMessageCreator {
  private:
    unsigned char* _hmac_key;
    size_t _hmacKeySize;
    unsigned char* _encrypt_key;
    size_t _encriptKeySize;
    const EVP_MD* _md;
    int _hashSize; // Algoritmh used Sha-256
    unsigned char* sign(unsigned char *inBuf, int inLen);
    int encrypt(unsigned char* plainText, int plainTextLen, unsigned char* iv, unsigned char* chiperText);
    int decrypt(unsigned char* cipherText, int cipherTextLen, unsigned char* iv, unsigned char* decryptedText);
    bool check_hash(unsigned char *inBuf, int bufLen, unsigned char *hash);

  public:
    SecureMessageCreator();
    int EncryptAndSignMessage(unsigned char* plainText, int plainTextLen, unsigned char** secureText);
    bool DecryptAndCheckSign(unsigned char* secureText, int secureTextLen, unsigned char** plainText, int &plainTextLen);
    static DH* get_dh2048(void);
};
