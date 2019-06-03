#include <openssl/bn.h>

class SecureMessageCreator {
  private:
    
    unsigned char* _hmac_key;
    size_t _hmacKeySize;
    unsigned char* _encrypt_key;
    const EVP_CIPHER* _encryptAlgorithm;
    size_t _encriptKeySize;
    const EVP_MD* _hashAlgorithm;

    int _hashSize; // Algoritm+h used Sha-256

    unsigned char* hash(unsigned char *inBuf, int inLen);
    int encrypt(unsigned char* plainText, int plainTextLen, unsigned char* iv, unsigned char* chiperText);
    int decrypt(unsigned char* cipherText, int cipherTextLen, unsigned char* iv, unsigned char* decryptedText);
    bool check_hash(unsigned char *inBuf, int bufLen, unsigned char *hash);
    bool simpleHash256(unsigned char* input,size_t inputLenght, unsigned char* &output);

  public:
    SecureMessageCreator();
    bool derivateKeys(unsigned char* inizializationKey, size_t ikSize);
    void destroyKeysIfSetted();

    int EncryptAndSignMessage(unsigned char* plainText, int plainTextLen, unsigned char** secureText);
    bool DecryptAndCheckSign(unsigned char* secureText, int secureTextLen, unsigned char** plainText, int &plainTextLen);
    
    EVP_PKEY* ExtractPublicKeyFromFile(const char* filename);
    EVP_PKEY* ExtractPrivateKey(const char* filename);

    DH* get_dh2048(void);

    unsigned int sign(unsigned char* msg, int msgSize, EVP_PKEY* privKey, unsigned char* &signature);
    bool verify(unsigned char *msg, int msgSize, unsigned char *signature, int signatureLen, EVP_PKEY* pubKey);
};
