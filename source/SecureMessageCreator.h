#include <openssl/bn.h>
#include <exception>

class SecureMessageCreatorException : public std::exception
{
    public:
    virtual const char *what() const throw() = 0;
};
class EncryptInitException : public SecureMessageCreatorException
{
    public:
    const char *what() const throw()
    {
        return "Not possible initialize encryption context";
    }
};

class SecureMessageCreator {
  private:
    
    unsigned char* _hmac_key;
    size_t _hmacKeySize;
    unsigned char* _encrypt_key;
    const EVP_CIPHER* _encryptAlgorithm;
    size_t _encriptKeySize;
    const EVP_MD* _hashAlgorithm;

    int _hashSize; // Algoritm+h used Sha-256

    EVP_CIPHER_CTX *context;
    HMAC_CTX *mdctx;

    unsigned char* hash(unsigned char *inBuf, int inLen, bool useNonce, unsigned long nonce);
    
    bool check_hash(unsigned char *inBuf, int bufLen, unsigned char *hash, bool useNonce, unsigned long nonce);
    bool simpleHash256(unsigned char* input,size_t inputLenght, unsigned char* &output);

  public:
    SecureMessageCreator();
    bool derivateKeys(unsigned char* inizializationKey, size_t ikSize);
    void destroyKeysIfSetted();

    unsigned long getNonce();

    void initEncryptContext(unsigned char* iv);
    int updateEncrypt(unsigned char* plainText, int plainTextLen, unsigned char* chiperText);
    int finalAndFreeEncryptContext(unsigned char* chiperText, int &chiperTextLen);

    void initDecryptContext(unsigned char* iv);
    int updateDecrypt(unsigned char* cipherText, int cipherTextLen, unsigned char* decryptedText);
    int finalAndFreeDecryptContext(unsigned char* chiperText, int &chiperTextLen);
    

    int EncryptAndSignMessageUpdate(unsigned char* plainText, int plainTextLen, unsigned char** secureText, bool useNonce, unsigned long nonce);
    bool DecryptAndCheckSignUpdate(unsigned char* secureText, int secureTextLen, unsigned char** plainText, int &plainTextLen, bool useNonce, unsigned long nonce);

    int EncryptAndSignMessageFinal(unsigned char* plainText, int plainTextLen, unsigned char** secureText, bool useNonce, unsigned long nonce);
    bool DecryptAndCheckSignFinal(unsigned char* secureText, int secureTextLen, unsigned char** plainText, int &plainTextLen, bool useNonce, unsigned long nonce);
    
    EVP_PKEY* ExtractPublicKeyFromFile(const char* filename);
    EVP_PKEY* ExtractPrivateKey(const char* filename);

    DH* get_dh2048(void);

    unsigned int sign(unsigned char* msg, int msgSize, EVP_PKEY* privKey, unsigned char* &signature);
    bool verify(unsigned char *msg, int msgSize, unsigned char *signature, int signatureLen, EVP_PKEY* pubKey);
};
