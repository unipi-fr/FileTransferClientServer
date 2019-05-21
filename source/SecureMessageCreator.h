#include <exception>
#include <openssl/bn.h>
#include <openssl/x509.h>

class SecureMessageCreatorException : public std::exception
{
    public:
    virtual const char *what() const throw() = 0;
};

class FileNotFoundException : public SecureMessageCreatorException
{
    public:
    const char *what() const throw()
    {
        return "file is not open";
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

    X509_STORE* _store;

    int _hashSize; // Algoritm+h used Sha-256

    unsigned char* sign(unsigned char *inBuf, int inLen);
    int encrypt(unsigned char* plainText, int plainTextLen, unsigned char* iv, unsigned char* chiperText);
    int decrypt(unsigned char* cipherText, int cipherTextLen, unsigned char* iv, unsigned char* decryptedText);
    bool check_hash(unsigned char *inBuf, int bufLen, unsigned char *hash);
    void caStoreInit(X509* cert, X509_CRL* crl);
    bool simpleHash256(unsigned char* input,size_t inputLenght, unsigned char* &output);

  public:
    SecureMessageCreator();
    bool derivateKeys(unsigned char* inizializationKey, size_t ikSize);

    int EncryptAndSignMessage(unsigned char* plainText, int plainTextLen, unsigned char** secureText);
    bool DecryptAndCheckSign(unsigned char* secureText, int secureTextLen, unsigned char** plainText, int &plainTextLen);
    
    EVP_PKEY* ExtractPublicKeyFromFile(const char* filename);
    EVP_PKEY* ExtractPrivateKey(const char* filename);

    // forse devono essere tolte /////////////////////////////////////////////////////////////////////////////////////////
    int ExctractSessionMesssage(unsigned char *cipherText, int cipherLen,unsigned char* encryptedKey, int encryptedKeyLen, 
        unsigned char *iv, EVP_PKEY* privKey, unsigned char *&plainText);

    int CreateSessionMessage(const char* plaintext, size_t plaintextSize, EVP_PKEY* pubKey, unsigned char* &encryptedKey,
        int &encryptedKeySize,unsigned char* &iv, int &ivSize,unsigned char* &chipertext);
    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    bool verifyCertificate(X509* cert);
    X509* loadCertificateFromFile(const char* filename);
    bool addCertificateToStore(X509* cert);

    DH* get_dh2048(void);

    unsigned int sign(char* msg, int msgSize, EVP_PKEY* privKey, unsigned char* &signature);
    bool verify(unsigned char *msg, int msgSize, unsigned char *signature, int signatureLen, EVP_PKEY* pubKey);
};
