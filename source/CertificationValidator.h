#include <openssl/x509.h>
#include <exception>

class CertificationValidatorException : public std::exception
{
    public:
    virtual const char *what() const throw() = 0;
};

class FileNotFoundException : public CertificationValidatorException
{
    public:
    const char *what() const throw()
    {
        return "file is not open";
    }
};

class CertificationValidator{
private:
    X509_STORE* _store;

public:
    CertificationValidator();

    bool verifyCertificate(X509* cert);
    X509* loadCertificateFromFile(const char* filename);
    bool addCertificationAut(X509* cert);
    EVP_PKEY* extractPubKeyFromCertificate(X509* cert);
};

