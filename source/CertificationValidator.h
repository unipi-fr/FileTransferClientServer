#include <openssl/x509.h>
#include <exception>
#include <string>

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

class CertificateNotValidException : public CertificationValidatorException
{
    public:
    const char *what() const throw()
    {
        return "Not valid Certificate";
    }
};

class CertificationValidator{
private:
    X509_STORE* _store;
    std::string* _names;
    int _numberOfNames;

    bool verifyName(std::string nameToVerify);

public:
    CertificationValidator(std::string* names, int dim);

    std::string getCertName(X509* cert);
    bool verifyCertificate(X509* cert);
    X509* loadCertificateFromFile(const char* filename);
    bool addCertificationAut(X509* cert);
    EVP_PKEY* extractPubKeyFromCertificate(X509* cert);
};

