#include "CertificationValidator.h"
#include <openssl/x509_vfy.h>
#include <openssl/pem.h>
#include <iostream>
using namespace std;

CertificationValidator::CertificationValidator(){
    _store = X509_STORE_new();
}

bool CertificationValidator::verifyCertificate(X509* cert){
    if(_store == NULL){
      return false;
    }

    X509_STORE_CTX* ctx= X509_STORE_CTX_new();

    X509_STORE_CTX_init(ctx, _store, cert, NULL);
    int ret = X509_verify_cert(ctx);//return 1 on success

    X509_STORE_CTX_free(ctx);

    return ret==1;
}

X509* CertificationValidator::loadCertificateFromFile(const char* filename){
    X509* cert = NULL;
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

bool CertificationValidator::addCertificationAut(X509* cert){
  return X509_STORE_add_cert(_store,cert) == 1;
}

EVP_PKEY* CertificationValidator::extractPubKeyFromCertificate(X509* cert)
{
  EVP_PKEY* pubKey = X509_get_pubkey(cert);
  return pubKey;
}