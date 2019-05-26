#include "CertificationValidator.h"
#include <openssl/x509_vfy.h>
#include <openssl/pem.h>
#include <iostream>

using namespace std;

CertificationValidator::CertificationValidator(string* names, int dim)
{
  _store = X509_STORE_new();

  _numberOfNames = dim;
  _names = new string[_numberOfNames];

  for(int i = 0; i < _numberOfNames ; i++)
  {
    _names[i] = string(names[i]);
  }    
}

bool CertificationValidator::verifyName(string nameToVerify)
{
  
  for(int i = 0; i<_numberOfNames ; i++)
  {
    if(_names[i] == nameToVerify)
    {
      return true;
    }
  }

  return false;

}

bool CertificationValidator::verifyCertificate(X509* cert)
{
  if(_store == NULL){
    return false;
  }

  X509_STORE_CTX* ctx= X509_STORE_CTX_new();

  X509_STORE_CTX_init(ctx, _store, cert, NULL);
  int ret = X509_verify_cert(ctx); //return 1 on success

  if(ret != 1)
    return false;

  X509_STORE_CTX_free(ctx);

  X509_NAME* subjectName;

  subjectName = X509_get_subject_name(cert);
  char* substr = X509_NAME_oneline(subjectName, NULL, 0);

  string str = string(substr);

  free(substr);
  X509_NAME_free(subjectName);

  return verifyName(str);
}

X509* CertificationValidator::loadCertificateFromFile(const char* filename)
{
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