#pragma once
#include <QString>
#include <openssl/evp.h>
#include <QFile>

typedef struct _cipher_params_t{
    unsigned char *key;
    unsigned char *iv;
    unsigned int encrypt;
    const EVP_CIPHER *cipher_type;
}cipher_params_t;

class AesEncryption
{
public:
    AesEncryption();

    int dectyptFile(const QString& encodedFilePath, const QByteArray& key, const QString& decodedFilePath);

    int decrypt(const QString& encodedFilePath, const QString& decodedFilePath, const QByteArray& key, const QByteArray& iv);
    int encrypt(const QString& sourceFilePath,  const QString& encodedFilePath, const QByteArray& key, const QByteArray& iv);

    void file_encrypt_decrypt(cipher_params_t * params, QFile *ifp, QFile *ofp);
    void cleanup(cipher_params_t * params, QFile *ifp, QFile *ofp);
};
