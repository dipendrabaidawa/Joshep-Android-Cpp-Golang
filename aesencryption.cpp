#include "aesencryption.h"
#include <QFile>

#include <QFile.h>
#include <QString.h>
#include <QDebug.h>
#include <openssl/ssl.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/ossl_typ.h>
#include <openssl/evp.h>
#include <openssl/evperr.h>


const int BUFSIZE = 100;
#define AES_256_KEY_SIZE 32

//docs:
//
//https://en.wikipedia.org/wiki/Padding_(cryptography)#PKCS#5_and_PKCS#7
//

AesEncryption::AesEncryption()
{

}

int AesEncryption::dectyptFile(const QString& encodedFilePath, const QByteArray& key, const QString& decodedFilePath)
{
    qInfo()<<"aesCryptoFile...";

    qInfo()<<"key char str:"<<QString::fromLatin1(key.data(), key.length());
    QByteArray baKey = key;
    qInfo()<<"baKey:"<<baKey.toHex()<<" len:"<<baKey.length();

    AES_KEY aes;

    if(AES_set_decrypt_key((unsigned char*)baKey.data(), baKey.length()*8, &aes) < 0) {
        qCritical() << "Set aes key for decrypting model file failed";
        return -1;
    }

    QFile inputFile(encodedFilePath);
    if (!inputFile.open(QIODevice::ReadOnly)) {
        qCritical() << "Open model file " << encodedFilePath <<" failed";
        return -1;
    }

    QFile outFile(decodedFilePath);
    if(!outFile.open(QIODevice::WriteOnly)){
        qCritical() << "Open file " << decodedFilePath <<" failed";
        return -1;
    }

    unsigned char iv[AES_BLOCK_SIZE];

    //read IV from file begin
    int len = inputFile.read((char*)&iv[0], AES_BLOCK_SIZE);
    if(len < AES_BLOCK_SIZE){
        qCritical()<<"Failed to read IV";
        return -1;
    }

    const int kBuffLen = 32;
    unsigned char encodedBuffer[kBuffLen];
    unsigned char decodedBuffer[kBuffLen];

    int lastLen = 0;
    while (len>0) {
        //read data from encoded file
        len = inputFile.read((char*)&encodedBuffer[0], kBuffLen);
        if(len > 0){
            AES_cbc_encrypt(&encodedBuffer[0], &decodedBuffer[0], len, &aes, &iv[0], AES_DECRYPT);
            outFile.write((const char*)&decodedBuffer[0],len);
            lastLen = len;
        }
    }

    //get unpadding len (PKCS#7 padding)
    unsigned char unpadding = decodedBuffer[lastLen - 1];
    qInfo()<<"unpadding:"<<unpadding;
    if(unpadding > 0){
        qint64 fileLen = outFile.size();
        qint64 fileLenUn = fileLen - unpadding;
        qInfo()<<"fileLen:"<<fileLen<<" fileLenUn:"<<fileLenUn;
        outFile.resize(fileLenUn);
    }

    inputFile.close();
    outFile.flush();
    outFile.close();

    return 0;
}

int AesEncryption::decrypt(const QString &encodedFilePath, const QString &decodedFilePath,const QByteArray &key, const QByteArray &iv)
{
    QFile inputFile(encodedFilePath);
    if (!inputFile.open(QIODevice::ReadOnly)) {
        qCritical() << "Open file " << encodedFilePath <<" failed";
        return -1;
    }


    QFile outFile(decodedFilePath);
    if(!outFile.open(QIODevice::WriteOnly)){
        qCritical() << "Open file " << decodedFilePath <<" failed";
        return -1;
    }

    cipher_params_t params;
    params.key = (unsigned char*)key.data();
    params.iv = (unsigned char*)iv.data();
    params.encrypt = 0;
    params.cipher_type = EVP_aes_256_cbc();
    file_encrypt_decrypt( &params, &inputFile, &outFile);

    return 0;
}

int AesEncryption::encrypt(const QString &sourceFilePath, const QString &encodedFilePath, const QByteArray &key, const QByteArray &iv)
{
    QFile inputFile(sourceFilePath);
    if (!inputFile.open(QIODevice::ReadOnly)) {
        qCritical() << "Open model file " << sourceFilePath <<" failed";
        return -1;
    }


    QFile outFile(encodedFilePath);
    if(!outFile.open(QIODevice::WriteOnly)){
        qCritical() << "Open file " << encodedFilePath <<" failed";
        return -1;
    }

    cipher_params_t params;
    params.key = (unsigned char*)key.data();
    params.iv = (unsigned char*)iv.data();
    params.encrypt = 1;
    params.cipher_type = EVP_aes_256_cbc();
    file_encrypt_decrypt( &params, &inputFile, &outFile);

    return 0;
}


//https://medium.com/@amit.kulkarni/encrypting-decrypting-a-file-using-openssl-evp-b26e0e4d28d4
void AesEncryption::file_encrypt_decrypt(cipher_params_t *params, QFile *ifp, QFile *ofp)
{
    int cipher_block_size = EVP_CIPHER_block_size(params->cipher_type);
    cipher_block_size = AES_BLOCK_SIZE;
    unsigned char in_buf[BUFSIZE];
    unsigned char out_buf[BUFSIZE + AES_BLOCK_SIZE];

    int num_bytes_read = 0;
    int out_len = 0;
    EVP_CIPHER_CTX *ctx;

    ctx = EVP_CIPHER_CTX_new();
    if(ctx == NULL){
        fprintf(stderr, "ERROR: EVP_CIPHER_CTX_new failed. OpenSSL error: %s\n",
                ERR_error_string(ERR_get_error(), NULL));
        cleanup(params, ifp, ofp);
    }

    /* Don't set key or IV right away; we want to check lengths */
    if(!EVP_CipherInit_ex(ctx, params->cipher_type, NULL, NULL, NULL, params->encrypt)){
        fprintf(stderr, "ERROR: EVP_CipherInit_ex failed. OpenSSL error: %s\n",
                ERR_error_string(ERR_get_error(), NULL));
        cleanup(params, ifp, ofp);
    }

    OPENSSL_assert(EVP_CIPHER_CTX_key_length(ctx) == AES_256_KEY_SIZE);
    OPENSSL_assert(EVP_CIPHER_CTX_iv_length(ctx) == AES_BLOCK_SIZE);

    /* Now we can set key and IV */
    if(!EVP_CipherInit_ex(ctx, NULL, NULL, params->key, params->iv, params->encrypt)){
        fprintf(stderr, "ERROR: EVP_CipherInit_ex failed. OpenSSL error: %s\n",
                ERR_error_string(ERR_get_error(), NULL));
        EVP_CIPHER_CTX_cleanup(ctx);
        cleanup(params, ifp, ofp);
    }

    while(1){
        // Read in data in blocks until EOF. Update the ciphering with each read.
        num_bytes_read = ifp->read((char*)in_buf, BUFSIZE);
        if (num_bytes_read == 0) {
            /* Reached End of file */
            break;
        }

        if (num_bytes_read < 0){
            fprintf(stderr, "ERROR: fread error: %s\n", strerror(errno));
            EVP_CIPHER_CTX_cleanup(ctx);
            cleanup(params, ifp, ofp);
        }
        if(!EVP_CipherUpdate(ctx, out_buf, &out_len, in_buf, num_bytes_read)){
            fprintf(stderr, "ERROR: EVP_CipherUpdate failed. OpenSSL error: %s\n",
                    ERR_error_string(ERR_get_error(), NULL));

            EVP_CIPHER_CTX_cleanup(ctx);
            cleanup(params, ifp, ofp);
        }

        //fwrite(out_buf, sizeof(unsigned char), out_len, ofp);
        int ret = ofp->write((char*)out_buf, out_len);
        if (ret < 0) {
            fprintf(stderr, "ERROR: fwrite error: %s\n", strerror(errno));
            EVP_CIPHER_CTX_cleanup(ctx);
            cleanup(params, ifp, ofp);
        }
    }

    /* Now cipher the final block and write it out to file */
    if(!EVP_CipherFinal_ex(ctx, out_buf, &out_len)){
        fprintf(stderr, "ERROR: EVP_CipherFinal_ex failed. OpenSSL error: %s\n",
                ERR_error_string(ERR_get_error(), NULL));
        EVP_CIPHER_CTX_cleanup(ctx);
        cleanup(params, ifp, ofp);
    }

    //fwrite(out_buf, sizeof(unsigned char), out_len, ofp);
    int writes = ofp->write((char*)out_buf, out_len);
    if (writes < 0) {
        fprintf(stderr, "ERROR: fwrite error: %s\n", strerror(errno));
        EVP_CIPHER_CTX_cleanup(ctx);
        cleanup(params, ifp, ofp);
    }
    EVP_CIPHER_CTX_cleanup(ctx);
}

void AesEncryption::cleanup(cipher_params_t *params, QFile *ifp, QFile *ofp)
{

}
