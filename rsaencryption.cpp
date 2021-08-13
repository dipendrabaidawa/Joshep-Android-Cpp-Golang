#include "rsaencryption.h"
#include <QDebug>

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#pragma comment(lib,"libcrypto.lib")


struct RsaEncryption::Private
{
    RSA* rsa = nullptr;
    QString publicKey;
    QString privateKey;
};


RsaEncryption::RsaEncryption():m_impl(new Private)
{
}


RsaEncryption::~RsaEncryption()
{
    if(m_impl->rsa)
    {
        RSA_free(m_impl->rsa);
        m_impl->rsa = nullptr;
    }
}

void RsaEncryption::generate()
{
    if(m_impl->rsa) {
        RSA_free(m_impl->rsa);
    }

    m_impl->rsa = RSA_new();
    RSA* keyPair = m_impl->rsa;
    BIGNUM* exponent = BN_new();

    const unsigned long RSA_KEY_EXPONENT = 65537;
    BN_set_word(exponent, RSA_KEY_EXPONENT);

    srand(time(NULL));

    const int RSA_KEY_BITS = 1024;

    RSA_generate_key_ex(keyPair, RSA_KEY_BITS, exponent, nullptr);

    BIO* pri = BIO_new(BIO_s_mem());
    BIO* pub = BIO_new(BIO_s_mem());

    //Write to memory private key
    PEM_write_bio_RSAPrivateKey(pri, keyPair, nullptr, nullptr, 0, nullptr, nullptr);

    //Write to memory public key
    PEM_write_bio_RSAPublicKey(pub, keyPair);

    int priLen = BIO_pending(pri);
    int pubLen = BIO_pending(pub);

    std::unique_ptr<char[]> priKey(new char[priLen +1]);
    std::unique_ptr<char[]> pubKey(new char[pubLen +1]);

    BIO_read(pri, &priKey[0], priLen);
    BIO_read(pub, &pubKey[0], pubLen);

    priKey[priLen] = '\0';
    pubKey[pubLen] = '\0';

    m_impl->privateKey = QString(&priKey[0]);
    m_impl->publicKey = QString(&pubKey[0]);

    BN_free(exponent);

    BIO_free_all(pri);
    BIO_free_all(pub);
}

QByteArray RsaEncryption::decryptPri(QString &data)
{
    QByteArray before = data.toLocal8Bit();
    QByteArray encodedBase64 = QByteArray::fromBase64(before);

    unsigned char* encryptedData = (unsigned char*)encodedBase64.data();
    int rsaLen = RSA_size(m_impl->rsa);
    int partNum = encodedBase64.size()/rsaLen;

    QByteArray result;
    for(int i = 0; i<partNum;i++){
        unsigned char* decryptedBin = new unsigned char[rsaLen];
        int resultLen = RSA_private_decrypt(rsaLen
                                            , encryptedData + i*rsaLen
                                            , decryptedBin
                                            , m_impl->rsa
                                            , RSA_PKCS1_OAEP_PADDING);

        if(resultLen == -1){
            qInfo()<<"ERROR: RSA_private_decrypt:"<<ERR_error_string(ERR_get_error(), NULL);
        }

        result.append((char*)decryptedBin, resultLen);
    }

    return result;
}

QString RsaEncryption::publicKey()
{
    return m_impl->publicKey;
}

RSA* createRSA(unsigned char* key,int len, bool pub)
{
    RSA* rsa = nullptr;
    BIO* bio = BIO_new(BIO_s_mem());
    BIO_write(bio, key, len+1);

    if(pub)
    {
        rsa = PEM_read_bio_RSA_PUBKEY(bio, nullptr, nullptr, nullptr);
        //rsa = PEM_read_bio_RSA_PUBKEY(bio, nullptr, nullptr, nullptr);
    }else
    {
        rsa = PEM_read_bio_RSAPrivateKey(bio,nullptr, nullptr, nullptr);
    }

    if(rsa == nullptr){
        qCritical()<<"[FAILED] "<<"can't init RSA";
    }

    BIO_free(bio);

    return rsa;
}

QByteArray RsaEncryption::encryptData(const QByteArray &key, const QByteArray &data)
{
    if(data.isEmpty()){
        return QByteArray();
    }

    RSA* rsa = createRSA((unsigned char*)key.data(), key.length(),true);
    if(rsa == nullptr){
        return QByteArray();
    }

    int rsaLen = RSA_size(rsa);
    qInfo()<<"RSA LEN:"<<rsaLen<<" pub key len:"<<key.length()<<" data len:"<<data.length();

    QByteArray result;
    unsigned char* encBuffer = new unsigned char[rsaLen];
    int crtLen = RSA_public_encrypt(data.length()
                                    , (unsigned char*)data.data()
                                    , encBuffer
                                    , rsa
                                    , RSA_PKCS1_OAEP_PADDING);

    qInfo()<<"crtLen:"<<crtLen;

    if(crtLen <= 0){
        qInfo()<<"ERROR: RSA_public_encrypt"<<ERR_error_string(ERR_get_error(), NULL);
        return QByteArray();
    }

    result.append((char*)encBuffer,crtLen);

    return result;

    int partNum = data.length()/rsaLen;
//    if(partNum == 0){
//        partNum = 1;
//    }

    int count = 0;

    for(int i = 0; i < partNum; i++){
        qInfo()<<"enc part";
        unsigned char* encryptedBin = new unsigned char[rsaLen];
        int resultLen = RSA_public_encrypt(rsaLen
                                           , (unsigned char*)data.data() + i*rsaLen
                                           , encryptedBin
                                           , rsa
                                           , RSA_PKCS1_OAEP_PADDING);
        if(resultLen == -1){
            qInfo()<<"ERROR: RSA_public_encrypt"<<ERR_error_string(ERR_get_error(), NULL);
            break;
        }

        qInfo()<<"APPEND len:"<<resultLen;
        result.append((char*)encryptedBin, resultLen);
        count+=resultLen;
    }

    qInfo()<<"Encrypted count:"<<count;
    RSA_free(rsa);
    return result;
}
