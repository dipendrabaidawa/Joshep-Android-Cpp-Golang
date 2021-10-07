#pragma once
#include <QString>
#include <memory>

class RsaEncryption
{
public:
    RsaEncryption();
    ~RsaEncryption();

    void generate();
    QByteArray decryptPri(QString &data);

    QString publicKey();

    static QByteArray encryptData(const QByteArray& key, const QByteArray& data);

private:
    struct Private;
    std::unique_ptr<Private> m_impl;
};
