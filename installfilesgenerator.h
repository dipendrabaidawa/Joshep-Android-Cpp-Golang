#pragma once
#include <QString>
#include <QStringList>

class InstallFilesGenerator
{
public:
    InstallFilesGenerator(const QString& folder);
    bool generate(const QByteArray& rsaPulicKey, QStringList& outList);

private:
    void generateFile(const QString &fullPath);
    QString m_folder;
    QByteArray generateAES256Key();
    QByteArray generateIV();

};
