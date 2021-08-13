#pragma once
#include <QString>

class AdbWrapper
{
public:
    AdbWrapper();
    bool copyFileToDevice(const QString& localFile, const QString deviceFolder);
    bool copyFileFromDevice(const QString& deviceFile, const QString& localFolder);
    QString adbPath();
    bool installApk(const QString& apkFilePath, QString& resp);
    bool runApk(const QString& apkName, QString& outResp);
    bool checkFileOnDevice(const QString& deviceFolder, const QString& fileName, QString &outResp);
    void clearFolderOnDevice(const QString& deviceFolder, QString &outResp);
};
