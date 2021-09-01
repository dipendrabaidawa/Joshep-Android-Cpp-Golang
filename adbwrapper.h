#pragma once

#include <QString>
#include <QProcess>


class AdbWrapper
{
public:
    AdbWrapper();

    static bool checkDevices (bool & isError, QProcess::ProcessError & error);

    static QString getIMEI (bool & isError, QProcess::ProcessError & error);

    static QString getManufacturer (bool & isError, QProcess::ProcessError & error);

    static QString getModel (bool & isError, QProcess::ProcessError & error);

    static QString getVersion (bool & isError, QProcess::ProcessError & error);

    static QString getSerialNumber (bool & isError, QProcess::ProcessError & error);

    static QString getDevicePhoneNumber (bool & isError, QProcess::ProcessError & error);

    static bool copyFileToDevice(const QString& localFile, const QString deviceFolder, bool & isError, QProcess::ProcessError & error);

    static bool copyFileFromDevice(const QString& deviceFile, const QString& localFolder, bool & isError, QProcess::ProcessError & error);

    static QString adbPath();

    static bool installApk(const QString& apkFilePath, QString& resp, bool & isError, QProcess::ProcessError & error);

    static bool runApk(const QString& apkName, QString& outResp, bool & isError, QProcess::ProcessError & error);

    static bool checkFileOnDevice(const QString& deviceFolder, const QString& fileName, QString &outResp, bool & isError, QProcess::ProcessError & error);

    static void clearFolderOnDevice(const QString& deviceFolder, QString &outResp, bool & isError, QProcess::ProcessError & error);

    //error
    static QString errorWhat (const QProcess::ProcessError & error);

    static QString errorWhere ();

    static QString errorDetails (const QProcess::ProcessError & error);

private:
    static QByteArray runAdb (QStringList args, bool &isError, QProcess::ProcessError & error);

    static QString getProp (QString prop, bool &isError, QProcess::ProcessError & error);

    static QString callIphonesubinfo (QString number, bool &isError, QProcess::ProcessError & error);

};
