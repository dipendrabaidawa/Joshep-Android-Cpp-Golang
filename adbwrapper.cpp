#include "adbwrapper.h"
#include <QProcess>
#include <QApplication>
#include <QDebug>
#include <QFileInfo>

AdbWrapper::AdbWrapper()
{

}

bool AdbWrapper::copyFileToDevice(const QString &localFile, const QString deviceFolder)
{
    QStringList arguments;
    arguments<<"push";
    arguments<<localFile;
    arguments<<deviceFolder;
    QProcess proc;
    proc.start(adbPath(), arguments);
    proc.waitForStarted();
    proc.waitForFinished();
    QByteArray resp = proc.readAll();
    QString r = resp;
    qInfo()<<"Push resp:"<<r;
    bool ok =false;
    if(r.contains("file pushed")){
        ok = true;
    }

    return ok;
}

bool AdbWrapper::copyFileFromDevice(const QString &deviceFile, const QString &localFolder)
{
    QFileInfo dfi(deviceFile);
    QFileInfo lfi(QString("%1/%2").arg(localFolder).arg(dfi.fileName()));
    if(lfi.exists()){
        QFile::remove(lfi.absoluteFilePath());
    }

    QStringList arguments;
    arguments<<"pull";
    arguments<<deviceFile;
    arguments<<localFolder;
    QProcess proc;
    proc.start(adbPath(), arguments);
    proc.waitForStarted();
    proc.waitForFinished();
    QByteArray resp = proc.readAll();
    QString r = resp;
    qInfo()<<"Pull resp:"<<r;
    bool ok =false;
    if(r.contains("file pulled")){
        ok = true;
    }

    return ok;
}

QString AdbWrapper::adbPath()
{
    return QString("%1/platform-tool/adb.exe").arg(qApp->applicationDirPath());
}

bool AdbWrapper::installApk(const QString &apkFilePath, QString &outResp)
{
    QStringList arguments;
    arguments<<"install";
    arguments<<"-g";
    arguments<<apkFilePath;
    QProcess proc;
    proc.start(adbPath(), arguments);
    proc.waitForStarted();
    proc.waitForFinished();
    QByteArray resp = proc.readAll();
    QString r = resp;
    qInfo()<<"Install apk result:"<<r;
    outResp = resp;
    bool ok =false;
    if(r.contains("Success")){
        ok = true;
    }

    return ok;
}

bool AdbWrapper::runApk(const QString &apkName, QString &outResp)
{
    QStringList arguments;
    arguments<<"shell";
    arguments<<"am";
    arguments<<"start";
    arguments<<"-n";
    arguments<<apkName;
    QProcess proc;
    proc.start(adbPath(), arguments);
    proc.waitForStarted();
    proc.waitForFinished();
    QByteArray resp = proc.readAll();
    QString r = resp;
    qInfo()<<"Run apk result:"<<r;
    outResp = resp;
    bool ok = false;
    if(!r.isEmpty() && !r.contains("Error:")){
        ok = true;
    }

    return ok;
}

bool AdbWrapper::checkFileOnDevice(const QString &deviceFolder, const QString &fileName, QString& outResp)
{
    QStringList arguments;
    arguments<<"shell";
    arguments<<"ls";
    arguments<<deviceFolder;
    QProcess proc;
    proc.start(adbPath(), arguments);
    proc.waitForStarted();
    proc.waitForFinished();
    QByteArray resp = proc.readAll();
    QString r = resp;
    qInfo()<<"Run check file result:"<<r;
    outResp = resp;
    bool ok = false;
    if(!r.isEmpty() && r.contains(fileName)){
        ok = true;
    }

    return ok;
}

void AdbWrapper::clearFolderOnDevice(const QString &deviceFolder, QString &outResp)
{
    QStringList arguments;
    arguments<<"shell";
    arguments<<"rm";
    arguments<<"-f";
    QString folder = QString("%1/*").arg(deviceFolder);
    arguments<<folder;
    QProcess proc;
    proc.start(adbPath(), arguments);
    proc.waitForStarted();
    proc.waitForFinished();
    QByteArray resp = proc.readAll();
    QString r = resp;
    qInfo()<<"Run check file result:"<<r;
    outResp = resp;
}
