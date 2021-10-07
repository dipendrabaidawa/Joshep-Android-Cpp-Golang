#include "adbwrapper.h"

#include <QProcess>
#include <QApplication>
#include <QDebug>
#include <QFileInfo>
#include <QRegularExpression>
#include <QRegularExpressionMatch>
#include <QMetaEnum>

AdbWrapper::AdbWrapper()
{

}

QString AdbWrapper::errorWhat (const QProcess::ProcessError &error)
{
    QMetaEnum metaEnum = QMetaEnum::fromType<QProcess::ProcessError>();
    return QString("adb.") + metaEnum.valueToKey(error) + ": error occured in adb.exe";
}

QString AdbWrapper::errorWhere ()
{
    return "An error occured during adb.exe execution. See \"Details\"\n"
            "section to get more detailed information about the error.";
}

QString AdbWrapper::errorDetails (const QProcess::ProcessError & error)
{
    QString res;
    switch (error)
    {
    case QProcess::FailedToStart:
        res = "The process failed to start. Either the invoked program is missing,\n "
                  "or you may have insufficient permissions or resources to invoke the program.";
        break;
    case QProcess::Crashed:
        res = "The process crashed some time after starting successfully.";
        break;
    case QProcess::Timedout:
        res = "The last waitFor...() function timed out.\n"
              "The state of QProcess is unchanged, and you can try calling waitFor...() again.";
        break;
    case QProcess::ReadError:
        res = "An error occurred when attempting to read from the process.\n"
              "For example, the process may not be running.";
        break;
    case QProcess::WriteError:
        res = "An error occurred when attempting to write to the process.\n "
                "For example, the process may not be running, or it may have closed its input channel.";
        break;
    case QProcess::UnknownError:
        res = "An unknown error occurred.";
        break;
    }
    return res;
}

QByteArray AdbWrapper::runAdb (QStringList args, bool &isError, QProcess::ProcessError & errIn)
{
    QByteArray res;
    QProcess proc;
    isError = false;
    proc.connect(&proc, &QProcess::errorOccurred,
                 [&errIn, &isError](QProcess::ProcessError error)
    {
        isError = true;
        errIn = error;
    });
    proc.start(adbPath (), args);
    proc.waitForStarted ();
    proc.waitForFinished ();
    res = proc.readAll ();
    return res;
}

bool AdbWrapper::checkDevices (bool & isError, QProcess::ProcessError & error)
{
    bool res = false;
    QStringList arguments;
    arguments<<"devices";    
    QByteArray resp = runAdb (arguments, isError, error);
    QString str = QString::fromStdString (resp.toStdString ());
    if (str.contains(QRegularExpression("device[^s]")))
        res = true;
    return res;
}

QString AdbWrapper::getSerialNumber (bool & isError, QProcess::ProcessError & error)
{
    QString res;

    QStringList arguments;
    arguments<<"get-serialno";

    QByteArray resp = runAdb (arguments, isError, error);
    res = QString::fromStdString (resp.toStdString ());
    res.remove("\r").remove("\n");

    return res;
}

QString AdbWrapper::getManufacturer (bool & isError, QProcess::ProcessError & error)
{
    return getProp ("ro.product.manufacturer", isError, error);
}

QString AdbWrapper::getModel (bool & isError, QProcess::ProcessError & error)
{
    return getProp ("ro.product.model", isError, error);
}

QString AdbWrapper::getVersion (bool & isError, QProcess::ProcessError & error)
{
    return getProp ("ro.build.version.release", isError, error);
}

QString AdbWrapper::callIphonesubinfo (QString number, bool & isError, QProcess::ProcessError &error)
{
    QString res;

    QStringList arguments;
    arguments<<"shell";
    arguments<<"service";
    arguments<<"call";
    arguments<<"iphonesubinfo";
    arguments<<number;

    QByteArray resp = runAdb (arguments, isError, error);
    auto strNotHandled = QString::fromStdString (resp.toStdString ());

    auto exp = QRegularExpression ("\\'(.)*\\'");
    for (const QRegularExpressionMatch &match : exp.globalMatch (strNotHandled))
        res += match.captured();
    res.remove('\'').remove('.');

    return res;
}

QString AdbWrapper::getProp (QString prop, bool &isError, QProcess::ProcessError & error)
{
    QString res;

    QStringList arguments;
    arguments<<"shell";
    arguments<<"getprop";
    arguments<<prop;

    QByteArray resp = runAdb (arguments, isError, error);
    res = QString::fromStdString (resp.toStdString ());
    res.remove("\r").remove("\n");

    return res;
}

QString AdbWrapper::getDevicePhoneNumber (bool & isError, QProcess::ProcessError & error)
{
    QString res;
    for (int i=1; i<=30; i++) {
        res = callIphonesubinfo(QString::number(i), isError, error);
        if (res.contains('+'))
            break;
        else
            res.clear();
    }
    if (res.isEmpty())
        res = callIphonesubinfo("15", isError, error);
    return res;
}

QString AdbWrapper::getIMEI (bool & isError, QProcess::ProcessError & error)
{
    return callIphonesubinfo("1", isError, error);
}

bool AdbWrapper::copyFileToDevice(const QString &localFile, const QString deviceFolder, bool & isError, QProcess::ProcessError & error)
{
    QStringList arguments;
    arguments<<"push";
    arguments<<localFile;
    arguments<<deviceFolder;
    QByteArray resp = runAdb (arguments, isError, error);
    QString r = resp;
    qInfo()<<"Push resp:"<<r;
    bool ok =false;
    if(r.contains("file pushed")){
        ok = true;
    }

    return ok;
}

bool AdbWrapper::copyFileFromDevice(const QString &deviceFile, const QString &localFolder, bool & isError, QProcess::ProcessError & error)
{
    QFileInfo dfi(deviceFile);
    QFileInfo lfi(QString("%1/%2").arg(localFolder, dfi.fileName()));
    if(lfi.exists()){
        QFile::remove(lfi.absoluteFilePath());
    }

    QStringList arguments;
    arguments<<"pull";
    arguments<<deviceFile;
    arguments<<localFolder;
    QByteArray resp = runAdb (arguments, isError, error);
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

bool AdbWrapper::installApk(const QString &apkFilePath, QString &outResp, bool & isError, QProcess::ProcessError & error)
{
    QStringList arguments;
    arguments<<"install";
    arguments<<"-g";
    arguments<<apkFilePath;
    QByteArray resp = runAdb (arguments, isError, error);
    QString r = resp;
    qInfo()<<"Install apk result:"<<r;
    outResp = resp;
    bool ok =false;
    if(r.contains("Success")){
        ok = true;
    }

    return ok;
}

bool AdbWrapper::runApk(const QString &apkName, QString &outResp, bool & isError, QProcess::ProcessError & error)
{
    QStringList arguments;
    arguments<<"shell";
    arguments<<"am";
    arguments<<"start";
    arguments<<"-n";
    arguments<<apkName;
    QByteArray resp = runAdb (arguments, isError, error);
    QString r = resp;
    qInfo()<<"Run apk result:"<<r;
    outResp = resp;
    bool ok = false;
    if(!r.isEmpty() && !r.contains("Error:")){
        ok = true;
    }

    return ok;
}

bool AdbWrapper::checkFileOnDevice(const QString &deviceFolder, const QString &fileName, QString& outResp, bool & isError, QProcess::ProcessError & error)
{
    QStringList arguments;
    arguments<<"shell";
    arguments<<"ls";
    arguments<<deviceFolder;
    QByteArray resp = runAdb (arguments, isError, error);
    QString r = resp;
    qInfo()<<"Run check file result:"<<r;
    outResp = resp;
    bool ok = false;
    if(!r.isEmpty() && r.contains(fileName)){
        ok = true;
    }

    return ok;
}

void AdbWrapper::clearFolderOnDevice(const QString &deviceFolder, QString &outResp, bool & isError, QProcess::ProcessError & error)
{
    QStringList arguments;
    arguments<<"shell";
    arguments<<"rm";
    arguments<<"-f";
    QString folder = QString("%1/*").arg(deviceFolder);
    arguments<<folder;
    QByteArray resp = runAdb (arguments, isError, error);
    QString r = resp;
    qInfo()<<"Run check file result:"<<r;
    outResp = resp;
}
