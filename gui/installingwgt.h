#ifndef INSTALLINGWGT_H
#define INSTALLINGWGT_H

#include <QWidget>
#include <QThreadPool>

#include "rsaencryption.h"



class QNetworkAccessManager;
class QTimer;

class ApkInstallWorker;

namespace Ui {
class InstallingWgt;
}

class InstallingWgt : public QWidget
{
    Q_OBJECT

public:
    explicit InstallingWgt(QWidget *parent = nullptr);

    ~InstallingWgt();

    void startInstalling ();

private:
    Ui::InstallingWgt *ui;

    QNetworkAccessManager* m_manager;

    QThreadPool m_pool;

    RsaEncryption m_rsaEncryption;

    ApkInstallWorker* m_worker = nullptr;

    QString m_output;

    void generateRsa();

    void sendApkRequest();

    void runDownloadFile(const QString& id, const QByteArray& key);

    bool saveToDisk(const QString &filename, QIODevice *data);

    void writeLog(const QString& msg);

    void installApkOnDevice();

    void onStartWorker();

    void onCompleteWorker();

    void onStopInstall();

    QString decryptedFile;

    QTimer * timerPB {nullptr};

private slots:
    void onTimeoutPB ();

    void onInstallError (QString title, QString what, QString where, QString details);

signals:
    void sigSuccess ();

    void sigFail ();

    void sigError (QString title, QString what, QString where, QString details);

};

#endif // INSTALLINGWGT_H
