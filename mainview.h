#pragma once
#include <QWidget>
#include <string>
#include <QThreadPool>
#include "rsaencryption.h"

QT_BEGIN_NAMESPACE
class QPushButton;
class QTextEdit;
class QNetworkAccessManager;
class QLineEdit;
QT_END_NAMESPACE
class ApkInstallWorker;
class MainView : public QWidget
{
    Q_OBJECT
public:
    MainView(QWidget* parent = nullptr);

private:
    QNetworkAccessManager* m_manager;
    QPushButton* m_sendApkRequest;
    QTextEdit* m_output;
    QLineEdit* m_endpoint;
    QPushButton* m_encryptButton;
    QPushButton* m_installApkButton;
    QPushButton* m_stopInstallButton;
    QThreadPool m_pool;

    RsaEncryption m_rsaEncryption;
    ApkInstallWorker* m_worker = nullptr;

    void generateRsa();
    void sendApkRequest();
    void runDownloadFile(const QString& id, const QByteArray& key);
    bool saveToDisk(const QString &filename, QIODevice *data);
    void writeLog(const QString& msg);

    void installApkOnDevice();
    void onStartWorker();
    void onCompleteWorker();
    void onStopInstall();
};
