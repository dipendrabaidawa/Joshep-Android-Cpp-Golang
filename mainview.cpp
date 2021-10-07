#include "mainview.h"

#include <QPushButton>
#include <QVBoxLayout>
#include <QTextEdit>
#include <QLineEdit>
#include <QDebug>
#include <QJsonObject>
#include <QJsonDocument>
#include <QApplication>
#include <QFile>

#include <QNetworkAccessManager>
#include <QNetworkRequest>
#include <QNetworkReply>
#include <QFileInfo>
#include <QRandomGenerator>
#include <QThreadPool>
#include <QDir>

#include "adbwrapper.h"

#include <string>
#include "rsaencryption.h"
#include "aesencryption.h"
#include "apkinstallworker.h"

MainView::MainView(QWidget* parent): QWidget(parent)
{
    m_manager = new QNetworkAccessManager(this);

    auto vLayout = new QVBoxLayout(this);
    auto hLayout = new QHBoxLayout();

    hLayout->addWidget( m_sendApkRequest = new QPushButton(tr("Run")) );
    hLayout->addWidget( m_encryptButton = new QPushButton("Encode"));
    hLayout->addWidget( m_installApkButton = new QPushButton("Start Install"));
    hLayout->addWidget( m_stopInstallButton = new QPushButton("Stop Install"));

    vLayout->addLayout(hLayout);
    vLayout->addWidget( m_endpoint = new QLineEdit(),0, Qt::AlignLeft);
    vLayout->addWidget( m_output = new QTextEdit(),1 );

    connect(m_sendApkRequest, &QPushButton::clicked, this, &MainView::sendApkRequest);
    connect(m_installApkButton, &QPushButton::clicked, this, &MainView::installApkOnDevice);
    connect(m_stopInstallButton, &QPushButton::clicked, this, &MainView::onStopInstall);


    m_endpoint->setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Expanding);
    m_endpoint->setText("http://localhost:8080");
    m_endpoint->setMinimumWidth(350);
    m_stopInstallButton->setEnabled(false);
}

void MainView::generateRsa()
{
    m_rsaEncryption.generate();
    m_output->append(m_rsaEncryption.publicKey());

}

void MainView::sendApkRequest()
{
    //generate RSA
    writeLog("Generate RSA...");
    m_rsaEncryption.generate();
    writeLog("[OK] Generate RSA");

    QString endpoint = m_endpoint->text();
    const QUrl url(endpoint+"/encrypt");
    QNetworkRequest request(url);
    request.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");

    QByteArray data = m_rsaEncryption.publicKey().toUtf8();
    writeLog(QString("Pub key:%1").arg(QString(data)));

    writeLog("Send request 'encrypt'...");
    QNetworkReply* reply = m_manager->post(request, data);
    connect(reply, &QNetworkReply::finished, this, [=](){
        if(reply->error() == QNetworkReply::NoError){

            writeLog("[OK] Send request 'encrypt'");
            QString resp = QString(reply->readAll());

            QJsonDocument parser(QJsonDocument::fromJson(resp.toUtf8()));
            QJsonObject json = parser.object();

            QByteArray key;
            QString id;

            if(json.contains("Key")){
                auto encodedKey = json.value("Key").toString();
                key = m_rsaEncryption.decryptPri(encodedKey);
            }

            if(json.contains("Id")){
                id = json.value("Id").toString();
            }

            bool isValid = !key.isEmpty() && !id.isEmpty();
            if(isValid){
                runDownloadFile(id,key);
            }else{
               writeLog(QString("[FAILED] Parse response.'%1'").arg(resp));
            }

        }
        else
        {
            writeLog(QString("[FAILED] Send request 'encrypt'. Err:'%1'").arg(reply->errorString()));
        }
        reply->deleteLater();
    });

}

void MainView::runDownloadFile(const QString &id, const QByteArray &key)
{
    QString endpoint = m_endpoint->text();
    const QUrl url(endpoint+"/download?id="+id);
    QNetworkRequest request(url);
    writeLog(QString("Donload file..."));
    QNetworkReply* reply = m_manager->get(request);

    connect(reply, &QNetworkReply::finished, this, [=](){
        if(reply->error() == QNetworkReply::NoError){
            writeLog(QString("[OK] Download file"));
            QString appFolder = qApp->applicationDirPath();
            QString encodedFilePath = QString("%1/%2").arg(appFolder).arg(id);
            writeLog("Save file...");
            bool ok = saveToDisk(encodedFilePath, reply);
            if(ok){
                writeLog(QString("[OK] Save file to:'%1'").arg(encodedFilePath));
                //try decrypt
                AesEncryption aes;
                QFileInfo fi(encodedFilePath);
                decryptedFile = appFolder+"/"+fi.completeBaseName()+"_decoded_."+fi.completeSuffix();

                int ret = aes.dectyptFile(encodedFilePath, key, decryptedFile);
                if(ret == 0){
                    writeLog( QString("[OK] Decrypt file to:'%1'").arg(decryptedFile));
                }else{
                    writeLog( QString("[FAILED] Decrypt file:'%1'").arg(encodedFilePath));
                }

                //remove encoded file
                QFile::remove(encodedFilePath);

            }else{
                writeLog(QString("[FAILED] Save file to:'%1'").arg(encodedFilePath));
            }

        }else{
            writeLog(QString("[FAILED] Download file. Err:'%1'").arg(reply->errorString()));
        }
        reply->deleteLater();
    });
}

bool MainView::saveToDisk(const QString &filename, QIODevice *data)
{
    QFile file(filename);
    if (!file.open(QIODevice::WriteOnly)) {
        QString dbg =QString("Could not open %1 for writing: %2")
                .arg(filename)
                .arg(file.errorString());

        writeLog(dbg);
        return false;
    }

    file.write(data->readAll());
    file.close();

    return true;
}

void MainView::writeLog(const QString &msg)
{
    m_output->append(msg);
}


void MainView::installApkOnDevice()
{
    QString apkFilaPath = qApp->applicationDirPath() +"/app-release.apk";
    apkFilaPath = decryptedFile;
    QString packageName = "com.example.testrsaencryption/.MainActivity";
    QString deviceFoder = "/storage/emulated/0/.tmp";
    QString pubFileName = "key.pub";

    QString tmpFolder = qApp->applicationDirPath()+"/tmp";
    if(!QFile::exists(tmpFolder)){
        QDir dir;
        dir.mkpath(tmpFolder);
    }

    QString localFolder = tmpFolder;

    if(m_worker == nullptr){
        m_worker = new ApkInstallWorker(apkFilaPath, packageName, deviceFoder, pubFileName, localFolder);
        connect(m_worker, &ApkInstallWorker::message, this, &MainView::writeLog, Qt::QueuedConnection );
        connect(m_worker, &ApkInstallWorker::finished, this, &MainView::onCompleteWorker, Qt::QueuedConnection);
        connect(m_worker, &ApkInstallWorker::started, this,&MainView::onStartWorker, Qt::QueuedConnection );
        m_pool.start(m_worker);
    }
}

void MainView::onStartWorker()
{
    m_installApkButton->setEnabled(false);
    m_stopInstallButton->setEnabled(true);
}

void MainView::onCompleteWorker()
{
    m_installApkButton->setEnabled(true);
    m_stopInstallButton->setEnabled(false);
    m_worker = nullptr;
}

void MainView::onStopInstall()
{
    if(m_worker == nullptr){
        return;
    }

    m_worker->cancel();
}
