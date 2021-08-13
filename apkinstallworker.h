
#include <QObject>
#include <QRunnable>
#include <QMutex>

class ApkInstallWorker : public QObject, public QRunnable
{
    Q_OBJECT
public:

    ApkInstallWorker(const QString& apkFilePath
                     , const QString& packageName
                     , const QString& deviceFolder
                     , const QString& publicKeyFileName
                     , const QString& localFolder);

    enum InstallStates { ClearDeviceFolderState
         , PushApkState
         , RunApkState
         , WaitPublicKeyState
         , ReceivePublicKeyState
         , LoadPublicKeyState
         , GenerateInstallFilesState
         , PushInstallFilesState
         , CompleteState };

    void run() override;

    void cancel();
    bool isCanceled();

signals:
    void started();
    void finished();
    void message(QString msg);
private:
    bool doPushApk();
    bool doRunApk();
    void doWaitPublicKey();
    void doReceivePublicKey();
    void doLoadPublicKey();
    void doGenerateInstallFiles();
    void doPushInstallFiles();
    void clearLocalFolder();

    QMutex m_cancelMutex;
    QString m_deviceFolder;
    QString m_publicKeyFileName;
    QString m_packageName;
    QString m_apkFilePath;
    QString m_localFolder;
    InstallStates m_state;
    bool m_canceled;
    QString m_lastError;
    QByteArray m_apkRsaPublicKeyData;
    QStringList m_installFileList;
    QStringList m_filesToClean;
};
