#include "mainwidget.h"
#include "ui_mainwidget.h"

#include <QSettings>
#include <QDebug>

#include "settingkeys.h"
#include "errorhandlingdlg.h"

MainWgt::MainWgt(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::MainWgt)
{
    ui->setupUi(this);
    setWindowTitle("WINDOWS INSTALLER");
    //init step wgts
    {
        ui->widgetStep1->setDescription("Login/Sign Up");
        ui->widgetStep2->setDescription("Device Information");
        ui->widgetStep3->setDescription("Customer Information");
        ui->widgetStep4->setDescription("Installing...");
        ui->widgetStep5->setDescription("Finished");
    }

    //login/sign up
    {
        connect (ui->loginSignUp, &LoginSignWgt::sigSuccess,
                 this, &MainWgt::onLoginSignUp);
    }

    //installing...
    {
        connect (ui->installing, &InstallingWgt::sigSuccess,
                 this, &MainWgt::onSuccessInstall);
        connect (ui->installing, &InstallingWgt::sigFail,
                 this, &MainWgt::onFailInstall);
        connect (ui->installing, &InstallingWgt::sigError,
                 this, &MainWgt::onErrorHandling);
    }

    //deviceInfo
    {
        connect (ui->deviceInfo, &DeviceInfoWgt::sigError,
                 this, &MainWgt::onErrorHandling);
    }

    //bottom widget
    {
        connect (ui->pushButtonLogout, &QPushButton::clicked,
                 this, &MainWgt::onLogout);
        connect (ui->pushButtonNext, &QPushButton::clicked,
                 this, &MainWgt::goToNextStep);
        connect (ui->pushButtonStart, &QPushButton::clicked,
                 this, &MainWgt::onStart);
    }

    goToNextStep ();
}

void MainWgt::onErrorHandling (QString title, QString what, QString where, QString details)
{
    auto dlg = new ErrorHandlingDlg (title, what, where, details, this);
    dlg->exec();
}

void MainWgt::onSuccessInstall ()
{
    ui->finished->setSuccess ();
    goToNextStep ();
}

void MainWgt::onFailInstall ()
{
    ui->finished->setFail ();
    goToNextStep ();
}

void MainWgt::onLogout ()
{
    curStep = SignUpSteps::login_signup;
    goToCurStep ();
}

void MainWgt::onStart ()
{
    curStep = SignUpSteps::installing;
    goToCurStep ();
}

void MainWgt::onLoginSignUp ()
{
    //UI/UX test - in API part must be encrypted
    {
        QSettings settings;
        auto name = settings.value (defAppName).toString ();
        ui->labelStatus->setText ("Logged in as : " + name);
    }
    goToNextStep ();
}

void MainWgt::goToCurStep ()
{
    int iStep = static_cast<int> (curStep);
    for(int i=1; i<iStep; i++) {
        auto stepWgt = findChild<StepWgt *>("widgetStep" + QString::number(i));
        stepWgt->setMode("Completed");
    }

    {
        auto stepWgt = findChild<StepWgt *>("widgetStep" + QString::number(iStep));
        stepWgt->setMode("Current");
    }

    for(int i=iStep+1; i<static_cast<int>(SignUpSteps::num_steps); i++) {
        auto stepWgt = findChild<StepWgt *>("widgetStep" + QString::number(i));
        stepWgt->setMode("NotCompleted");
    }

    if (curStep == SignUpSteps::finished) {
        auto stepWgt = findChild<StepWgt *>("widgetStep" + QString::number(static_cast<int>(SignUpSteps::finished)));
        stepWgt->setMode("Completed");
    }


    ui->pushButtonLogout->show ();
    ui->pushButtonStart->show ();
    ui->pushButtonNext->hide ();
    ui->pushButtonLogout->setEnabled (true);
    ui->pushButtonStart->setEnabled (true);
    ui->pushButtonStart->setText ("Start");

    if(curStep == SignUpSteps::login_signup) {
        ui->labelStatus->setText ("Not logged in");
        ui->stackedWidgetWorkArea->setCurrentWidget (ui->loginSignUp);
        ui->loginSignUp->clear ();
        ui->pushButtonLogout->hide ();
        ui->pushButtonStart->hide ();
    }
    else if(curStep == SignUpSteps::deviceInfo) {
        ui->stackedWidgetWorkArea->setCurrentWidget (ui->deviceInfo);
        ui->pushButtonStart->hide ();
        ui->pushButtonNext->show ();
    }
    else if(curStep == SignUpSteps::customerInfo)
        ui->stackedWidgetWorkArea->setCurrentWidget (ui->customerInfo);
    else if(curStep == SignUpSteps::installing) {
        ui->stackedWidgetWorkArea->setCurrentWidget (ui->installing);
        ui->installing->startInstalling ();
        ui->pushButtonLogout->setEnabled (false);
        ui->pushButtonStart->setEnabled (false);
    }
    else if(curStep == SignUpSteps::finished) {
        ui->stackedWidgetWorkArea->setCurrentWidget (ui->finished);
        ui->pushButtonStart->setText ("Start New");
    }
}

void MainWgt::goToNextStep ()
{
    if (SignUpSteps::num_steps == curStep) {
        qCritical () << "can not go to next step, last step";
        return;
    }
    curStep = static_cast<SignUpSteps> (static_cast<int> (curStep) + 1);
    goToCurStep ();
}

MainWgt::~MainWgt()
{
    delete ui;
}
