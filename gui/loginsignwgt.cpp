#include "loginsignwgt.h"
#include "ui_loginsignwgt.h"

#include <QSettings>
#include <QMetaType>
#include <QtGlobal>

#include "settingkeys.h"

LoginSignWgt::LoginSignWgt (QWidget *parent) :
    QWidget (parent),
    ui (new Ui::LoginSignWgt)
{
    ui->setupUi (this);

    //connects
    {
        connect (ui->login, &LoginWgt::sigForgotPasswordActivated,
                 this, &LoginSignWgt::onForgotPasswordActivated);

        connect (ui->login, &LoginWgt::sigSignUp,
                 this, &LoginSignWgt::onSignUp);

        connect (ui->password, &PasswordWgt::sigLogin,
                 this, &LoginSignWgt::onLogin);

        connect (ui->signUp, &SignWgt::sigLogin,
                 this, &LoginSignWgt::onLogin);

        connect (ui->login, &LoginWgt::sigSuccess,
                 this, &LoginSignWgt::sigSuccess);

        connect (ui->signUp, &SignWgt::sigSuccess,
                 this, &LoginSignWgt::sigSuccess);
    }

    //show login/sign up
    {
        QSettings settings;
        QWidget * curWgt = ui->login;
#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
        if (!settings.value(defAppEmail).canConvert (QMetaType (QMetaType::QString)) ||
            !settings.value(defAppPassword).canConvert (QMetaType (QMetaType::QString)) ||
            !settings.value(defAppName).canConvert (QMetaType (QMetaType::QString)))
#else
        if (!settings.value(defAppEmail).canConvert (QMetaType::QString) ||
            !settings.value(defAppPassword).canConvert (QMetaType::QString) ||
            !settings.value(defAppName).canConvert (QMetaType::QString))
#endif
            curWgt = ui->signUp;
        ui->stackedWidget->setCurrentWidget(curWgt);
    }
}

LoginSignWgt::~LoginSignWgt ()
{
    delete ui;
}

void LoginSignWgt::clear ()
{
    ui->password->clear ();
    ui->signUp->clear ();
    ui->login->clear ();
}

void LoginSignWgt::onForgotPasswordActivated ()
{
    ui->password->clear ();
    ui->stackedWidget->setCurrentWidget(ui->password);
}

void LoginSignWgt::onSignUp ()
{
    ui->signUp->clear ();
    ui->stackedWidget->setCurrentWidget(ui->signUp);
}

void LoginSignWgt::onLogin ()
{
    ui->login->clear ();
    ui->stackedWidget->setCurrentWidget(ui->login);
}
