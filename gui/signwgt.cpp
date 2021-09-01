#include "signwgt.h"
#include "ui_signwgt.h"

#include <QSettings>

#include "utils.h"
#include "settingkeys.h"

//UI/UX test - in API part must be removed
#define defInvitationCode "1234"

SignWgt::SignWgt(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::SignWgt)
{
    ui->setupUi(this);

    connect (ui->labelLogin, &QLabel::linkActivated,
             this, &SignWgt::sigLogin);
    connect (ui->pushButtonQuestion, &QPushButton::clicked,
             this, &SignWgt::onQuestion);
    connect (ui->pushButtonInvitationCode, &QPushButton::clicked,
             this, &SignWgt::onSend);
    connect (ui->pushButtonSignUp, &QPushButton::clicked,
             this, &SignWgt::onSignUp);
    connect (ui->lineEditInvitationCode, &QLineEdit::textChanged,
             this, &SignWgt::onActivationCodeChanged);
    connect (ui->checkBoxTermsPrivacy, &QCheckBox::stateChanged,
             this, &SignWgt::checkConditionsSignUp);
    connect (ui->lineEditPassword, &QLineEdit::textChanged,
             this, &SignWgt::checkConditionsSignUp);
    connect (ui->lineEditRetypePassword, &QLineEdit::textChanged,
             this, &SignWgt::checkConditionsSignUp);

    onlyInviationView (false, true);
    checkConditionsSignUp ();
    ui->pushButtonInvitationCode->setEnabled (false);
    ui->lineEditPassword->setEchoMode (QLineEdit::Password);
    ui->lineEditRetypePassword->setEchoMode (QLineEdit::Password);
}

SignWgt::~SignWgt()
{
    delete ui;
}

void SignWgt::clear ()
{
    auto lineEdits = findChildren<QLineEdit *>();
    foreach (auto edit, lineEdits)
        edit->clear ();
    ui->labelStatusInvitationCode->clear ();
}

void SignWgt::onSignUp ()
{
    QSettings settings;
    //UI/UX test - in API part must be encrypted
    {
        auto email = ui->lineEditEmail->text ();
        settings.setValue (defAppEmail, email);
        auto password = ui->lineEditPassword->text ();
        settings.setValue (defAppPassword, password);
        auto name = ui->lineEditName->text ();
        settings.setValue (defAppName, name);
        emit sigSuccess ();
    }
}

void SignWgt::onQuestion ()
{
    auto mode = ui->lineEditPassword->echoMode ();
    ui->lineEditPassword->setEchoMode (mode == QLineEdit::Normal ? QLineEdit::Password : QLineEdit::Normal);
    ui->lineEditRetypePassword->setEchoMode (mode == QLineEdit::Normal ? QLineEdit::Password : QLineEdit::Normal);
}

void SignWgt::onActivationCodeChanged ()
{
    ui->pushButtonInvitationCode->setEnabled (!ui->lineEditInvitationCode->text().isEmpty ());
}

void SignWgt::onSend ()
{
    //UI/UX test - in API part must be removed
    {
        auto code = ui->lineEditInvitationCode->text ();
        onlyInviationView (defInvitationCode == code);
    }
}

void SignWgt::checkConditionsSignUp ()
{
    bool cahSignUp = true;

    changeProperty (ui->labelRePasswordStatus, "Status", "");
    ui->labelRePasswordStatus->clear ();

    if (!ui->checkBoxTermsPrivacy->isChecked ())
        cahSignUp = false;
    if (ui->lineEditPassword->text().isEmpty())
        cahSignUp = false;
    if (ui->lineEditPassword->text() != ui->lineEditRetypePassword->text()) {
        cahSignUp = false;
        changeProperty (ui->labelRePasswordStatus, "Status", "fail");
        ui->labelRePasswordStatus->setText ("Password not the same");
    }

    ui->pushButtonSignUp->setEnabled (cahSignUp);
}

void SignWgt::onlyInviationView (bool activated, bool init)
{
    auto wgts = findChildren <QWidget *> ();
    foreach (auto wgt, wgts)
        wgt->setHidden (!activated);

    if (activated) {
        changeProperty (ui->labelStatusInvitationCode, "Status", "success");
        ui->labelStatusInvitationCode->setText ("Invation accepted");

    }
    else {
        if (!init) {
            changeProperty (ui->labelStatusInvitationCode, "Status", "fail");
            ui->labelStatusInvitationCode->setText("Invation declined");
        }
        else
            ui->labelStatusInvitationCode->clear ();

        ui->labelStatusInvitationCode->show ();
        ui->labelInvitationCode->show ();
        ui->invitationWgt->show ();
        ui->lineEditInvitationCode->show ();
        ui->pushButtonInvitationCode->show ();
        ui->labelLogin->show ();
    }

}
