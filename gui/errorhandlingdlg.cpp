#include "errorhandlingdlg.h"
#include "ui_errorhandlingdlg.h"

#include <QClipboard>

#include <QMessageBox>
ErrorHandlingDlg::ErrorHandlingDlg (QString title, QString what, QString where, QString details, QWidget *parent) :
    QDialog (parent),
    ui (new Ui::ErrorHandlingDlg)
{
    ui->setupUi (this);

    connect (ui->pushButtonDetailsShow, &QPushButton::clicked,
             this, &ErrorHandlingDlg::onShowDetails);
    connect (ui->pushButtonDetailsHide, &QPushButton::clicked,
             this, &ErrorHandlingDlg::onHideDetails);
    connect (ui->pushButtonCopy, &QPushButton::clicked,
             this, &ErrorHandlingDlg::onCopy);
    connect (ui->pushButtonOk, &QPushButton::clicked,
             this, &ErrorHandlingDlg::accept);

    setWindowTitle (title);
    ui->labelWhatValue->setText (what);
    ui->labelWhereValue->setText (where);
    ui->plainTextEditDetails->setPlainText (details);

    onHideDetails ();
}

ErrorHandlingDlg::~ErrorHandlingDlg ()
{
    delete ui;
}

void ErrorHandlingDlg::onShowDetails ()
{
    ui->plainTextEditDetails->show ();
    ui->wgtHide->show ();
    ui->labelDetailsTitleShow->hide ();
    ui->pushButtonDetailsShow->hide ();
    adjustSize ();
}

void ErrorHandlingDlg::onHideDetails ()
{
    ui->plainTextEditDetails->hide ();
    ui->wgtHide->hide ();
    ui->labelDetailsTitleShow->show ();
    ui->pushButtonDetailsShow->show ();
    adjustSize ();
}

void ErrorHandlingDlg::onCopy ()
{
    QGuiApplication::clipboard()->setText (ui->plainTextEditDetails->toPlainText ());
}
