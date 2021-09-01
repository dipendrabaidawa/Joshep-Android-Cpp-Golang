#include "finishedwgt.h"
#include "ui_finishedwgt.h"

#include "utils.h"

FinishedWgt::FinishedWgt (QWidget *parent) :
    QWidget (parent),
    ui (new Ui::FinishedWgt)
{
    ui->setupUi (this);
}

void FinishedWgt::setSuccess ()
{
    changeProperty (ui->labelStatus, "Status", "success");
    ui->labelStatus->setText ("Installation successful!");
}

void FinishedWgt::setFail ()
{
    changeProperty (ui->labelStatus, "Status", "fail");
    ui->labelStatus->setText ("Installation failed.");
}

FinishedWgt::~FinishedWgt ()
{
    delete ui;
}
