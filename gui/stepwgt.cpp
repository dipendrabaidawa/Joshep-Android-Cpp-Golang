#include "stepwgt.h"
#include "ui_stepwgt.h"

#include "utils.h"

StepWgt::StepWgt(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::StepWgt)
{
    ui->setupUi(this);
    changeProperty(ui->labelMarker, "mode", "NotCompleted");
    changeProperty(ui->labelDescription, "mode", "NotCompleted");
}

void StepWgt::setDescription(QString description)
{
    ui->labelDescription->setText(description);
}

void StepWgt::setMode(QString mode)
{
    changeProperty(ui->labelMarker, "mode", mode);
    changeProperty(ui->labelDescription, "mode", mode);
    update();
}

StepWgt::~StepWgt()
{
    delete ui;
}
