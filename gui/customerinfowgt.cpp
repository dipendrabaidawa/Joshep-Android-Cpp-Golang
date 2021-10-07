#include "customerinfowgt.h"
#include "ui_customerinfowgt.h"

#include <QStyle>

CustomerInfoWgt::CustomerInfoWgt(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::CustomerInfoWgt)
{
    ui->setupUi(this);

    connect (ui->comboBoxParentalBlock, &QComboBox::currentTextChanged,
             this, &CustomerInfoWgt::onParentalBlockChanged);
    connect (ui->comboBoxCommunity, &QComboBox::currentTextChanged,
             this, &CustomerInfoWgt::onCommunityChanged);
    connect (ui->comboBoxOptionalRestrictions, &QComboBox::currentTextChanged,
             this, &CustomerInfoWgt::onOptionalRestrictionsChanged);

    auto lineEdits = findChildren<QLineEdit *> ();
    foreach (auto edit, lineEdits) {
        QPalette pal;
        pal.setColor(QPalette::PlaceholderText, Qt::darkGray);
        edit->setPalette(pal);
    }

    onParentalBlockChanged ();
    onCommunityChanged ();
    onOptionalRestrictionsChanged ();
}

void CustomerInfoWgt::onOptionalRestrictionsChanged ()
{
    bool isOn = ("Yes" == ui->comboBoxOptionalRestrictions->currentText ());
    ui->listWidgetOptionalRestrictions->setHidden (!isOn);
}

void CustomerInfoWgt::onCommunityChanged ()
{
    bool isOn = ("Meshimer" == ui->comboBoxCommunity->currentText ());
    ui->labelMeshimer->setHidden (!isOn);
    ui->comboBoxMeshimer->setHidden (!isOn);
}

void CustomerInfoWgt::onParentalBlockChanged ()
{
    bool isOn = ("Yes" == ui->comboBoxParentalBlock->currentText ());
    ui->lineEditParentalPhoneNumber->setHidden (!isOn);
    ui->lineEditParentalCode->setHidden (!isOn);
}

CustomerInfoWgt::~CustomerInfoWgt()
{
    delete ui;
}
