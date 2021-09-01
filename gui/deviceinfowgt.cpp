#include "deviceinfowgt.h"
#include "ui_deviceinfowgt.h"

#include <QtConcurrent>
#include <QProcess>
#include <QMetaEnum>

#include "adbwrapper.h"
#include "utils.h"

DeviceInfoWgt::DeviceInfoWgt(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::DeviceInfoWgt)
{
    ui->setupUi(this);

    connect (ui->pushButtonConnectDevice, &QPushButton::clicked,
             this, &DeviceInfoWgt::onConnectDevice);
    connect (&devInfoFutureWatcher, &QFutureWatcher<DeviceInfo>::finished,
             this, &DeviceInfoWgt::onDevInfoUpdated);

    onConnectDevice ();
}

void DeviceInfoWgt::onConnectDevice ()
{
    auto future = QtConcurrent::run (&DeviceInfoWgt::updateDevInfo, this);
    devInfoFutureWatcher.setFuture (future);
    ui->pushButtonConnectDevice->setEnabled (false);
}

void DeviceInfoWgt::onDevInfoUpdated ()
{
    auto newDevInfo = devInfoFutureWatcher.result ();

    changeProperty (ui->labelConnectionStatus_value, "Status", newDevInfo.isConnected ? "success" : "fail");
    if (newDevInfo.isConnected)
        ui->labelConnectionStatus_value->setText ("CONNECTED");
    else
        ui->labelConnectionStatus_value->setText ("DEVICE NOT DETECTED");

    ui->labelIMEI_value->setText (newDevInfo.imei);
    ui->labelManufacturer_value->setText (newDevInfo.manufacturer);
    ui->labelModel_value->setText (newDevInfo.model);
    ui->labelVersion_value->setText (newDevInfo.version);
    ui->labelSerialNumber_value->setText (newDevInfo.serialNumber);
    ui->labelDevicePhoneNumber_value->setText (newDevInfo.devicePhoneNumber);

    ui->pushButtonConnectDevice->setEnabled (true);

    if (newDevInfo.isError)
        emit sigError ( "Error: Adb Module",
                        AdbWrapper::errorWhat(newDevInfo.error),
                        AdbWrapper::errorWhere(),
                        AdbWrapper::errorDetails(newDevInfo.error));
}

DeviceInfoWgt::~DeviceInfoWgt()
{
    delete ui;
}

DeviceInfoWgt::DeviceInfo DeviceInfoWgt::updateDevInfo ()
{
    DeviceInfo res;

    res.isConnected = AdbWrapper::checkDevices (res.isError, res.error);
    if (!res.isError)
        res.imei = AdbWrapper::getIMEI (res.isError, res.error);
    if (!res.isError)
        res.manufacturer = AdbWrapper::getManufacturer (res.isError, res.error);
    if (!res.isError)
        res.model = AdbWrapper::getModel (res.isError, res.error);
    if (!res.isError)
        res.version = AdbWrapper::getVersion (res.isError, res.error);
    if (!res.isError)
        res.serialNumber = AdbWrapper::getSerialNumber (res.isError, res.error);
    if (!res.isError)
        res.devicePhoneNumber = AdbWrapper::getDevicePhoneNumber (res.isError, res.error);

    return res;
}

