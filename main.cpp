#include <QApplication>
#include <QFile>

#include "mainview.h"
#include "gui/mainwidget.h"
#include "gui/deviceinfowgt.h"

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);

    qRegisterMetaType<DeviceInfoWgt::DeviceInfo>("DeviceInfo");

    QCoreApplication::setOrganizationName("apkinstaller");
    QCoreApplication::setOrganizationDomain("apkinstaller");
    QCoreApplication::setApplicationName ("apkinstaller");
    //install css
    {
        QFile file(":/gui/css/dark.css");
        if(file.open(QIODevice::ReadOnly))
        {
            QString css = file.readAll();
            a.setStyleSheet(css);
        }
    }

    //MainView w;
    MainWgt w;
    w.show();
    return a.exec();
}
