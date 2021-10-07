#include <QStyle>
#include <QVariant>
#include <QWidget>
#include <QStandardPaths>
#include <QDir>

#include <string>

#include "utils.h"

void changeProperty(QWidget * wgt, const char *property, QVariant value)
{
    wgt->setProperty(property, value);
    wgt->style()->unpolish(wgt);
    wgt->style()->polish(wgt);
}
