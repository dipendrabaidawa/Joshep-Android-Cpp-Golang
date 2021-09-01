#ifndef STEPWGT_H
#define STEPWGT_H

#include <QWidget>

namespace Ui {
class StepWgt;
}

class StepWgt : public QWidget
{
    Q_OBJECT

public:
    explicit StepWgt(QWidget *parent = nullptr);
    ~StepWgt();
    void setDescription(QString description);
    void setMode(QString mode);
private:
    Ui::StepWgt *ui;
};

#endif // STEPWGT_H
