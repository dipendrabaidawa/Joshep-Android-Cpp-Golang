#ifndef FINISHEDWGT_H
#define FINISHEDWGT_H

#include <QWidget>

namespace Ui {
class FinishedWgt;
}

class FinishedWgt : public QWidget
{
    Q_OBJECT

public:
    explicit FinishedWgt(QWidget *parent = nullptr);

    ~FinishedWgt();

    void setSuccess ();

    void setFail ();

private:
    Ui::FinishedWgt *ui;
};

#endif // FINISHEDWGT_H
