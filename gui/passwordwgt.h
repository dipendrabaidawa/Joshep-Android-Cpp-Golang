#ifndef PASSWORDWGT_H
#define PASSWORDWGT_H

#include <QWidget>

namespace Ui {
class PasswordWgt;
}

class PasswordWgt : public QWidget
{
    Q_OBJECT

public:
    explicit PasswordWgt(QWidget *parent = nullptr);

    ~PasswordWgt();

    void clear ();

private:
    Ui::PasswordWgt *ui;

signals:
    void sigLogin ();

};

#endif // PASSWORDWGT_H
