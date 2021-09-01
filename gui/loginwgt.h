#ifndef LOGINWGT_H
#define LOGINWGT_H

#include <QWidget>

class QShowEvent;

namespace Ui {
class LoginWgt;
}

class LoginWgt : public QWidget
{
    Q_OBJECT

public:
    explicit LoginWgt(QWidget *parent = nullptr);

    ~LoginWgt();

    void clear ();

protected:
    void showEvent(QShowEvent *event);

private:
    Ui::LoginWgt *ui;

private slots:
    void onQuestion ();

    void onLogin ();

    void checkConditionsLogin ();

signals:
    void sigForgotPasswordActivated ();

    void sigSignUp ();

    void sigSuccess ();

};

#endif // LOGINWGT_H
