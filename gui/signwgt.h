#ifndef SIGNWGT_H
#define SIGNWGT_H

#include <QWidget>

namespace Ui {
class SignWgt;
}

class SignWgt : public QWidget
{
    Q_OBJECT

public:
    explicit SignWgt(QWidget *parent = nullptr);

    ~SignWgt();

    void clear ();

private:
    Ui::SignWgt *ui;

    void onlyInviationView (bool activated, bool init = false);

private slots:
    void onQuestion ();

    void onSend ();

    void onActivationCodeChanged ();

    void checkConditionsSignUp ();

    void onSignUp ();

signals:
    void sigLogin ();

    void sigSuccess ();
};

#endif // SIGNWGT_H
