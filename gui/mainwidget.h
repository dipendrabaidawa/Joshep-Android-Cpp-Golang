#ifndef LOGINSIGNOUTWGT_H
#define LOGINSIGNOUTWGT_H

#include <QWidget>

namespace Ui {
class MainWgt;
}

class MainWgt : public QWidget
{
    Q_OBJECT
    enum class SignUpSteps {undef_step,     //only to first call goToNextStep
                            login_signup,
                            deviceInfo, customerInfo,
                            installing, finished,
                            num_steps = finished};
public:
    explicit MainWgt(QWidget *parent = nullptr);
    ~MainWgt();

private:
    Ui::MainWgt *ui;

    SignUpSteps curStep {SignUpSteps::undef_step};

    void goToCurStep ();

private slots:
    void goToNextStep ();

    void onLoginSignUp ();

    void onLogout ();

    void onStart ();

    void onSuccessInstall ();

    void onFailInstall ();

    void onErrorHandling (QString title, QString what, QString where, QString details);

};

#endif // LOGINSIGNOUTWGT_H
