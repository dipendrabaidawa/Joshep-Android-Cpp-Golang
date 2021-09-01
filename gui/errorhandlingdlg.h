#ifndef ERRORHANDLINGDLG_H
#define ERRORHANDLINGDLG_H

#include <QDialog>

namespace Ui {
class ErrorHandlingDlg;
}

class ErrorHandlingDlg : public QDialog
{
    Q_OBJECT

public:
    explicit ErrorHandlingDlg(QString title, QString what, QString where, QString details, QWidget *parent = nullptr);

    ~ErrorHandlingDlg();

private:
    Ui::ErrorHandlingDlg *ui;

private slots:
    void onShowDetails ();

    void onHideDetails ();

    void onCopy ();
};

#endif // ERRORHANDLINGDLG_H
