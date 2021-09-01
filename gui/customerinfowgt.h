#ifndef CUSTOMERINFOWGT_H
#define CUSTOMERINFOWGT_H

#include <QWidget>

namespace Ui {
class CustomerInfoWgt;
}

class CustomerInfoWgt : public QWidget
{
    Q_OBJECT

public:
    explicit CustomerInfoWgt(QWidget *parent = nullptr);
    ~CustomerInfoWgt();

private:
    Ui::CustomerInfoWgt *ui;

private slots:
    void onParentalBlockChanged ();

    void onCommunityChanged ();

    void onOptionalRestrictionsChanged ();
};

#endif // CUSTOMERINFOWGT_H
