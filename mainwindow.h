#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include "steganographycore.h"
#include "passwordvalidator.h"

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void on_browseInputFileButton_hide_clicked();
    void on_browseCoverImageButton_hide_clicked();
    void on_passwordLineEdit_hide_textChanged(const QString &arg1);
    void on_hideButton_clicked();

    void on_browseStegoImageButton_extract_clicked();
    void on_passwordLineEdit_extract_textChanged(const QString &arg1);
    void on_extractButton_clicked();

    void updateHideButtonState();
    void updateExtractButtonState();

    void handleProgress(int percentage);
    void handleStatus(const QString& statusMessage);


private:
    Ui::MainWindow *ui;
    SteganographyCore m_stegoCore;
    QString m_inputFilePath_hide;
    QString m_coverImagePath_hide;
    QString m_stegoImagePath_extract;
};
#endif // MAINWINDOW_H
