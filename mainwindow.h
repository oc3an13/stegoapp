#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include "steganographycore.h"
#include "passwordvalidator.h"
#include <QFutureWatcher>

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

signals:
    void updateProgressBarSignal(int percentage);
    void updateStatusLabelSignal(const QString& statusMessage);

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

    void handleUpdateProgressBar(int percentage);
    void handleUpdateStatusLabel(const QString& statusMessage);
    void handleHideOperationFinished();
    void handleExtractOperationFinished();

private:
    Ui::MainWindow *ui;
    SteganographyCore m_stegoCore;

    QString m_inputFilePath_hide;
    QString m_coverImagePath_hide;
    QString m_stegoImagePath_extract;

    QFutureWatcher<bool> m_hideOperationWatcher;
    QFutureWatcher<bool> m_extractOperationWatcher;

    struct HideParams {
        QString inputFilePath;
        QString coverImagePath;
        QString outputStegoImagePath;
        QString password;
    };
    HideParams m_currentHideParams;

    struct ExtractParams {
        QString stegoImagePath;
        QString outputDirectory;
        QString password;
        QString originalFileNameResult;
    };
    ExtractParams m_currentExtractParams;
};
#endif // MAINWINDOW_H
