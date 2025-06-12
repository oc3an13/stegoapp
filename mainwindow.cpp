#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QFileDialog>
#include <QMessageBox>
#include <QDebug>
#include <QFileInfo>
#include <QtConcurrent/QtConcurrent>
#include <QThread>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow) {
    ui->setupUi(this);
    this->setWindowTitle("Steganography App");

    connect(this, &MainWindow::updateProgressBarSignal, this, &MainWindow::handleUpdateProgressBar);
    connect(this, &MainWindow::updateStatusLabelSignal, this, &MainWindow::handleUpdateStatusLabel);

    connect(&m_hideOperationWatcher, &QFutureWatcher<bool>::finished, this, &MainWindow::handleHideOperationFinished);
    connect(&m_extractOperationWatcher, &QFutureWatcher<bool>::finished, this, &MainWindow::handleExtractOperationFinished);

    updateHideButtonState();
    updateExtractButtonState();
}

MainWindow::~MainWindow() {
    m_hideOperationWatcher.cancel();
    m_extractOperationWatcher.cancel();
    m_hideOperationWatcher.waitForFinished();
    m_extractOperationWatcher.waitForFinished();
    delete ui;
}

void MainWindow::handleUpdateProgressBar(int percentage) {
    if (ui->tabWidget->currentIndex() == 0) {
        ui->progressBar_hide->setValue(percentage);
    } else {
        ui->progressBar_extract->setValue(percentage);
    }
}

void MainWindow::handleUpdateStatusLabel(const QString& statusMessage) {
    qDebug() << "Threaded Status: " << statusMessage;
    if (ui->tabWidget->currentIndex() == 0) {
        ui->statusLabel_hide->setText("Status: " + statusMessage);
    } else {
        ui->statusLabel_extract->setText("Status: " + statusMessage);
    }
}

void MainWindow::handleHideOperationFinished() {
    bool success = m_hideOperationWatcher.result();
    ui->hideButton->setEnabled(true);
    updateHideButtonState();

    if (success) {
        QMessageBox::information(this, "Success", "File hidden successfully in " + m_currentHideParams.outputStegoImagePath);
    } else {
        QMessageBox::critical(this, "Error", "Failed to hide file. Check status messages.");
    }
    if (success || ui->progressBar_hide->value() == 100) {
        ui->progressBar_hide->setValue(0);
    }
}

void MainWindow::handleExtractOperationFinished() {
    bool success = m_extractOperationWatcher.result();
    ui->extractButton->setEnabled(true);
    updateExtractButtonState();

    if (success) {
        QMessageBox::information(this, "Success", "File extracted successfully as " + m_currentExtractParams.originalFileNameResult + " in " + m_currentExtractParams.outputDirectory);
    } else {
        QMessageBox::critical(this, "Error", "Failed to extract file. Check status messages.");
    }
    if (success || ui->progressBar_extract->value() == 100) {
        ui->progressBar_extract->setValue(0);
    }
}

void MainWindow::on_browseInputFileButton_hide_clicked() {
    QString filePath = QFileDialog::getOpenFileName(this, "Select File to Hide", m_inputFilePath_hide, "All Files (*.*)");
    if (!filePath.isEmpty()) {
        m_inputFilePath_hide = filePath;
        ui->inputFileLineEdit_hide->setText(m_inputFilePath_hide);
    }
    updateHideButtonState();
}

void MainWindow::on_browseCoverImageButton_hide_clicked() {
    QString filePath = QFileDialog::getOpenFileName(this, "Select Cover Image (JPG or PNG)", m_coverImagePath_hide, "Images (*.jpg *.jpeg *.png)");
    if (!filePath.isEmpty()) {
        m_coverImagePath_hide = filePath;
        ui->coverImageLineEdit_hide->setText(m_coverImagePath_hide);
    }
    updateHideButtonState();
}

void MainWindow::on_browseStegoImageButton_extract_clicked() {
    QString filePath = QFileDialog::getOpenFileName(this, "Select Stego Image (PNG or JPG)", m_stegoImagePath_extract, "Images (*.png *.jpg *.jpeg)");
    if (!filePath.isEmpty()) {
        m_stegoImagePath_extract = filePath;
        ui->stegoImageLineEdit_extract->setText(m_stegoImagePath_extract);
    }
    updateExtractButtonState();
}

void MainWindow::on_passwordLineEdit_hide_textChanged(const QString &arg1) {
    bool isValid = PasswordValidator::isValid(arg1);
    PasswordValidator::Strength strength = PasswordValidator::getStrength(arg1);
    ui->passwordStrengthLabel_hide->setText("Strength: " + PasswordValidator::strengthToString(strength) + (isValid ? "" : " (Too weak)"));
    ui->passwordStrengthLabel_hide->setStyleSheet(isValid ? "QLabel { color : green; }" : "QLabel { color : red; }");
    updateHideButtonState();
}

void MainWindow::updateHideButtonState() {
    bool passwordOk = PasswordValidator::isValid(ui->passwordLineEdit_hide->text());
    bool filesOk = !m_inputFilePath_hide.isEmpty() && !m_coverImagePath_hide.isEmpty();
    ui->hideButton->setEnabled(passwordOk && filesOk && !m_hideOperationWatcher.isRunning());
}

void MainWindow::on_passwordLineEdit_extract_textChanged(const QString &arg1) {
    Q_UNUSED(arg1);
    updateExtractButtonState();
}

void MainWindow::updateExtractButtonState() {
    bool passwordOk = !ui->passwordLineEdit_extract->text().isEmpty();
    bool fileOk = !m_stegoImagePath_extract.isEmpty();
    ui->extractButton->setEnabled(passwordOk && fileOk && !m_extractOperationWatcher.isRunning());
}

void MainWindow::on_hideButton_clicked() {
    if (m_hideOperationWatcher.isRunning()) {
        QMessageBox::information(this, "In Progress", "Hide operation is already in progress.");
        return;
    }

    QString outputStegoImagePath = QFileDialog::getSaveFileName(
        this, "Save Stego Image As (PNG Recommended for LSB)", "",
        "PNG Images (*.png);;JPEG Images (*.jpg *.jpeg);;All Files (*.*)");
    if (outputStegoImagePath.isEmpty()) return;

    QFileInfo fileInfo(outputStegoImagePath);
    if (fileInfo.suffix().toLower() != "png") {
        outputStegoImagePath = fileInfo.path() + "/" + fileInfo.completeBaseName() + ".png";
    }

    m_currentHideParams.inputFilePath = m_inputFilePath_hide;
    m_currentHideParams.coverImagePath = m_coverImagePath_hide;
    m_currentHideParams.outputStegoImagePath = outputStegoImagePath;
    m_currentHideParams.password = ui->passwordLineEdit_hide->text();

    ui->hideButton->setEnabled(false);
    ui->statusLabel_hide->setText("Status: Processing (in background)...");
    ui->progressBar_hide->setValue(0);

    QFuture<bool> future = QtConcurrent::run([this]() {
        auto progressCb = [this](int p) { emit updateProgressBarSignal(p); };
        auto statusCb = [this](const QString& s) { emit updateStatusLabelSignal(s); };

        return m_stegoCore.hideFileInImage(
            m_currentHideParams.inputFilePath,
            m_currentHideParams.coverImagePath,
            m_currentHideParams.outputStegoImagePath,
            m_currentHideParams.password,
            progressCb,
            statusCb
            );
    });
    m_hideOperationWatcher.setFuture(future);
}

void MainWindow::on_extractButton_clicked() {
    if (m_extractOperationWatcher.isRunning()) {
        QMessageBox::information(this, "In Progress", "Extract operation is already in progress.");
        return;
    }

    QString outputDir = QFileDialog::getExistingDirectory(this, "Select Directory to Save Extracted File");
    if (outputDir.isEmpty()) return;

    m_currentExtractParams.stegoImagePath = m_stegoImagePath_extract;
    m_currentExtractParams.outputDirectory = outputDir;
    m_currentExtractParams.password = ui->passwordLineEdit_extract->text();

    ui->extractButton->setEnabled(false);
    ui->statusLabel_extract->setText("Status: Processing (in background)...");
    ui->progressBar_extract->setValue(0);

    QFuture<bool> future = QtConcurrent::run([this]() {
        auto progressCb = [this](int p) { emit updateProgressBarSignal(p); };
        auto statusCb = [this](const QString& s) { emit updateStatusLabelSignal(s); };

        return m_stegoCore.extractFileFromImage(
            m_currentExtractParams.stegoImagePath,
            m_currentExtractParams.outputDirectory,
            m_currentExtractParams.password,
            progressCb,
            statusCb,
            m_currentExtractParams.originalFileNameResult
            );
    });
    m_extractOperationWatcher.setFuture(future);
}
