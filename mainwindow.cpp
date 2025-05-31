#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QFileDialog>
#include <QMessageBox>
#include <QFileInfo>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow) {
    ui->setupUi(this);
    this->setWindowTitle("Steganography App");
    updateHideButtonState();
    updateExtractButtonState();
}

MainWindow::~MainWindow() {
    delete ui;
}

void MainWindow::on_browseInputFileButton_hide_clicked() {
    m_inputFilePath_hide = QFileDialog::getOpenFileName(this, "Select File to Hide", "", "All Files (*.*)");
    ui->inputFileLineEdit_hide->setText(m_inputFilePath_hide);
    updateHideButtonState();
}

void MainWindow::on_browseCoverImageButton_hide_clicked() {
    m_coverImagePath_hide = QFileDialog::getOpenFileName(this, "Select Cover Image", "", "Images (*.png *.jpg *.jpeg *.bmp)"); // Разрешаем разные форматы на вход
    ui->coverImageLineEdit_hide->setText(m_coverImagePath_hide);
    updateHideButtonState();
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
    ui->hideButton->setEnabled(passwordOk && filesOk);
}

void MainWindow::on_hideButton_clicked() {
    QString outputStegoImagePath = QFileDialog::getSaveFileName(
        this,
        "Save Stego Image As (PNG)",
        "",
        "PNG Images (*.png);;All Files (*.*)"
        );
    if (outputStegoImagePath.isEmpty()) return;

    QFileInfo fileInfo(outputStegoImagePath);
    if (fileInfo.suffix().toLower() != "png") {
        outputStegoImagePath = fileInfo.path() + "/" + fileInfo.completeBaseName() + ".png";
    }

    ui->hideButton->setEnabled(false);
    ui->statusLabel_hide->setText("Status: Processing...");
    ui->progressBar_hide->setValue(0);

    bool success = m_stegoCore.hideFileInImage(
        m_inputFilePath_hide,
        m_coverImagePath_hide,
        outputStegoImagePath,
        ui->passwordLineEdit_hide->text(),
        [this](int p){ this->handleProgress(p); QApplication::processEvents(); },
        [this](const QString& s){ this->handleStatus(s); QApplication::processEvents(); }
        );

    ui->hideButton->setEnabled(true);
    updateHideButtonState();

    if (success) {
        QMessageBox::information(this, "Success", "File hidden successfully in " + outputStegoImagePath);
    } else {
        QMessageBox::critical(this, "Error", "Failed to hide file. Check status messages.");
    }
    ui->progressBar_hide->setValue(0);
}

void MainWindow::on_browseStegoImageButton_extract_clicked() {
    m_stegoImagePath_extract = QFileDialog::getOpenFileName(this, "Select Stego Image", "", "Images (*.png *.jpg *.jpeg *.bmp)");
    ui->stegoImageLineEdit_extract->setText(m_stegoImagePath_extract);
    updateExtractButtonState();
}

void MainWindow::on_passwordLineEdit_extract_textChanged(const QString &arg1) {
    Q_UNUSED(arg1);
    updateExtractButtonState();
}

void MainWindow::updateExtractButtonState() {
    bool passwordOk = !ui->passwordLineEdit_extract->text().isEmpty();
    bool fileOk = !m_stegoImagePath_extract.isEmpty();
    ui->extractButton->setEnabled(passwordOk && fileOk);
}

void MainWindow::on_extractButton_clicked() {
    QString outputDir = QFileDialog::getExistingDirectory(this, "Select Directory to Save Extracted File");
    if (outputDir.isEmpty()) return;

    ui->extractButton->setEnabled(false);
    ui->statusLabel_extract->setText("Status: Processing...");
    ui->progressBar_extract->setValue(0);
    QString originalFileName;

    bool success = m_stegoCore.extractFileFromImage(
        m_stegoImagePath_extract,
        outputDir,
        ui->passwordLineEdit_extract->text(),
        [this](int p){ ui->progressBar_extract->setValue(p); QApplication::processEvents(); },
        [this](const QString& s){ ui->statusLabel_extract->setText("Status: " + s); QApplication::processEvents(); },
        originalFileName
        );

    ui->extractButton->setEnabled(true);
    updateExtractButtonState();

    if (success) {
        QMessageBox::information(this, "Success", "File extracted successfully as " + originalFileName + " in " + outputDir);
    } else {
        QMessageBox::critical(this, "Error", "Failed to extract file. Check status messages.");
    }
    ui->progressBar_extract->setValue(0);
}

void MainWindow::handleProgress(int percentage) {
    ui->progressBar_hide->setValue(percentage);
}

void MainWindow::handleStatus(const QString& statusMessage) {
    ui->statusLabel_hide->setText("Status: " + statusMessage);
}
