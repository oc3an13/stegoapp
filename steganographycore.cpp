#include "steganographycore.h"
#include <QFile>
#include <QFileInfo>
#include <QDir>
#include <QDataStream>

#include <opencv2/opencv.hpp>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/err.h>

SteganographyCore::SteganographyCore() {
}

QByteArray SteganographyCore::deriveKeyFromPassword(const QString& password) {
    QByteArray passBytes = password.toUtf8();
    unsigned char hash[SHA256_DIGEST_LENGTH];
    EVP_MD_CTX *mdctx;
    const EVP_MD *md;
    unsigned int md_len;

    md = EVP_sha256();
    mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) {
        if (m_statusCb) m_statusCb("Error: EVP_MD_CTX_new failed for SHA256 derivation.");
        return QByteArray();
    }
    if (1 != EVP_DigestInit_ex(mdctx, md, NULL)) {
        if (m_statusCb) m_statusCb("Error: EVP_DigestInit_ex failed for SHA256 derivation.");
        EVP_MD_CTX_free(mdctx);
        return QByteArray();
    }
    if (1 != EVP_DigestUpdate(mdctx, passBytes.constData(), passBytes.length())) {
        if (m_statusCb) m_statusCb("Error: EVP_DigestUpdate failed for SHA256 derivation.");
        EVP_MD_CTX_free(mdctx);
        return QByteArray();
    }
    if (1 != EVP_DigestFinal_ex(mdctx, hash, &md_len)) {
        if (m_statusCb) m_statusCb("Error: EVP_DigestFinal_ex failed for SHA256 derivation.");
        EVP_MD_CTX_free(mdctx);
        return QByteArray();
    }
    EVP_MD_CTX_free(mdctx);
    if (md_len != SHA256_DIGEST_LENGTH) {
        if (m_statusCb) m_statusCb("Error: SHA256 derived hash length mismatch.");
        return QByteArray();
    }
    return QByteArray(reinterpret_cast<const char*>(hash), SHA256_DIGEST_LENGTH);
}

QByteArray SteganographyCore::aesEncrypt(const QByteArray& data, const QByteArray& key, const QByteArray& iv) {
    EVP_CIPHER_CTX *ctx = nullptr;
    QByteArray encryptedData;
    int len = 0;
    int ciphertext_len_update = 0;

    if(!(ctx = EVP_CIPHER_CTX_new())) {
        if (m_statusCb) m_statusCb("Error: EVP_CIPHER_CTX_new failed during encryption.");
        return QByteArray();
    }
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL,
                                reinterpret_cast<const unsigned char*>(key.constData()),
                                reinterpret_cast<const unsigned char*>(iv.constData()))) {
        if (m_statusCb) m_statusCb("Error: EVP_EncryptInit_ex failed.");
        EVP_CIPHER_CTX_free(ctx);
        return QByteArray();
    }
    unsigned char* out_buf = new unsigned char[data.length() + AES_BLOCK_SIZE_BYTES];
    if(1 != EVP_EncryptUpdate(ctx, out_buf, &len,
                               reinterpret_cast<const unsigned char*>(data.constData()), data.length())) {
        if (m_statusCb) m_statusCb("Error: EVP_EncryptUpdate failed.");
        delete[] out_buf;
        EVP_CIPHER_CTX_free(ctx);
        return QByteArray();
    }
    ciphertext_len_update = len;
    encryptedData.append(reinterpret_cast<const char*>(out_buf), ciphertext_len_update);

    if(1 != EVP_EncryptFinal_ex(ctx, out_buf + ciphertext_len_update, &len)) {
        if (m_statusCb) m_statusCb("Error: EVP_EncryptFinal_ex failed.");
        delete[] out_buf;
        EVP_CIPHER_CTX_free(ctx);
        return QByteArray();
    }
    encryptedData.append(reinterpret_cast<const char*>(out_buf + ciphertext_len_update), len);

    delete[] out_buf;
    EVP_CIPHER_CTX_free(ctx);
    return encryptedData;
}

QByteArray SteganographyCore::aesDecrypt(const QByteArray& encryptedData, const QByteArray& key, const QByteArray& iv) {
    EVP_CIPHER_CTX *ctx = nullptr;
    QByteArray decryptedData;
    int len = 0;
    int plaintext_len_update = 0;

    if(!(ctx = EVP_CIPHER_CTX_new())) {
        if (m_statusCb) m_statusCb("Error: EVP_CIPHER_CTX_new failed during decryption.");
        return QByteArray();
    }
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL,
                                reinterpret_cast<const unsigned char*>(key.constData()),
                                reinterpret_cast<const unsigned char*>(iv.constData()))) {
        if (m_statusCb) m_statusCb("Error: EVP_DecryptInit_ex failed.");
        EVP_CIPHER_CTX_free(ctx);
        return QByteArray();
    }
    unsigned char* out_buf = new unsigned char[encryptedData.length()];
    if(1 != EVP_DecryptUpdate(ctx, out_buf, &len,
                               reinterpret_cast<const unsigned char*>(encryptedData.constData()), encryptedData.length())) {
        if (m_statusCb) m_statusCb("Error: EVP_DecryptUpdate failed (possibly wrong key or corrupted data).");
        delete[] out_buf;
        EVP_CIPHER_CTX_free(ctx);
        return QByteArray();
    }
    plaintext_len_update = len;
    decryptedData.append(reinterpret_cast<const char*>(out_buf), plaintext_len_update);

    if(1 != EVP_DecryptFinal_ex(ctx, out_buf + plaintext_len_update, &len)) {
        if (m_statusCb) m_statusCb("Error: EVP_DecryptFinal_ex failed (possibly wrong key or corrupted data).");
        delete[] out_buf;
        EVP_CIPHER_CTX_free(ctx);
        return QByteArray();
    }
    decryptedData.append(reinterpret_cast<const char*>(out_buf + plaintext_len_update), len);

    delete[] out_buf;
    EVP_CIPHER_CTX_free(ctx);
    return decryptedData;
}

void SteganographyCore::setBit(unsigned char& byte, int bitPosition, bool value) {
    if (value) {
        byte |= (1 << bitPosition);
    } else {
        byte &= ~(1 << bitPosition);
    }
}

bool SteganographyCore::getBit(unsigned char byte, int bitPosition) {
    return (byte >> bitPosition) & 1;
}

bool SteganographyCore::embedData(cv::Mat& image, const QByteArray& dataToEmbed, ProgressCallback progressCb) {
    if (image.empty() || image.type() != CV_8UC3) {
        if (m_statusCb) m_statusCb("Error: Cover image is empty or not a 3-channel color image.");
        return false;
    }
    quint64 totalBitsToEmbed = static_cast<quint64>(dataToEmbed.size()) * 8;
    quint64 imageCapacityBits = static_cast<quint64>(image.rows) * image.cols * image.channels(); // 1 LSB per channel
    if (totalBitsToEmbed > imageCapacityBits) {
        if (m_statusCb) m_statusCb("Error: Not enough space in the image to hide the data.");
        return false;
    }
    int dataByteIndex = 0;
    int bitInCurrentByte = 0;
    quint64 bitsEmbedded = 0;
    for (int r = 0; r < image.rows; ++r) {
        for (int c = 0; c < image.cols; ++c) {
            cv::Vec3b& pixel = image.at<cv::Vec3b>(r, c);
            for (int ch = 0; ch < image.channels(); ++ch) {
                if (bitsEmbedded < totalBitsToEmbed) {
                    bool dataBit = getBit(dataToEmbed.at(dataByteIndex), bitInCurrentByte);
                    setBit(pixel[ch], 0, dataBit);
                    bitInCurrentByte++;
                    if (bitInCurrentByte == 8) {
                        bitInCurrentByte = 0;
                        dataByteIndex++;
                    }
                    bitsEmbedded++;
                    if (progressCb && bitsEmbedded % 20000 == 0) {
                        progressCb(static_cast<int>((bitsEmbedded * 100) / totalBitsToEmbed));
                    }
                } else {
                    if (progressCb) progressCb(100);
                    return true;
                }
            }
        }
    }
    if (progressCb) progressCb(100);
    return bitsEmbedded == totalBitsToEmbed;
}

QByteArray SteganographyCore::extractData(const cv::Mat& image, quint64 totalBitsToExtract, ProgressCallback progressCb) {
    if (image.empty() || image.type() != CV_8UC3) {
        if (m_statusCb) m_statusCb("Error: Stego image is empty or not a 3-channel color image.");
        return QByteArray();
    }
    quint64 imageCapacityBits = static_cast<quint64>(image.rows) * image.cols * image.channels();
    if (totalBitsToExtract > imageCapacityBits) {
        if (m_statusCb) m_statusCb("Error: Requested data length exceeds image capacity.");
        return QByteArray();
    }
    QByteArray extractedData;
    qsizetype bytesToExtract = static_cast<qsizetype>((totalBitsToExtract + 7) / 8);
    extractedData.resize(bytesToExtract);
    extractedData.fill(0);
    int dataByteIndex = 0;
    int bitInCurrentByte = 0;
    quint64 bitsExtracted = 0;
    for (int r = 0; r < image.rows; ++r) {
        for (int c = 0; c < image.cols; ++c) {
            const cv::Vec3b& pixel = image.at<cv::Vec3b>(r, c);
            for (int ch = 0; ch < image.channels(); ++ch) {
                if (bitsExtracted < totalBitsToExtract) {
                    bool dataBit = getBit(pixel[ch], 0);
                    unsigned char& currentByte = reinterpret_cast<unsigned char&>(extractedData.data()[dataByteIndex]);
                    setBit(currentByte, bitInCurrentByte, dataBit);
                    bitInCurrentByte++;
                    if (bitInCurrentByte == 8) {
                        bitInCurrentByte = 0;
                        dataByteIndex++;
                    }
                    bitsExtracted++;
                    if (progressCb && bitsExtracted % 20000 == 0) { // Update progress less frequently
                        progressCb(static_cast<int>((bitsExtracted * 100) / totalBitsToExtract));
                    }
                } else {
                    if (progressCb) progressCb(100);
                    return extractedData;
                }
            }
        }
    }
    if (progressCb) progressCb(100);
    return bitsExtracted == totalBitsToExtract ? extractedData : QByteArray();
}

bool SteganographyCore::hideFileInImage(const QString& inputFilePath,
                                        const QString& coverImagePath,
                                        const QString& outputStegoImagePathPassed,
                                        const QString& password,
                                        ProgressCallback progressCb,
                                        StatusCallback statusCbParamGlobal) {
    this->m_statusCb = statusCbParamGlobal;

    if (m_statusCb) m_statusCb("Starting hide process...");
    if (progressCb) progressCb(0);

    QFile inputFile(inputFilePath);
    if (!inputFile.open(QIODevice::ReadOnly)) {
        if (m_statusCb) m_statusCb("Error: Could not open input file: " + inputFile.errorString());
        return false;
    }
    QByteArray originalFileData = inputFile.readAll();
    inputFile.close();
    if (originalFileData.isEmpty() && inputFile.size() > 0) {
        if (m_statusCb) m_statusCb("Error: Failed to read input file content.");
        return false;
    }
    if (progressCb) progressCb(5);

    QFileInfo fileInfo(inputFilePath);
    QString originalFilename = fileInfo.fileName();
    QByteArray originalFilenameBytes = originalFilename.toUtf8();
    QByteArray metadata;
    QDataStream metaStream(&metadata, QIODevice::WriteOnly);
    metaStream << static_cast<quint32>(originalFilenameBytes.size());
    metaStream.writeRawData(originalFilenameBytes.constData(), originalFilenameBytes.size());
    metaStream << static_cast<quint64>(originalFileData.size());
    if (progressCb) progressCb(10);

    QByteArray payloadToEncrypt = metadata + originalFileData;
    QByteArray aesKey = deriveKeyFromPassword(password);
    if(aesKey.isEmpty()) return false;
    QByteArray iv(AES_IV_SIZE_BYTES, 0);
    if (RAND_bytes(reinterpret_cast<unsigned char*>(iv.data()), AES_IV_SIZE_BYTES) != 1) {
        if (m_statusCb) m_statusCb("Error: Could not generate random IV.");
        return false;
    }
    if (progressCb) progressCb(15);

    if (m_statusCb) m_statusCb("Encrypting data...");
    QByteArray encryptedPayload = aesEncrypt(payloadToEncrypt, aesKey, iv);
    if (encryptedPayload.isEmpty()) {
        return false;
    }
    if (progressCb) progressCb(30);

    QByteArray passwordHash = deriveKeyFromPassword(password);
    if(passwordHash.isEmpty()) return false;
    QByteArray dataToEmbed;
    QDataStream embedStream(&dataToEmbed, QIODevice::WriteOnly);
    embedStream.writeRawData(passwordHash.constData(), passwordHash.size());
    embedStream.writeRawData(iv.constData(), iv.size());
    embedStream << static_cast<quint64>(encryptedPayload.size());
    embedStream.writeRawData(encryptedPayload.constData(), encryptedPayload.size());
    if (progressCb) progressCb(35);

    if (m_statusCb) m_statusCb("Loading cover image...");
    cv::Mat coverImage = cv::imread(coverImagePath.toStdString(), cv::IMREAD_COLOR);
    if (coverImage.empty()) {
        if (m_statusCb) m_statusCb("Error: Could not load cover image: " + coverImagePath);
        return false;
    }
    if (coverImage.type() != CV_8UC3) {
        if (m_statusCb) m_statusCb("Error: Cover image must be a 3-channel color image.");
        return false;
    }
    if (progressCb) progressCb(40);

    if (m_statusCb) m_statusCb("Embedding data into image (LSB)...");
    if (!embedData(coverImage, dataToEmbed, [&](int p){ if(progressCb) progressCb(40 + (p*50/100)); })) {
        return false;
    }
    if (progressCb) progressCb(90);

    QString finalOutputStegoPath = outputStegoImagePathPassed;
    QFileInfo outputInfo(finalOutputStegoPath);

    if (outputInfo.suffix().toLower() != "png") {
        finalOutputStegoPath = outputInfo.path() + "/" + outputInfo.completeBaseName() + ".png";
        if (m_statusCb) m_statusCb("Note: Outputting as PNG for LSB reliability. Requested path: " + outputStegoImagePathPassed);
    }

    if (m_statusCb) m_statusCb("Saving stego image as PNG: " + finalOutputStegoPath);
    try {
        if (!cv::imwrite(finalOutputStegoPath.toStdString(), coverImage)) {
            if (m_statusCb) m_statusCb("Error: Could not save stego image as PNG: " + finalOutputStegoPath);
            return false;
        }
    } catch (const cv::Exception& ex) {
        if (m_statusCb) m_statusCb("OpenCV Error saving PNG image: " + QString(ex.what()));
        return false;
    }

    if (progressCb) progressCb(100);
    if (m_statusCb) m_statusCb("Hide process completed successfully. Output: " + finalOutputStegoPath);
    return true;
}

bool SteganographyCore::extractFileFromImage(const QString& stegoImagePath,
                                             const QString& outputDirectory,
                                             const QString& password,
                                             ProgressCallback progressCb,
                                             StatusCallback statusCbParamGlobal,
                                             QString& outOriginalFileName) {
    this->m_statusCb = statusCbParamGlobal;
    if (m_statusCb) m_statusCb("Starting extraction process...");
    if (progressCb) progressCb(0);

    cv::Mat stegoImage = cv::imread(stegoImagePath.toStdString(), cv::IMREAD_COLOR);
    if (stegoImage.empty()) {
        if (m_statusCb) m_statusCb("Error: Could not load stego image: " + stegoImagePath);
        return false;
    }
    if (stegoImage.type() != CV_8UC3) {
        if (m_statusCb) m_statusCb("Error: Stego image must be a 3-channel color image.");
        return false;
    }
    if (progressCb) progressCb(10);

    if (m_statusCb) m_statusCb("Extracting header data...");
    quint64 expectedHeaderSizeBytes = static_cast<quint64>(PASSWORD_HASH_SIZE_BYTES) + AES_IV_SIZE_BYTES + sizeof(quint64);
    quint64 preliminaryHeaderBits = expectedHeaderSizeBytes * 8;
    quint64 imageCapacityBits = static_cast<quint64>(stegoImage.rows) * stegoImage.cols * stegoImage.channels();

    if(preliminaryHeaderBits > imageCapacityBits){
        if (m_statusCb) m_statusCb("Error: Image too small to contain necessary header.");
        return false;
    }

    QByteArray headerPart = extractData(stegoImage, preliminaryHeaderBits, [&](int p){ if(progressCb) progressCb(10 + (p*5/100)); });
    if (static_cast<quint64>(headerPart.size()) != expectedHeaderSizeBytes) {
        if (m_statusCb) m_statusCb("Error: Could not extract complete header from image. Expected " + QString::number(expectedHeaderSizeBytes) + " bytes, got " + QString::number(headerPart.size()));
        return false;
    }

    QByteArray extractedPasswordHash = headerPart.left(PASSWORD_HASH_SIZE_BYTES);
    QByteArray iv = headerPart.mid(PASSWORD_HASH_SIZE_BYTES, AES_IV_SIZE_BYTES);
    quint64 encryptedPayloadSize;
    QDataStream sizeStream(headerPart.right(sizeof(quint64)));
    sizeStream >> encryptedPayloadSize;
    if (progressCb) progressCb(15);

    QByteArray derivedKeyForVerification = deriveKeyFromPassword(password);
    if(derivedKeyForVerification.isEmpty()) return false;
    if (extractedPasswordHash != derivedKeyForVerification) {
        if (m_statusCb) m_statusCb("Error: Incorrect password or corrupted data (hash mismatch).");
        return false;
    }
    if (progressCb) progressCb(20);

    if (m_statusCb) m_statusCb("Extracting encrypted payload (size: " + QString::number(encryptedPayloadSize) + " bytes)...");
    quint64 totalBitsToExtractFromImage = preliminaryHeaderBits + (encryptedPayloadSize * 8);
    if(totalBitsToExtractFromImage > imageCapacityBits){
        if (m_statusCb) m_statusCb("Error: Declared payload size exceeds image capacity for full extraction.");
        return false;
    }

    QByteArray fullEmbeddedData = extractData(stegoImage, totalBitsToExtractFromImage, [&](int p){ if(progressCb) progressCb(20 + (p*50/100)); });
    if(fullEmbeddedData.isEmpty() || static_cast<quint64>(fullEmbeddedData.size()) * 8 < totalBitsToExtractFromImage){
        if (m_statusCb) m_statusCb("Error: Failed to extract full embedded data from image.");
        return false;
    }
    QByteArray encryptedPayload = fullEmbeddedData.right(static_cast<qsizetype>(encryptedPayloadSize));
    if (static_cast<quint64>(encryptedPayload.size()) != encryptedPayloadSize) {
        if (m_statusCb) m_statusCb("Error: Extracted encrypted payload size mismatch.");
        return false;
    }
    if (progressCb) progressCb(70);

    if (m_statusCb) m_statusCb("Decrypting data...");
    QByteArray aesKey = derivedKeyForVerification;
    QByteArray decryptedPayload = aesDecrypt(encryptedPayload, aesKey, iv);
    if (decryptedPayload.isEmpty()) {
        return false;
    }
    if (progressCb) progressCb(85);

    QDataStream payloadStream(decryptedPayload);
    quint32 originalFilenameSizeBytes;
    payloadStream >> originalFilenameSizeBytes;
    if (payloadStream.atEnd() || originalFilenameSizeBytes > static_cast<quint32>(decryptedPayload.size() - sizeof(quint64) )) {
        if (m_statusCb) m_statusCb("Error: Corrupted metadata (filename size invalid).");
        return false;
    }
    QByteArray originalFilenameBytes;
    originalFilenameBytes.resize(originalFilenameSizeBytes);
    if (payloadStream.readRawData(originalFilenameBytes.data(), originalFilenameSizeBytes) != (int)originalFilenameSizeBytes) {
        if (m_statusCb) m_statusCb("Error: Corrupted metadata (could not read filename).");
        return false;
    }
    outOriginalFileName = QString::fromUtf8(originalFilenameBytes);

    quint64 originalFileSize;
    payloadStream >> originalFileSize;
    qsizetype currentPos = static_cast<qsizetype>(payloadStream.device()->pos());
    qsizetype remainingBytesInStream = decryptedPayload.size() - currentPos;
    if (static_cast<quint64>(remainingBytesInStream) < originalFileSize) {
        if (m_statusCb) m_statusCb("Error: Corrupted metadata (file content size mismatch with stream). Expected " + QString::number(originalFileSize) + " B, found " + QString::number(remainingBytesInStream) + " B remaining.");
        return false;
    }
    QByteArray originalFileData = decryptedPayload.mid(currentPos, static_cast<qsizetype>(originalFileSize));
    if (static_cast<quint64>(originalFileData.size()) != originalFileSize) {
        if (m_statusCb) m_statusCb("Warning: Extracted file data size ("+QString::number(originalFileData.size())+" B) does not match metadata size ("+QString::number(originalFileSize)+" B). Possible data corruption.");
    }
    if (progressCb) progressCb(90);

    QDir dir(outputDirectory);
    if (!dir.exists()) {
        if(!dir.mkpath(".")) {
            if (m_statusCb) m_statusCb("Error: Could not create output directory: " + outputDirectory);
            return false;
        }
    }
    QString outputFilePath = dir.filePath(outOriginalFileName);
    QFile outputFile(outputFilePath);
    if (!outputFile.open(QIODevice::WriteOnly)) {
        if (m_statusCb) m_statusCb("Error: Could not open output file for writing: " + outputFile.errorString());
        return false;
    }
    if(outputFile.write(originalFileData) != (qint64)originalFileData.size()){
        if (m_statusCb) m_statusCb("Error: Could not write all data to output file: " + outputFile.errorString());
        outputFile.close();
        return false;
    }
    outputFile.close();

    if (progressCb) progressCb(100);
    if (m_statusCb) m_statusCb("Extraction successful. File saved as: " + outputFilePath);
    return true;
}
