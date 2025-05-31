#ifndef STEGANOGRAPHYCORE_H
#define STEGANOGRAPHYCORE_H

#include <QString>
#include <QByteArray>
#include <functional>
#include <vector>

namespace cv {
class Mat;
}

class SteganographyCore {
public:
    SteganographyCore();

    using ProgressCallback = std::function<void(int)>;
    using StatusCallback = std::function<void(const QString&)>;


    bool hideFileInImage(const QString& inputFilePath,
                         const QString& coverImagePath,
                         const QString& outputStegoImagePath,
                         const QString& password,
                         ProgressCallback progressCb,
                         StatusCallback statusCbParam);

    bool extractFileFromImage(const QString& stegoImagePath,
                              const QString& outputDirectory,
                              const QString& password,
                              ProgressCallback progressCb,
                              StatusCallback statusCbParam,
                              QString& outOriginalFileName);
private:
    QByteArray aesEncrypt(const QByteArray& data, const QByteArray& key, const QByteArray& iv);
    QByteArray aesDecrypt(const QByteArray& encryptedData, const QByteArray& key, const QByteArray& iv);
    QByteArray deriveKeyFromPassword(const QString& password);

    bool embedData(cv::Mat& image, const QByteArray& data, ProgressCallback progressCb);
    QByteArray extractData(const cv::Mat& image, quint64 dataLength, ProgressCallback progressCb);

    void setBit(unsigned char& byte, int bitPosition, bool value);
    bool getBit(unsigned char byte, int bitPosition);

    const int AES_KEY_SIZE_BYTES = 32;
    const int AES_IV_SIZE_BYTES = 16;
    const int AES_BLOCK_SIZE_BYTES = 16;
    const int PASSWORD_HASH_SIZE_BYTES = 32;

    StatusCallback m_statusCb;
};

#endif // STEGANOGRAPHYCORE_H
