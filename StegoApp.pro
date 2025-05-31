QT       += core gui widgets

CONFIG   += c++11

SOURCES += \
    main.cpp \
    mainwindow.cpp \
    steganographycore.cpp \
    passwordvalidator.cpp

HEADERS  += \
    mainwindow.h \
    steganographycore.h \
    passwordvalidator.h

FORMS    += \
    mainwindow.ui

INCLUDEPATH += /usr/include/opencv4 
LIBS += -L/usr/local/lib -lopencv_core -lopencv_imgcodecs -lopencv_imgproc 

LIBS += -lssl -lcrypto

LIBS += /lib/x86_64-linux-gnu/libcurl.so 
