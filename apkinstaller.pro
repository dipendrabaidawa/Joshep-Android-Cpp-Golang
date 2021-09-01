QT += widgets core gui network
QT += concurrent

# Enable c++17
win32-msvc* {
    MSVC_VER = $$(VisualStudioVersion)
    greaterThan(MSVC_VER, 15.3){
        CONFIG += C++17
        QMAKE_CXXFLAGS += /std:c++17
    }
}

TEMPLATE = app
TARGET = apkinstaller

INCLUDEPATH += $$PWD/inc \

win32 {
    contains(QMAKE_TARGET.arch, x86_64) {
        CONFIG(debug, debug|release) {
            DESTDIR = $$PWD/bin/debug/x64
            TARGET = $$join(TARGET,,,d)
        } else {
            DESTDIR = $$PWD/bin/release/x64
        }
    } else {
        CONFIG(debug, debug|release) {
            DESTDIR = $$PWD/bin/debug/x86
            TARGET = $$join(TARGET,,,d)
        } else {
            DESTDIR = $$PWD/bin/release/x86
        }
    }
}

win32 {
    contains(QMAKE_TARGET.arch, x86_64) {
        LIBS += -L$$PWD/lib/x64
    } else {
        LIBS += -L$$PWD/lib/x86
    }
}

*msvc* { # visual studio spec filter
      QMAKE_CXXFLAGS += -MP
}

HEADERS += \
    adbwrapper.h \
    aesencryption.h \
    apkinstallworker.h \
    gui/customerinfowgt.h \
    gui/deviceinfowgt.h \
    gui/errorhandlingdlg.h \
    gui/finishedwgt.h \
    gui/installingwgt.h \
    settingkeys.h \
    installfilesgenerator.h \
    mainview.h \
    rsaencryption.h \
    gui/loginsignwgt.h \
    gui/loginwgt.h \
    gui/mainwidget.h \
    gui/passwordwgt.h \
    gui/stepwgt.h \
    gui/utils.h \
    gui/signwgt.h


SOURCES += \
    adbwrapper.cpp \
    aesencryption.cpp \
    apkinstallworker.cpp \
    gui/customerinfowgt.cpp \
    gui/deviceinfowgt.cpp \
    gui/errorhandlingdlg.cpp \
    gui/finishedwgt.cpp \
    gui/installingwgt.cpp \
    installfilesgenerator.cpp \
    main.cpp \
    mainview.cpp \
    rsaencryption.cpp \
    gui/loginsignwgt.cpp \
    gui/loginwgt.cpp \
    gui/mainwidget.cpp \
    gui/passwordwgt.cpp \
    gui/stepwgt.cpp \
    gui/utils.cpp \
    gui/signwgt.cpp

FORMS += \
    gui/customerinfowgt.ui \
    gui/deviceinfowgt.ui \
    gui/errorhandlingdlg.ui \
    gui/finishedwgt.ui \
    gui/installingwgt.ui \
    gui/mainwidget.ui \
    gui/loginsignwgt.ui \
    gui/loginwgt.ui \
    gui/passwordwgt.ui \
    gui/signwgt.ui \
    gui/stepwgt.ui

RESOURCES += \
    res.qrc
