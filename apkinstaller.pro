QT += widgets core gui network

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
    installfilesgenerator.h \
    mainview.h \
    rsaencryption.h

SOURCES += \
    adbwrapper.cpp \
    aesencryption.cpp \
    apkinstallworker.cpp \
    installfilesgenerator.cpp \
    main.cpp \
    mainview.cpp \
    rsaencryption.cpp
