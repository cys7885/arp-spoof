TEMPLATE = app
CONFIG += console
CONFIG -= app_bundle
CONFIG -= qt
LIBS += -lpcap

SOURCES += main.c \
    arp_request.c \
    get_rsc.c

HEADERS += \
    utils.h
