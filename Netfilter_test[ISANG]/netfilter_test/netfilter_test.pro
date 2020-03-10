LIBS += -lnetfilter_queue
LIBS += -lpcap
CONFIG -= qt
CONFIG += console c++11

HEADERS += \
    packet_structure.h

SOURCES += \
    nfqnl_test.c
