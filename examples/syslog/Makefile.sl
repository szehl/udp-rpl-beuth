all: logger

APPS=syslog

TARGET=avr-raven
WITH_UIP6=1
UIP_CONF_IPV6=1
CFLAGS += -DPROJECT_CONF_H=\"project-conf.h\"
CFLAGS += -ffunction-sections
CFLAGS += -DUIP_CONF_IPV6_RPL
LDFLAGS += -Wl,--gc-sections,--undefined=_reset_vector__,--undefined=InterruptVectors,--undefined=_copy_data_init__,--undefined=_clear_bss_init__,--undefined=_end_of_init__

CONTIKI = ../..
include $(CONTIKI)/Makefile.include
