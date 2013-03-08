ifndef TARGET
  TARGET=avr-raven
  MCU=atmega1284p
endif

ifndef MCU
  MCU=atmega1284p
endif

ifdef WITH_COMPOWER
  APPS+=powertrace
  CFLAGS+= -DCONTIKIMAC_CONF_COMPOWER=1 -DWITH_COMPOWER=1 -DQUEUEBUF_CONF_NUM=4
endif

ifdef SERVER_REPLY
  CFLAGS+=-DSERVER_REPLY=$(SERVER_REPLY)
endif

ifdef PERIOD
  CFLAGS+=-DPERIOD=$(PERIOD)
endif

all:
	${MAKE} -f Makefile.sl TARGET=$(TARGET) NOAVRSIZE=1 logger.elf
	avr-objcopy -O ihex -R .eeprom -R .fuse -R .signature logger.elf logger.hex

clean:
	${MAKE} -f Makefile.sl TARGET=$(TARGET) clean
	rm symbols.c symbols.h logger.elf logger.hex
	rm -rf obj_avr-raven
