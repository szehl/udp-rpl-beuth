ifndef TARGET
  TARGET=avr-zigbit
  MCU=atmega1281
endif
ifndef WEBDIR
 OUTFILE=snmp-$(TARGET)
else
 OUTFILE=snmp-$(WEBDIR)-$(TARGET)
endif

ifndef MCU
  MCU=atmega1281
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
	${MAKE} -f Makefile.snmp TARGET=$(TARGET) MIB_INIT=mib-rpl-zigbit.c NOAVRSIZE=1 snmp.elf   
	@if [ $(OUTFILE) != "snmp" ]; then cp snmp.elf $(OUTFILE).elf;fi
	avr-objcopy -O ihex -R .eeprom -R .fuse -R .signature $(OUTFILE).elf $(OUTFILE).hex
	avr-size -C --mcu=$(MCU) $(OUTFILE).elf

clean:
	${MAKE} -f Makefile.snmp TARGET=$(TARGET) clean
	rm symbols.c symbols.h snmp.elf $(OUTFILE).elf  $(OUTFILE).hex
	rm -rf obj_avr-raven
