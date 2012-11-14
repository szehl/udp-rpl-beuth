#activate to enable extern PA on 2,4GHz modules from ANS
CFLAGS+= -DRF230BB_EXTERNAL_PA_ENABLED

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


#CFLAGS+= -DUIP_CONF_IPV6
#CFLAGS+= -DUIP_CONF_IPV6_RPL
#CFLAGS+= -DUIP_CONF_ROUTER

#activate to enable extern PA on 2,4GHz modules from ANS
CFLAGS+= -DRF230BB_EXTERNAL_PA_ENABLED

#activate to test meshed networks
#CFLAGS+= -DRF230_MAX_TX_POWER=15
#CFLAGS+= -DRF230_MIN_RX_POWER=30

#add one byte to the echo reply (uip6.c)
#used for sending echo request and reply
#with same frame length.
#for running the test send echo with 73byte data
#example= ping6 [dest] -s 73

#CFLAGS+= -DICMP_ECHO_MAX_TRANS_TEST

#disable ICMP Checksum check with UIP_CONF_IPV6_CHECKS=0 
#in /platform/avr-zigbit/contiki-conf.h

#enable led blink when packet arrives, see tcpip.c, works only for ATANY-Module
#CFLAGS+= -DPACKET_BLINK_ZIGBIT_ENABLE


#UIP_CONF_IPV6=1
#UIP_CONF_ROUTER=1
#UIP_CONF_IPV6_RPL=1


#CFLAGS+= -DMAC_CONF_FREQUENCY=0x09 #900MHz
#CFLAGS+= -DMAC_CONF_FREQUENCY=0x24 #2400MHz
#CFLAGS+= -DMAC_CONF_NUMBER=0x09
#for using .sh-script initial value must
#CFLAGS+= -DMAC_CONF_NUMBER=0x09

all:
	${MAKE} -f Makefile.snmp TARGET=$(TARGET) MIB_INIT=mib-rpl-zigbit.c NOAVRSIZE=1 snmp.elf   
	@if [ $(OUTFILE) != "snmp" ]; then cp snmp.elf $(OUTFILE).elf;fi
	avr-objcopy -O ihex -R .eeprom -R .fuse -R .signature $(OUTFILE).elf $(OUTFILE).hex
	avr-size -C --mcu=$(MCU) $(OUTFILE).elf

clean:
	${MAKE} -f Makefile.snmp TARGET=$(TARGET) clean
	rm symbols.c symbols.h snmp.elf $(OUTFILE).elf  $(OUTFILE).hex
	rm -rf obj_avr-raven
