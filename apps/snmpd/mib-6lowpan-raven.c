/*
 * Copyright (c) 2013, Anuj Sehgal.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file is part of the Contiki operating system.
 *
 * Anuj Sehgal <s.anuj@jacobs-university.de>
 */

#include <stdlib.h>
#include <string.h>

#include "contiki.h"

#include "mib-6lowpan-raven.h"
#include "mib-init.h"
#include "ber.h"
#include "utils.h"
#include "logging.h"
#include "dispatcher.h"
#include "snmpd.h"
#include "sicslowpan.h"
#if CONTIKI_TARGET_AVR_RAVEN && ENABLE_PROGMEM
#include <avr/pgmspace.h>
#else
#define PROGMEM
#endif

#define AVR_SNMP 1

/* SNMPv2 system group */
static const u8t ber_oid_system_sysDesc[] PROGMEM             = {0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00};
static const ptr_t oid_system_sysDesc PROGMEM                 = {ber_oid_system_sysDesc, 8};
static const u8t ber_oid_system_sysObjectId [] PROGMEM        = {0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x02, 0x00};
static const ptr_t oid_system_sysObjectId PROGMEM             = {ber_oid_system_sysObjectId, 8};
static const u8t ber_oid_system_sysUpTime [] PROGMEM          = {0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x03, 0x00};
static const ptr_t oid_system_sysUpTime PROGMEM               = {ber_oid_system_sysUpTime, 8};
static const u8t ber_oid_system_sysContact [] PROGMEM         = {0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x04, 0x00};
static const ptr_t oid_system_sysContact PROGMEM              = {ber_oid_system_sysContact, 8};
static const u8t ber_oid_system_sysName [] PROGMEM            = {0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x05, 0x00};
static const ptr_t oid_system_sysName PROGMEM                 = {ber_oid_system_sysName, 8};
static const u8t ber_oid_system_sysLocation [] PROGMEM        = {0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x06, 0x00};
static const ptr_t oid_system_sysLocation PROGMEM             = {ber_oid_system_sysLocation, 8};
static const u8t ber_oid_system_sysServices [] PROGMEM        = {0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x07, 0x00};
static const ptr_t oid_system_sysServices PROGMEM             = {ber_oid_system_sysServices, 8};
static const u8t ber_oid_system_sysORLastChange [] PROGMEM    = {0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x08, 0x00};
static const ptr_t oid_system_sysORLastChange PROGMEM         = {ber_oid_system_sysORLastChange, 8};
static const u8t ber_oid_system_sysOREntry [] PROGMEM         = {0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x09, 0x01};
static const ptr_t oid_system_sysOREntry PROGMEM              = {ber_oid_system_sysOREntry, 8};

/* SNMP group */
static const u8t ber_oid_snmpInPkts[] PROGMEM                 = {0x2b, 0x06, 0x01, 0x02, 0x01, 0x0B, 0x01, 0x00};
static const ptr_t oid_snmpInPkts PROGMEM                     = {ber_oid_snmpInPkts, 8};
static const u8t ber_oid_snmpInBadVersions[] PROGMEM          = {0x2b, 0x06, 0x01, 0x02, 0x01, 0x0B, 0x03, 0x00};
static const ptr_t oid_snmpInBadVersions PROGMEM              = {ber_oid_snmpInBadVersions, 8};
static const u8t ber_oid_snmpInASNParseErrs[] PROGMEM         = {0x2b, 0x06, 0x01, 0x02, 0x01, 0x0B, 0x06, 0x00};
static const ptr_t oid_snmpInASNParseErrs PROGMEM             = {ber_oid_snmpInASNParseErrs, 8};
static const u8t ber_oid_snmpEnableAuthenTraps[] PROGMEM      = {0x2b, 0x06, 0x01, 0x02, 0x01, 0x0B, 0x1E, 0x00};
static const ptr_t oid_snmpEnableAuthenTraps PROGMEM          = {ber_oid_snmpEnableAuthenTraps, 8};
static const u8t ber_oid_snmpSilentDrops[] PROGMEM            = {0x2b, 0x06, 0x01, 0x02, 0x01, 0x0B, 0x1F, 0x00};
static const ptr_t oid_snmpSilentDrops PROGMEM                = {ber_oid_snmpSilentDrops, 8};
static const u8t ber_oid_snmpProxyDrops[] PROGMEM             = {0x2b, 0x06, 0x01, 0x02, 0x01, 0x0B, 0x20, 0x00};
static const ptr_t oid_snmpProxyDrops PROGMEM                 = {ber_oid_snmpProxyDrops, 8};


/* lowpanObjects group */
static const u8t ber_oid_lowpanReasmTimeout[] PROGMEM           = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0xF2, 0x06, 0x01, 0x03, 0x01, 0x01, 0x00};
static const ptr_t oid_lowpanReasmTimeout PROGMEM               = {ber_oid_lowpanReasmTimeout, 13};
static const u8t ber_oid_lowpanInReceives[] PROGMEM             = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0xF2, 0x06, 0x01, 0x03, 0x01, 0x02, 0x00};
static const ptr_t oid_lowpanInReceives PROGMEM                 = {ber_oid_lowpanInReceives, 13};
static const u8t ber_oid_lowpanInHdrErrors[] PROGMEM            = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0xF2, 0x06, 0x01, 0x03, 0x01, 0x03, 0x00};
static const ptr_t oid_lowpanInHdrErrors PROGMEM                = {ber_oid_lowpanInHdrErrors, 13};
static const u8t ber_oid_lowpanInMeshReceives[] PROGMEM         = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0xF2, 0x06, 0x01, 0x03, 0x01, 0x04, 0x00};
static const ptr_t oid_lowpanInMeshReceives PROGMEM             = {ber_oid_lowpanInMeshReceives, 13};
static const u8t ber_oid_lowpanInMeshForwds[] PROGMEM           = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0xF2, 0x06, 0x01, 0x03, 0x01, 0x05, 0x00};
static const ptr_t oid_lowpanInMeshForwds PROGMEM               = {ber_oid_lowpanInMeshForwds, 13};
static const u8t ber_oid_lowpanInMeshDelivers[] PROGMEM         = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0xF2, 0x06, 0x01, 0x03, 0x01, 0x06, 0x00};
static const ptr_t oid_lowpanInMeshDelivers PROGMEM             = {ber_oid_lowpanInMeshDelivers, 13};
static const u8t ber_oid_lowpanInReasmReqds[] PROGMEM           = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0xF2, 0x06, 0x01, 0x03, 0x01, 0x07, 0x00};
static const ptr_t oid_lowpanInReasmReqds PROGMEM               = {ber_oid_lowpanInReasmReqds, 13};
static const u8t ber_oid_lowpanInReasmFails[] PROGMEM           = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0xF2, 0x06, 0x01, 0x03, 0x01, 0x08, 0x00};
static const ptr_t oid_lowpanInReasmFails PROGMEM               = {ber_oid_lowpanInReasmFails, 13};
static const u8t ber_oid_lowpanInReasmOKs[] PROGMEM             = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0xF2, 0x06, 0x01, 0x03, 0x01, 0x09, 0x00};
static const ptr_t oid_lowpanInReasmOKs PROGMEM                 = {ber_oid_lowpanInReasmOKs, 13};
static const u8t ber_oid_lowpanInCompReqds[] PROGMEM            = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0xF2, 0x06, 0x01, 0x03, 0x01, 0x0A, 0x00};
static const ptr_t oid_lowpanInCompReqds PROGMEM                = {ber_oid_lowpanInCompReqds, 13};
static const u8t ber_oid_lowpanInCompFails[] PROGMEM            = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0xF2, 0x06, 0x01, 0x03, 0x01, 0x0B, 0x00};
static const ptr_t oid_lowpanInCompFails PROGMEM                = {ber_oid_lowpanInCompFails, 13};
static const u8t ber_oid_lowpanInCompOKs[] PROGMEM              = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0xF2, 0x06, 0x01, 0x03, 0x01, 0x0C, 0x00};
static const ptr_t oid_lowpanInCompOKs PROGMEM                  = {ber_oid_lowpanInCompOKs, 13};
static const u8t ber_oid_lowpanInDiscards[] PROGMEM             = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0xF2, 0x06, 0x01, 0x03, 0x01, 0x0D, 0x00};
static const ptr_t oid_lowpanInDiscards PROGMEM                 = {ber_oid_lowpanInDiscards, 13};
static const u8t ber_oid_lowpanInDelivers[] PROGMEM             = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0xF2, 0x06, 0x01, 0x03, 0x01, 0x0E, 0x00};
static const ptr_t oid_lowpanInDelivers PROGMEM                 = {ber_oid_lowpanInDelivers, 13};
static const u8t ber_oid_lowpanOutRequests[] PROGMEM            = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0xF2, 0x06, 0x01, 0x03, 0x01, 0x0F, 0x00};
static const ptr_t oid_lowpanOutRequests PROGMEM                = {ber_oid_lowpanOutRequests, 13};
static const u8t ber_oid_lowpanOutCompReqds[] PROGMEM           = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0xF2, 0x06, 0x01, 0x03, 0x01, 0x10, 0x00};
static const ptr_t oid_lowpanOutCompReqds PROGMEM               = {ber_oid_lowpanOutCompReqds, 13};
static const u8t ber_oid_lowpanOutCompFails[] PROGMEM           = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0xF2, 0x06, 0x01, 0x03, 0x01, 0x11, 0x00};
static const ptr_t oid_lowpanOutCompFails PROGMEM               = {ber_oid_lowpanOutCompFails, 13};
static const u8t ber_oid_lowpanOutCompOKs[] PROGMEM             = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0xF2, 0x06, 0x01, 0x03, 0x01, 0x12, 0x00};
static const ptr_t oid_lowpanOutCompOKs PROGMEM                 = {ber_oid_lowpanOutCompOKs, 13};
static const u8t ber_oid_lowpanOutFragReqds[] PROGMEM           = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0xF2, 0x06, 0x01, 0x03, 0x01, 0x13, 0x00};
static const ptr_t oid_lowpanOutFragReqds PROGMEM               = {ber_oid_lowpanOutFragReqds, 13};
static const u8t ber_oid_lowpanOutFragFails[] PROGMEM           = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0xF2, 0x06, 0x01, 0x03, 0x01, 0x14, 0x00};
static const ptr_t oid_lowpanOutFragFails PROGMEM               = {ber_oid_lowpanOutFragFails, 13};
static const u8t ber_oid_lowpanOutFragOKs[] PROGMEM             = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0xF2, 0x06, 0x01, 0x03, 0x01, 0x15, 0x00};
static const ptr_t oid_lowpanOutFragOKs PROGMEM                 = {ber_oid_lowpanOutFragOKs, 13};
static const u8t ber_oid_lowpanOutFragCreates[] PROGMEM         = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0xF2, 0x06, 0x01, 0x03, 0x01, 0x16, 0x00};
static const ptr_t oid_lowpanOutFragCreates PROGMEM             = {ber_oid_lowpanOutFragCreates, 13};
static const u8t ber_oid_lowpanOutMeshHopLimitExceeds[] PROGMEM = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0xF2, 0x06, 0x01, 0x03, 0x01, 0x17, 0x00};
static const ptr_t oid_lowpanOutMeshHopLimitExceeds PROGMEM     = {ber_oid_lowpanOutMeshHopLimitExceeds, 13};
static const u8t ber_oid_lowpanOutMeshNoRoutes[] PROGMEM        = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0xF2, 0x06, 0x01, 0x03, 0x01, 0x18, 0x00};
static const ptr_t oid_lowpanOutMeshNoRoutes PROGMEM            = {ber_oid_lowpanOutMeshNoRoutes, 13};
static const u8t ber_oid_lowpanOutMeshRequests[] PROGMEM        = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0xF2, 0x06, 0x01, 0x03, 0x01, 0x19, 0x00};
static const ptr_t oid_lowpanOutMeshRequests PROGMEM            = {ber_oid_lowpanOutMeshRequests, 13};
static const u8t ber_oid_lowpanOutMeshForwds[] PROGMEM          = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0xF2, 0x06, 0x01, 0x03, 0x01, 0x1A, 0x00};
static const ptr_t oid_lowpanOutMeshForwds PROGMEM              = {ber_oid_lowpanOutMeshForwds, 13};
static const u8t ber_oid_lowpanOutMeshTransmits[] PROGMEM       = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0xF2, 0x06, 0x01, 0x03, 0x01, 0x1B, 0x00};
static const ptr_t oid_lowpanOutMeshTransmits PROGMEM           = {ber_oid_lowpanOutMeshTransmits, 13};
static const u8t ber_oid_lowpanOutDiscards[] PROGMEM            = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0xF2, 0x06, 0x01, 0x03, 0x01, 0x1C, 0x00};
static const ptr_t oid_lowpanOutDiscards PROGMEM                = {ber_oid_lowpanOutDiscards, 13};
static const u8t ber_oid_lowpanOutTransmits[] PROGMEM           = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0xF2, 0x06, 0x01, 0x03, 0x01, 0x1D, 0x00};
static const ptr_t oid_lowpanOutTransmits PROGMEM               = {ber_oid_lowpanOutTransmits, 13};
static const u8t ber_oid_lowpanInReasmNotReqds[] PROGMEM        = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0xF2, 0x06, 0x01, 0x03, 0x01, 0x1E, 0x00};
static const ptr_t oid_lowpanInReasmNotReqds PROGMEM            = {ber_oid_lowpanInReasmNotReqds, 13};

ptr_t* handleTableNextOid2(u8t* oid, u8t len, u8t* columns, u8t columnNumber, u8t rowNumber) {
    ptr_t* ret = 0;
    u32t oid_el1, oid_el2;
    u8t i;
    i = ber_decode_oid_item(oid, len, &oid_el1);
    i = ber_decode_oid_item(oid + i, len - i, &oid_el2);
    for (i = 0; i < columnNumber; i++) {
        if (oid_el1 < columns[i] || (oid_el1 == columns[i] && oid_el2 < rowNumber)) {
            ret = oid_create();
            CHECK_PTR_U(ret);
            ret->len = 2;
            ret->ptr = malloc(2);
            CHECK_PTR_U(ret->ptr);
            ret->ptr[0] = columns[i];
            if (oid_el1 < columns[i]) {
                ret->ptr[1] = 1;
            } else {
                ret->ptr[1] = oid_el2 + 1;
            }
            break;
        }
    }
    return ret;
}

u8t displayCounter=0;

/*
 * A callback function for setting the tempurature. Called from the raven-lcd-interface process.
 */
u32t tempLastUpdate;
s8t temperature;

void snmp_set_temp(char* s)
{
  temperature = 0;
  u8t i = 0;
  while ( i < strlen(s) && s[i] >= '0' && s[i] <= '9') {
    temperature = temperature * 10 + s[i] - '0';
    i++;
  }
  tempLastUpdate = clock_time();
}


/*
 *  "system" group
 */
s8t getTimeTicks(mib_object_t* object, u8t* oid, u8t len)
{
    object->varbind.value.u_value = clock_time();
    return 0;
}

/* ----------------   sysORTable    -------------------------- */

#define sysORID         2
#define sysORDescr      3
#define sysORUpTime     4

u8t sysORTableColumns[] = {sysORID, sysORDescr, sysORUpTime};

#define ORTableSize     1

static u8t ber_oid_mib2[]              = {0x2b, 0x06, 0x01, 0x06, 0x03, 0x01};
static ptr_t oid_mib2                  = {ber_oid_mib2, 6};

static u8t ber_oid_jacobs_raven[]      = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0xf2, 0x06, 0x01, 0x01};
static ptr_t oid_jacobs_raven          = {ber_oid_jacobs_raven, 10};

s8t getOREntry(mib_object_t* object, u8t* oid, u8t len)
{
    u32t oid_el1, oid_el2;
    u8t i;
    i = ber_decode_oid_item(oid, len, &oid_el1);
    i = ber_decode_oid_item(oid + i, len - i, &oid_el2);

    if (len != 2) {
        return -1;
    }

    switch (oid_el1) {
        case sysORID: 
            object->varbind.value_type = BER_TYPE_OID;
            switch (oid_el2) {
                case 1:
                    object->varbind.value.p_value.ptr = oid_mib2.ptr;
                    object->varbind.value.p_value.len = oid_mib2.len;
                    break;
                default:
                    return -1;
            }
            break;
        case sysORDescr:
            object->varbind.value_type = BER_TYPE_OCTET_STRING;
            switch (oid_el2) {
                case 1:
                    object->varbind.value.p_value.ptr = (u8t*)"The MIB module for SNMP entities";
                    object->varbind.value.p_value.len = strlen((char*)object->varbind.value.p_value.ptr);
                    break;
                default:
                    return -1;
            }
            break;
        case sysORUpTime:
            object->varbind.value_type = BER_TYPE_TIME_TICKS;
            switch (oid_el2) {
                case 1:
                    object->varbind.value.u_value = 0;
                    break;
                default:
                    return -1;
            }
            break;
        default:
            return -1;
    }
    return 0;
}

ptr_t* getNextOREntry(mib_object_t* object, u8t* oid, u8t len)
{
    return handleTableNextOid2(oid, len, sysORTableColumns, 3, ORTableSize);
}

/*
 * SNMP group
 */
s8t getMIBSnmpInPkts(mib_object_t* object, u8t* oid, u8t len)
{
    object->varbind.value.u_value = getSnmpInPkts();
    return 0;
}

s8t getMIBSnmpInBadVersions(mib_object_t* object, u8t* oid, u8t len)
{
    object->varbind.value.u_value = getSnmpInBadVersions();
    return 0;
}

s8t getMIBSnmpInASNParseErrs(mib_object_t* object, u8t* oid, u8t len)
{
    object->varbind.value.u_value = getSnmpInASNParseErrs();
    return 0;
}

s8t getMIBSnmpSilentDrops(mib_object_t* object, u8t* oid, u8t len)
{
    object->varbind.value.u_value = getSnmpSilentDrops();
    return 0;
}


/*
 * lowpanObjects group
 */
extern uint32_t MIBlowpanReasmTimeout;
extern uint32_t MIBlowpanInReceives;
extern uint32_t MIBlowpanInHdrErrors;
//extern uint32_t MIBlowpanInMeshReceives;
//extern uint32_t MIBlowpanInMeshForwds;
//extern uint32_t MIBlowpanInMeshDelivers;
extern uint32_t MIBlowpanInReasmReqds;
extern uint32_t MIBlowpanInReasmFails;
extern uint32_t MIBlowpanInReasmOKs;
extern uint32_t MIBlowpanInCompReqds;
extern uint32_t MIBlowpanInCompFails;
extern uint32_t MIBlowpanInCompOKs;
extern uint32_t MIBlowpanInDiscards;
extern uint32_t MIBlowpanInDelivers;
extern uint32_t MIBlowpanOutRequests;
extern uint32_t MIBlowpanOutCompReqds;
extern uint32_t MIBlowpanOutCompFails;
extern uint32_t MIBlowpanOutCompOKs;
extern uint32_t MIBlowpanOutFragReqds;
extern uint32_t MIBlowpanOutFragFails;
extern uint32_t MIBlowpanOutFragOKs;
extern uint32_t MIBlowpanOutFragCreates;
//extern uint32_t MIBlowpanOutMeshHopLimitExceeds;
//extern uint32_t MIBlowpanOutMeshNoRoutes;
//extern uint32_t MIBlowpanOutMeshRequests;
//extern uint32_t MIBlowpanOutMeshForwds;
//extern uint32_t MIBlowpanOutMeshTransmits;
extern uint32_t MIBlowpanOutDiscards;
extern uint32_t MIBlowpanOutTransmits;

s8t getLowpanReasmTimeout(mib_object_t* object, u8t* oid, u8t len)
{
    object->varbind.value.u_value = MIBlowpanReasmTimeout;
    return 0;
}

s8t getLowpanInReceives(mib_object_t* object, u8t* oid, u8t len)
{
    object->varbind.value.u_value = MIBlowpanInReceives;
    return 0;
}

s8t getLowpanInHdrErrors(mib_object_t* object, u8t* oid, u8t len)
{
    object->varbind.value.u_value = MIBlowpanInHdrErrors;
    return 0;
}

/*
 * getLowpanInMeshReceives()
 * getLowpanInMeshForwds()
 * getLowpanInMeshDelivers()
 */

s8t getLowpanInReasmReqds(mib_object_t* object, u8t* oid, u8t len)
{
    object->varbind.value.u_value = MIBlowpanInReasmReqds;
    return 0;
}

s8t getLowpanInReasmFails(mib_object_t* object, u8t* oid, u8t len)
{
    object->varbind.value.u_value = MIBlowpanInReasmFails;
    return 0;
}

s8t getLowpanInReasmOKs(mib_object_t* object, u8t* oid, u8t len)
{
    object->varbind.value.u_value = MIBlowpanInReasmOKs;
    return 0;
}

s8t getLowpanInCompReqds(mib_object_t* object, u8t* oid, u8t len)
{
    object->varbind.value.u_value = MIBlowpanInCompReqds;
    return 0;
}

s8t getLowpanInCompFails(mib_object_t* object, u8t* oid, u8t len)
{
    object->varbind.value.u_value = MIBlowpanInCompFails;
    return 0;
}

s8t getLowpanInCompOKs(mib_object_t* object, u8t* oid, u8t len)
{
    object->varbind.value.u_value = MIBlowpanInCompOKs;
    return 0;
}

s8t getLowpanInDiscards(mib_object_t* object, u8t* oid, u8t len)
{
    object->varbind.value.u_value = MIBlowpanInDiscards;
    return 0;
}

s8t getLowpanInDelivers(mib_object_t* object, u8t* oid, u8t len)
{
    object->varbind.value.u_value = MIBlowpanInDelivers;
    return 0;
}

s8t getLowpanOutRequests(mib_object_t* object, u8t* oid, u8t len)
{
    object->varbind.value.u_value = MIBlowpanOutRequests;
    return 0;
}

s8t getLowpanOutCompReqds(mib_object_t* object, u8t* oid, u8t len)
{
    object->varbind.value.u_value = MIBlowpanOutCompReqds;
    return 0;
}

s8t getLowpanOutCompFails(mib_object_t* object, u8t* oid, u8t len)
{
    object->varbind.value.u_value = MIBlowpanOutCompFails;
    return 0;
}

s8t getLowpanOutCompOKs(mib_object_t* object, u8t* oid, u8t len)
{
    object->varbind.value.u_value = MIBlowpanOutCompOKs;
    return 0;
}

s8t getLowpanOutFragReqds(mib_object_t* object, u8t* oid, u8t len)
{
    object->varbind.value.u_value = MIBlowpanOutFragReqds;
    return 0;
}

s8t getLowpanOutFragFails(mib_object_t* object, u8t* oid, u8t len)
{
    object->varbind.value.u_value = MIBlowpanOutFragFails;
    return 0;
}

s8t getLowpanOutFragOKs(mib_object_t* object, u8t* oid, u8t len)
{
    object->varbind.value.u_value = MIBlowpanOutFragOKs;
    return 0;
}

s8t getLowpanOutFragCreates(mib_object_t* object, u8t* oid, u8t len)
{
    object->varbind.value.u_value = MIBlowpanOutFragCreates;
    return 0;
}

/*
 * getLowpanOutMeshHopLimitExceeds()
 * getLowpanOutMeshNoRoutes()
 * getLowpanOutMeshRequests()
 * getLowpanOutMeshForwds()
 * getLowpanOutMeshTransmits()
 */

s8t getLowpanOutDiscards(mib_object_t* object, u8t* oid, u8t len)
{
  object->varbind.value.u_value = MIBlowpanOutDiscards;
    return 0;
}

s8t getLowpanOutTransmits(mib_object_t* object, u8t* oid, u8t len)
{
    object->varbind.value.u_value = MIBlowpanOutTransmits;
    return 0;
}

/*-----------------------------------------------------------------------------------*/
/*
 * Initialize the MIB.
 */
s8t mib_init()
{
    s32t defaultServiceValue = 78;
    s32t defaultSnmpEnableAuthenTraps = 2;
    s32t ifNumber = 1;
    char* sysDesc = "6LoWPAN MIB Test Node";
    char* sysContact = "Anuj Sehgal <s.anuj@jacobs-university.de>";
    char* sysName = "AVR Raven";
    char* sysLocation = "Jacobs University Bremen";
    

    // system group
    if (add_scalar(&oid_system_sysDesc, FLAG_ACCESS_READONLY, BER_TYPE_OCTET_STRING, sysDesc, 0, 0) == -1 ||
        add_scalar(&oid_system_sysObjectId, FLAG_ACCESS_READONLY, BER_TYPE_OID, &oid_jacobs_raven, 0, 0) == -1 ||
        add_scalar(&oid_system_sysUpTime, FLAG_ACCESS_READONLY, BER_TYPE_TIME_TICKS, 0, &getTimeTicks, 0) == -1 ||
        add_scalar(&oid_system_sysContact, 0, BER_TYPE_OCTET_STRING, sysContact, 0, 0) == -1 ||
        add_scalar(&oid_system_sysName, 0, BER_TYPE_OCTET_STRING, sysName, 0, 0) == -1 ||
        add_scalar(&oid_system_sysLocation, 0, BER_TYPE_OCTET_STRING, sysLocation, 0, 0) == -1 ||
        add_scalar(&oid_system_sysServices, FLAG_ACCESS_READONLY, BER_TYPE_INTEGER, &defaultServiceValue, 0, 0) == -1 ||
        add_scalar(&oid_system_sysORLastChange, FLAG_ACCESS_READONLY, BER_TYPE_TIME_TICKS, 0, 0, 0) == -1) {
        return -1;
    }
    if (add_table(&oid_system_sysOREntry, &getOREntry, &getNextOREntry, 0) == -1) {
        return -1;
    }


    // snmp group
    if (add_scalar(&oid_snmpInPkts, FLAG_ACCESS_READONLY, BER_TYPE_COUNTER, 0, &getMIBSnmpInPkts, 0) != ERR_NO_ERROR ||
        add_scalar(&oid_snmpInBadVersions, FLAG_ACCESS_READONLY, BER_TYPE_COUNTER, 0, &getMIBSnmpInBadVersions, 0) != ERR_NO_ERROR ||
        add_scalar(&oid_snmpInASNParseErrs, FLAG_ACCESS_READONLY, BER_TYPE_COUNTER, 0, &getMIBSnmpInASNParseErrs, 0) != ERR_NO_ERROR ||
        add_scalar(&oid_snmpEnableAuthenTraps, FLAG_ACCESS_READONLY, BER_TYPE_INTEGER, &defaultSnmpEnableAuthenTraps, 0, 0) != ERR_NO_ERROR ||
        add_scalar(&oid_snmpSilentDrops, FLAG_ACCESS_READONLY, BER_TYPE_COUNTER, 0,  &getMIBSnmpSilentDrops, 0) != ERR_NO_ERROR ||
        add_scalar(&oid_snmpProxyDrops, FLAG_ACCESS_READONLY, BER_TYPE_COUNTER, 0,  0, 0) != ERR_NO_ERROR) {
        return -1;
    }

    // lowpanObjects group
    if (add_scalar(&oid_lowpanReasmTimeout, FLAG_ACCESS_READONLY, BER_TYPE_UNSIGNED32, 0, &getLowpanReasmTimeout, 0) == -1 ||
	add_scalar(&oid_lowpanInReceives, FLAG_ACCESS_READONLY, BER_TYPE_COUNTER32, 0, &getLowpanInReceives, 0) == -1 ||
	add_scalar(&oid_lowpanInHdrErrors, FLAG_ACCESS_READONLY, BER_TYPE_COUNTER32, 0, &getLowpanInHdrErrors, 0) == -1 ||
        add_scalar(&oid_lowpanInMeshReceives, FLAG_ACCESS_READONLY, BER_TYPE_COUNTER32, 0, 0, 0) == -1 ||
        add_scalar(&oid_lowpanInMeshForwds, FLAG_ACCESS_READONLY, BER_TYPE_COUNTER32, 0, 0, 0) == -1 ||
        add_scalar(&oid_lowpanInMeshDelivers, FLAG_ACCESS_READONLY, BER_TYPE_COUNTER32, 0, 0, 0) == -1 ||
        add_scalar(&oid_lowpanInReasmReqds, FLAG_ACCESS_READONLY, BER_TYPE_COUNTER32, 0, &getLowpanInReasmReqds, 0) == -1 ||
        add_scalar(&oid_lowpanInReasmFails, FLAG_ACCESS_READONLY, BER_TYPE_COUNTER32, 0, &getLowpanInReasmFails, 0) == -1 ||
        add_scalar(&oid_lowpanInReasmOKs, FLAG_ACCESS_READONLY, BER_TYPE_COUNTER32, 0, &getLowpanInReasmOKs, 0) == -1 ||
        add_scalar(&oid_lowpanInCompReqds, FLAG_ACCESS_READONLY, BER_TYPE_COUNTER32, 0, &getLowpanInCompReqds, 0) == -1 ||
        add_scalar(&oid_lowpanInCompFails, FLAG_ACCESS_READONLY, BER_TYPE_COUNTER32, 0, &getLowpanInCompFails, 0) == -1 ||
        add_scalar(&oid_lowpanInCompOKs, FLAG_ACCESS_READONLY, BER_TYPE_COUNTER32, 0, &getLowpanInCompOKs, 0) == -1 ||
        add_scalar(&oid_lowpanInDiscards, FLAG_ACCESS_READONLY, BER_TYPE_COUNTER32, 0, &getLowpanInDiscards, 0) == -1 ||
        add_scalar(&oid_lowpanInDelivers, FLAG_ACCESS_READONLY, BER_TYPE_COUNTER32, 0, &getLowpanInDelivers, 0) == -1 ||
        add_scalar(&oid_lowpanOutRequests, FLAG_ACCESS_READONLY, BER_TYPE_COUNTER32, 0, &getLowpanOutRequests, 0) == -1 ||
        add_scalar(&oid_lowpanOutCompReqds, FLAG_ACCESS_READONLY, BER_TYPE_COUNTER32, 0, &getLowpanOutCompReqds, 0) == -1 ||
        add_scalar(&oid_lowpanOutCompFails, FLAG_ACCESS_READONLY, BER_TYPE_COUNTER32, 0, &getLowpanOutCompFails, 0) == -1 ||
        add_scalar(&oid_lowpanOutCompOKs, FLAG_ACCESS_READONLY, BER_TYPE_COUNTER32, 0, &getLowpanOutCompOKs, 0) == -1 ||
        add_scalar(&oid_lowpanOutFragReqds, FLAG_ACCESS_READONLY, BER_TYPE_COUNTER32, 0, &getLowpanOutFragReqds, 0) == -1 ||
        add_scalar(&oid_lowpanOutFragFails, FLAG_ACCESS_READONLY, BER_TYPE_COUNTER32, 0, &getLowpanOutFragFails, 0) == -1 ||
        add_scalar(&oid_lowpanOutFragOKs, FLAG_ACCESS_READONLY, BER_TYPE_COUNTER32, 0, &getLowpanOutFragOKs, 0) == -1 ||
        add_scalar(&oid_lowpanOutFragCreates, FLAG_ACCESS_READONLY, BER_TYPE_COUNTER32, 0, &getLowpanOutFragCreates, 0) == -1 ||
        add_scalar(&oid_lowpanOutMeshHopLimitExceeds, FLAG_ACCESS_READONLY, BER_TYPE_COUNTER32, 0, 0, 0) == -1 ||
        add_scalar(&oid_lowpanOutMeshNoRoutes, FLAG_ACCESS_READONLY, BER_TYPE_COUNTER32, 0, 0, 0) == -1 ||
        add_scalar(&oid_lowpanOutMeshRequests, FLAG_ACCESS_READONLY, BER_TYPE_COUNTER32, 0, 0, 0) == -1 ||
        add_scalar(&oid_lowpanOutMeshForwds, FLAG_ACCESS_READONLY, BER_TYPE_COUNTER32, 0, 0, 0) == -1 ||
        add_scalar(&oid_lowpanOutMeshTransmits, FLAG_ACCESS_READONLY, BER_TYPE_COUNTER32, 0, 0, 0) == -1 ||
        add_scalar(&oid_lowpanOutDiscards, FLAG_ACCESS_READONLY, BER_TYPE_COUNTER32, 0, &getLowpanOutDiscards, 0) == -1 ||
        add_scalar(&oid_lowpanOutTransmits, FLAG_ACCESS_READONLY, BER_TYPE_COUNTER32, 0, &getLowpanOutTransmits, 0) == -1) {
      return -1;
    }
    return 0;
}
