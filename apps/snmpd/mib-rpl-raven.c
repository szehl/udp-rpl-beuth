#include <stdlib.h>
#include <string.h>

#include "contiki.h"

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

#include "net/rpl/rpl-private.h"
#include "net/rpl/rpl.h"
#include "net/uip-ds6.h"

#define AVR_SNMP 1

u32t EncodeTableOID(u8t* ptr, u32t pos, u32t value)
{
  switch(ber_encoded_oid_item_length(value)){
  case 5:
    ptr[pos] = ((value >> (7 * 4)) & 0x7F) | 0x80;
    pos++;
  case 4:
    ptr[pos] = ((value >> (7 * 3)) & 0x7F) | 0x80;
    pos++;
  case 3:
    ptr[pos] = ((value >> (7 * 2)) & 0x7F) | 0x80;
    pos++;
  case 2:
    ptr[pos] = ((value >> (7 * 1)) & 0x7F) | 0x80;
    pos++;
  case 1:
    ptr[pos] = ((value >> (7 * 0)) & 0x7F);
    pos++;
    break;
  default:
    return -1;
  }
  return pos;
}

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

/* SNMPv2 system group */
const static u8t ber_oid_system_sysDesc[] PROGMEM             = {0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00};
const static ptr_t oid_system_sysDesc PROGMEM                 = {ber_oid_system_sysDesc, 8};
const static u8t ber_oid_system_sysObjectId [] PROGMEM        = {0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x02, 0x00};
const static ptr_t oid_system_sysObjectId PROGMEM             = {ber_oid_system_sysObjectId, 8};
const static u8t ber_oid_system_sysUpTime [] PROGMEM          = {0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x03, 0x00};
const static ptr_t oid_system_sysUpTime PROGMEM               = {ber_oid_system_sysUpTime, 8};
const static u8t ber_oid_system_sysContact [] PROGMEM         = {0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x04, 0x00};
const static ptr_t oid_system_sysContact PROGMEM              = {ber_oid_system_sysContact, 8};
const static u8t ber_oid_system_sysName [] PROGMEM            = {0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x05, 0x00};
const static ptr_t oid_system_sysName PROGMEM                 = {ber_oid_system_sysName, 8};
const static u8t ber_oid_system_sysLocation [] PROGMEM        = {0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x06, 0x00};
const static ptr_t oid_system_sysLocation PROGMEM             = {ber_oid_system_sysLocation, 8};
const static u8t ber_oid_system_sysServices [] PROGMEM        = {0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x07, 0x00};
const static ptr_t oid_system_sysServices PROGMEM             = {ber_oid_system_sysServices, 8};
const static u8t ber_oid_system_sysORLastChange [] PROGMEM    = {0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x08, 0x00};
const static ptr_t oid_system_sysORLastChange PROGMEM         = {ber_oid_system_sysORLastChange, 8};
const static u8t ber_oid_system_sysOREntry [] PROGMEM         = {0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x09, 0x01};
const static ptr_t oid_system_sysOREntry PROGMEM              = {ber_oid_system_sysOREntry, 8};

/* rplDefaults group */
static const u8t ber_oid_rplDefaultDISMode[] PROGMEM             = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0xF2, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00};
static const ptr_t oid_rplDefaultDISMode PROGMEM                 = {ber_oid_rplDefaultDISMode, 14};
static const u8t ber_oid_rplDefaultDISMessages[] PROGMEM         = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0xF2, 0x06, 0x01, 0x02, 0x01, 0x01, 0x02, 0x00};
static const ptr_t oid_rplDefaultDISMessages PROGMEM             = {ber_oid_rplDefaultDISMessages, 14};
static const u8t ber_oid_rplDefaultDISTimeout[] PROGMEM          = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0xF2, 0x06, 0x01, 0x02, 0x01, 0x01, 0x03, 0x00};
static const ptr_t oid_rplDefaultDISTimeout PROGMEM              = {ber_oid_rplDefaultDISTimeout, 14};
static const u8t ber_oid_rplDefaultDAODelay[] PROGMEM            = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0xF2, 0x06, 0x01, 0x02, 0x01, 0x01, 0x04, 0x00};
static const ptr_t oid_rplDefaultDAODelay PROGMEM                = {ber_oid_rplDefaultDAODelay, 14};
static const u8t ber_oid_rplDefaultDAOAckEnabled[] PROGMEM       = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0xF2, 0x06, 0x01, 0x02, 0x01, 0x01, 0x05, 0x00};
static const ptr_t oid_rplDefaultDAOAckEnabled PROGMEM           = {ber_oid_rplDefaultDAOAckEnabled, 14};
static const u8t ber_oid_rplDefaultPreference[] PROGMEM          = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0xF2, 0x06, 0x01, 0x02, 0x01, 0x01, 0x06, 0x00};
static const ptr_t oid_rplDefaultPreference PROGMEM              = {ber_oid_rplDefaultPreference, 14};
static const u8t ber_oid_rplDefaultMinHopRankIncrease[] PROGMEM  = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0xF2, 0x06, 0x01, 0x02, 0x01, 0x01, 0x07, 0x00};
static const ptr_t oid_rplDefaultMinHopRankIncrease PROGMEM      = {ber_oid_rplDefaultMinHopRankIncrease, 14};
static const u8t ber_oid_rplDefaultMaxRankIncrease[] PROGMEM     = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0xF2, 0x06, 0x01, 0x02, 0x01, 0x01, 0x08, 0x00};
static const ptr_t oid_rplDefaultMaxRankIncrease PROGMEM         = {ber_oid_rplDefaultMaxRankIncrease, 14};
static const u8t ber_oid_rplDefaultModeOfOperation[] PROGMEM     = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0xF2, 0x06, 0x01, 0x02, 0x01, 0x01, 0x09, 0x00};
static const ptr_t oid_rplDefaultModeOfOperation PROGMEM         = {ber_oid_rplDefaultModeOfOperation, 14};
static const u8t ber_oid_rplDefaultIntervalDoublings[] PROGMEM   = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0xF2, 0x06, 0x01, 0x02, 0x01, 0x01, 0x0A, 0x00};
static const ptr_t oid_rplDefaultIntervalDoublings PROGMEM       = {ber_oid_rplDefaultIntervalDoublings, 14};
static const u8t ber_oid_rplDefaultIntervalMin[] PROGMEM         = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0xF2, 0x06, 0x01, 0x02, 0x01, 0x01, 0x0B, 0x00};
static const ptr_t oid_rplDefaultIntervalMin PROGMEM             = {ber_oid_rplDefaultIntervalMin, 14};
static const u8t ber_oid_rplDefaultRedundancyConstant[] PROGMEM  = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0xF2, 0x06, 0x01, 0x02, 0x01, 0x01, 0x0C, 0x00};
static const ptr_t oid_rplDefaultRedundancyConstant PROGMEM      = {ber_oid_rplDefaultRedundancyConstant, 14};

/* rplActive group */
static const u8t ber_oid_rplActiveInstance[] PROGMEM             = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0xF2, 0x06, 0x01, 0x02, 0x01, 0x02, 0x01, 0x00};
static const ptr_t oid_rplActiveInstance PROGMEM                 = {ber_oid_rplActiveInstance, 14};
static const u8t ber_oid_rplActiveDodag[] PROGMEM                = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0xF2, 0x06, 0x01, 0x02, 0x01, 0x02, 0x02, 0x00};
static const ptr_t oid_rplActiveDodag PROGMEM                    = {ber_oid_rplActiveDodag, 14};
static const u8t ber_oid_rplActiveDodagTriggerSequence[] PROGMEM = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0xF2, 0x06, 0x01, 0x02, 0x01, 0x02, 0x03, 0x00};
static const ptr_t oid_rplActiveDodagTriggerSequence PROGMEM     = {ber_oid_rplActiveDodagTriggerSequence, 14};

/* rplStats group */
static const u8t ber_oid_rplMemOverflows[] PROGMEM               = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0xF2, 0x06, 0x01, 0x02, 0x01, 0x08, 0x01, 0x00};
static const ptr_t oid_rplMemOverflows PROGMEM                   = {ber_oid_rplMemOverflows, 14};
static const u8t ber_oid_rplParseErrors[] PROGMEM                = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0xF2, 0x06, 0x01, 0x02, 0x01, 0x08, 0x02, 0x00};
static const ptr_t oid_rplParseErrors PROGMEM                    = {ber_oid_rplParseErrors, 14};
static const u8t ber_oid_rplUnknownMsgTypes[] PROGMEM            = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0xF2, 0x06, 0x01, 0x02, 0x01, 0x08, 0x03, 0x00};
static const ptr_t oid_rplUnknownMsgTypes PROGMEM                = {ber_oid_rplUnknownMsgTypes, 14};
static const u8t ber_oid_rplSecurityPolicyViolations[] PROGMEM   = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0xF2, 0x06, 0x01, 0x02, 0x01, 0x08, 0x04, 0x00};
static const ptr_t oid_rplSecurityPolicyViolations PROGMEM       = {ber_oid_rplSecurityPolicyViolations, 14};
static const u8t ber_oid_rplIntegrityCheckFailures[] PROGMEM     = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0xF2, 0x06, 0x01, 0x02, 0x01, 0x08, 0x05, 0x00};
static const ptr_t oid_rplIntegrityCheckFailures PROGMEM         = {ber_oid_rplIntegrityCheckFailures, 14};
static const u8t ber_oid_rplReplayProtectionFailures[] PROGMEM   = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0xF2, 0x06, 0x01, 0x02, 0x01, 0x08, 0x06, 0x00};
static const ptr_t oid_rplReplayProtectionFailures PROGMEM       = {ber_oid_rplReplayProtectionFailures, 14};
static const u8t ber_oid_rplValidParentFailures[] PROGMEM        = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0xF2, 0x06, 0x01, 0x02, 0x01, 0x08, 0x07, 0x00};
static const ptr_t oid_rplValidParentFailures PROGMEM            = {ber_oid_rplValidParentFailures, 14};
static const u8t ber_oid_rplNoInstanceIDs[] PROGMEM              = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0xF2, 0x06, 0x01, 0x02, 0x01, 0x08, 0x08, 0x00};
static const ptr_t oid_rplNoInstanceIDs PROGMEM                  = {ber_oid_rplNoInstanceIDs, 14};
static const u8t ber_oid_rplTriggeredLocalRepairs[] PROGMEM      = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0xF2, 0x06, 0x01, 0x02, 0x01, 0x08, 0x09, 0x00};
static const ptr_t oid_rplTriggeredLocalRepairs PROGMEM          = {ber_oid_rplTriggeredLocalRepairs, 14};
static const u8t ber_oid_rplTriggeredGlobalRepairs[] PROGMEM     = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0xF2, 0x06, 0x01, 0x02, 0x01, 0x08, 0x0A, 0x00};
static const ptr_t oid_rplTriggeredGlobalRepairs PROGMEM         = {ber_oid_rplTriggeredGlobalRepairs, 14};
static const u8t ber_oid_rplNoParentSecs[] PROGMEM               = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0xF2, 0x06, 0x01, 0x02, 0x01, 0x08, 0x0B, 0x00};
static const ptr_t oid_rplNoParentSecs PROGMEM                   = {ber_oid_rplNoParentSecs, 14};
static const u8t ber_oid_rplActiveNoParentSecs[] PROGMEM         = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0xF2, 0x06, 0x01, 0x02, 0x01, 0x08, 0x0C, 0x00};
static const ptr_t oid_rplActiveNoParentSecs PROGMEM             = {ber_oid_rplActiveNoParentSecs, 14};
static const u8t ber_oid_rplOBitSetDownwards[] PROGMEM           = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0xF2, 0x06, 0x01, 0x02, 0x01, 0x08, 0x0D, 0x00};
static const ptr_t oid_rplOBitSetDownwards PROGMEM               = {ber_oid_rplOBitSetDownwards, 14};
static const u8t ber_oid_rplOBitClearedUpwards[] PROGMEM         = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0xF2, 0x06, 0x01, 0x02, 0x01, 0x08, 0x0E, 0x00};
static const ptr_t oid_rplOBitClearedUpwards PROGMEM             = {ber_oid_rplOBitClearedUpwards, 14};
static const u8t ber_oid_rplFBitSet[] PROGMEM                    = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0xF2, 0x06, 0x01, 0x02, 0x01, 0x08, 0x0F, 0x00};
static const ptr_t oid_rplFBitSet PROGMEM                        = {ber_oid_rplFBitSet, 14};
static const u8t ber_oid_rplRBitSet[] PROGMEM                    = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0xF2, 0x06, 0x01, 0x02, 0x01, 0x08, 0x10, 0x00};
static const ptr_t oid_rplRBitSet PROGMEM                        = {ber_oid_rplRBitSet, 14};
static const u8t ber_oid_rplTrickleTimerResets[] PROGMEM         = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0xF2, 0x06, 0x01, 0x02, 0x01, 0x08, 0x11, 0x00};
static const ptr_t oid_rplTrickleTimerResets PROGMEM             = {ber_oid_rplTrickleTimerResets, 14};

/*
 *"system" group
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

const static u8t ber_oid_mib2[]              = {0x2b, 0x06, 0x01, 0x06, 0x03, 0x01};
const static ptr_t oid_mib2                  = {ber_oid_mib2, 6};

const static u8t ber_oid_jacobs_raven[]      = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0xf2, 0x06, 0x01, 0x02};
const static ptr_t oid_jacobs_raven          = {ber_oid_jacobs_raven, 10};

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
      object->varbind.value.p_value.ptr = (u8t*)"RPL-MIB Test Mote";
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
 * rplDefaults group
 *
 * rplDefaults(1)
 *  +- rwn RplDISMode            rplDefaultDISMode(1)
 *  +- rwn Unsigned32            rplDefaultDISMessages(2)
 *  +- rwn Unsigned32            rplDefaultDISTimeout(3)
 *  +- rwn RplDAODelay           rplDefaultDAODelay(4)
 *  +- rwn TruthValue            rplDefaultDAOAckEnabled(5)
 *  +- rwn RplDodagPreference    rplDefaultPreference(6)
 *  +- rwn RplMinHopRankIncrease rplDefaultMinHopRankIncrease(7)
 *  +- rwn Unsigned32            rplDefaultMaxRankIncrease(8)
 *  +- rwn RplModeOfOperation    rplDefaultModeOfOperation(9)
 *  +- rwn Unsigned32            rplDefaultIntervalDoublings(10)
 *  +- rwn Unsigned32            rplDefaultIntervalMin(11)
 *  +- rwn Unsigned32            rplDefaultRedundancyConstant(12)
*/

s8t getRplDefaultDISMode(mib_object_t* object, u8t* oid, u8t len)
{
#if RPL_DIS_SEND
  object->varbind.value.i_value = 2;
#else
  object->varbind.value.i_value = 1;
#endif
  return 0;  
}

s8t getRplDefaultDISMessages(mib_object_t* object, u8t* oid, u8t len)
{
  object->varbind.value.i_value = 1;
  return 0;  
}

s8t getRplDefaultDISTimeout(mib_object_t* object, u8t* oid, u8t len)
{
  object->varbind.value.i_value = 0;
  return 0;  
}

s8t getRplDefaultDAODelay(mib_object_t* object, u8t* oid, u8t len)
{
  object->varbind.value.i_value = CLOCK_SECOND;
  return 0;
}

s8t getRplDefaultDAOAckEnabled(mib_object_t* object, u8t* oid, u8t len)
{
#ifdef RPL_CONF_DAO_ACK
  object->varbind.value.i_value = 1; //True(1)                                                                                   
#else
  object->varbind.value.i_value = 2; //False(2)                                                                                  
#endif
  return 0;  
}

s8t getRplDefaultPreference(mib_object_t* object, u8t* oid, u8t len)
{
  extern MIBrplDefaultPreference;
  object->varbind.value.i_value = MIBrplDefaultPreference;
  return 0;  
}

s8t getRplDefaultMinHopRankIncrease(mib_object_t* object, u8t* oid, u8t len)
{
  object->varbind.value.i_value = RPL_MIN_HOPRANKINC;
  return 0;  
}

s8t getRplDefaultMaxRankIncrease(mib_object_t* object, u8t* oid, u8t len)
{
  object->varbind.value.i_value = RPL_MAX_RANKINC;
  return 0;  
}

s8t getRplDefaultModeOfOperation(mib_object_t* object, u8t* oid, u8t len)
{
  object->varbind.value.i_value = RPL_MOP_DEFAULT;
  return 0;  
}

s8t getRplDefaultIntervalDoublings(mib_object_t* object, u8t* oid, u8t len)
{
  object->varbind.value.i_value = RPL_DIO_INTERVAL_DOUBLINGS;
  return 0;  
}

s8t getRplDefaultIntervalMin(mib_object_t* object, u8t* oid, u8t len)
{
  object->varbind.value.i_value = RPL_DIO_INTERVAL_MIN;
  return 0;  
}

s8t getRplDefaultRedundancyConstant(mib_object_t* object, u8t* oid, u8t len)
{
  object->varbind.value.i_value = RPL_DIO_REDUNDANCY;
  return 0;  
}

/*
 * rplActive group
 *
 * rplActive(2)
 *  +- rwn RplInstanceID   rplActiveInstance(1)
 *  +- rwn InetAddressIPv6 rplActiveDodag(2)
 *  +- rwn Unsigned32      rplActiveDodagTriggerSequence(3) 
 */

s8t getRplActiveInstance(mib_object_t* object, u8t* oid, u8t len)
{
  rpl_dag_t *dag;
  dag = rpl_get_any_dag();
  if (dag == NULL) {
    return -1;
  }
  
  object->varbind.value.i_value = dag->instance->instance_id;
  return 0;
}

s8t getRplActiveDodag(mib_object_t* object, u8t* oid, u8t len)
{
  rpl_dag_t *dag;
  int i;
  dag = rpl_get_any_dag();
  if (dag == NULL) {
    return -1;
  }

  for(i = 0; i < RPL_MAX_DAG_PER_INSTANCE; i++) {
    if (dag->instance->dag_table[i].used) {
      object->varbind.value.p_value.ptr = (u8t*) dag->instance->dag_table[i].dag_id.u8;
      object->varbind.value.p_value.len = 16;
      break;
    }
  }
  return 0;
}

s8t getRplActiveDodagTriggerSequence(mib_object_t* object, u8t* oid, u8t len)
{
  rpl_dag_t *dag;
  dag = rpl_get_any_dag();
  if (dag == NULL) {
    return -1;
  }
  
  object->varbind.value.i_value = dag->instance->dtsn_out;
  return 0;  
}

/*
 * rplOCPTable group
 * 
 * rplOCPTable(3)
 *  +-rplOCPEntry(1) [rplOCPCodepoint]
 *     +- --- RplObjectiveCodePoint rplOCPCodepoint(1)
 *     +- rwn TruthValue            rplOCPEnabled(2)
 */

/* rplOCPTable */
static const u8t ber_oid_rplOCPEntry[] PROGMEM = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0xF2, 0x06, 0x01, 0x02, 0x01, 0x03, 0x01};
static const ptr_t oid_rplOCPEntry PROGMEM     = {ber_oid_rplOCPEntry, 13};
extern rpl_of_t RPL_OF;

#define rplOCPEnabled 2

s8t getRplOCPEntry(mib_object_t* object, u8t* oid, u8t len) 
{
  u32t oid_el1, oid_el2;
  u8t i;
  
  if (len != 2) {
    return -1;
  }

  i = ber_decode_oid_item(oid, len, &oid_el1);
  i = ber_decode_oid_item(oid + i, len - i, &oid_el2);
  
  switch (oid_el1) 
    {
    case rplOCPEnabled:
      if (oid_el2 == RPL_OF.ocp) {
	object->varbind.value_type = BER_TYPE_INTEGER;
	object->varbind.value.i_value = 1;
      } else {
	return -1;
      }
      break;
    default:
      return -1;
    }
  
  return 0;
}

u8t RplOCPColumns[] = {rplOCPEnabled};

ptr_t* getNextOIDRplOCPEntry(mib_object_t* object, u8t* oid, u8t len) {
  ptr_t* ret = 0;
  u32t oid_el1, oid_el2;
  u8t i;

  i = ber_decode_oid_item(oid, len, &oid_el1);
  i = ber_decode_oid_item(oid + i, len - i, &oid_el2);

  //printf("\ngetNextOIDRplOCPEntry\n");
  //printf("oid_el1: %d\n", oid_el1);
  //printf("oid_el2: %d\n", oid_el2);

  if (oid_el1 < RplOCPColumns[0] || (oid_el1 == RplOCPColumns[0] && oid_el2 < RPL_OF.ocp)) {
    ret = oid_create();
    CHECK_PTR_U(ret);
    ret->len = 2;
    ret->ptr = malloc(2);
    CHECK_PTR_U(ret->ptr);

    ret->ptr[0] = RplOCPColumns[0];
    ret->ptr[1] = RPL_OF.ocp;
    //printf("Created: %d.%d\n", ret->ptr[0], ret->ptr[1]);
  }
  return ret;
}

/*
 * rplInstanceTable group
 *
 * rplInstanceTable(4)
 *  +-rplInstanceEntry(1) [rplInstanceID]
 *     +- --- RplInstanceID         rplInstanceID(1)
 *     +- r-n RplDISMode            rplInstanceDISMode(2)
 *     +- r-n Unsigned32            rplInstanceDISMessages(3)
 *     +- r-n Unsigned32            rplInstanceDISTimeout(4)
 *     +- r-n RplModeOfOperation    rplInstanceModeOfOperation(5)
*/

/* rplInstanceTable */
static const u8t ber_oid_rplInstanceEntry[] PROGMEM = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0xF2, 0x06, 0x01, 0x02, 0x01, 0x04, 0x01};
static const ptr_t oid_rplInstanceEntry PROGMEM     = {ber_oid_rplInstanceEntry, 13};

#define rplInstanceDISMode         2
#define rplInstanceDISMessages     3
#define rplInstanceDISTimeout      4
#define rplInstanceModeOfOperation 5

s8t getRplInstanceEntry(mib_object_t* object, u8t* oid, u8t len) {
  u32t oid_el1, oid_el2;
  u8t i;
  rpl_instance_t *instance;
  
  if (len != 2) {
    return -1;
  }

  i = ber_decode_oid_item(oid, len, &oid_el1);
  i = ber_decode_oid_item(oid + i, len - i, &oid_el2);
  //printf("getRplInstanceEntry - oid_el1.oid_el2: %d.%d\n", oid_el1, oid_el2);

  instance = rpl_get_instance(oid_el2);
  if (instance == NULL) {
    return -1;
  }

  switch (oid_el1)
    {
    case rplInstanceDISMode:
      object->varbind.value_type = BER_TYPE_INTEGER;
#if RPL_DIS_SEND
      object->varbind.value.i_value = 2;
#else
      object->varbind.value.i_value = 1;
#endif
      break;
    case rplInstanceDISMessages:
      object->varbind.value_type = BER_TYPE_UNSIGNED32;
      object->varbind.value.i_value = 1;
      break;
    case rplInstanceDISTimeout:
      object->varbind.value_type = BER_TYPE_UNSIGNED32;
      object->varbind.value.i_value = 0;
      break;
    case rplInstanceModeOfOperation:
      object->varbind.value_type = BER_TYPE_INTEGER;
      object->varbind.value.i_value = instance->mop;
      break;
    default:
      return -1;
    }
  return 0;
}

u8t RplInstanceColumns[] = {rplInstanceDISMode, rplInstanceDISMessages, rplInstanceDISTimeout, rplInstanceModeOfOperation};
#define RplInstanceTableSize RPL_MAX_INSTANCES

s8t instance_loc(u32t oid_instance_id) {
  extern rpl_instance_t instance_table[];
  int i;

  for (i = 0; i < RplInstanceTableSize; i++) {
    if (instance_table[i].instance_id == oid_instance_id) {
      return i+1;
    }
  }
  return -1;
}

ptr_t* getNextOIDRplInstanceEntry(mib_object_t* object, u8t* oid, u8t len) {
  ptr_t* ret = 0;
  u32t oid_el1, oid_el2;
  u8t i;
  u8t columnNumber = 4;
  
  extern rpl_instance_t instance_table[];
  
  i = ber_decode_oid_item(oid, len, &oid_el1);
  i = ber_decode_oid_item(oid + i, len - i, &oid_el2);

  //printf("\ngetNextOIDRplInstanceEntry\n");
  //printf("oid_el1: %d\n", oid_el1);
  //printf("oid_el2: %d\n", oid_el2);

  for(i = 0; i < columnNumber; i++) {
    if (oid_el1 < RplInstanceColumns[i] || 
	(oid_el1 == RplInstanceColumns[i] && (instance_loc(oid_el2) < RplInstanceTableSize || instance_loc(oid_el2) == -1))) {
      //printf("Inside IF statement\n");
      ret = oid_create();
      CHECK_PTR_U(ret);
      ret->len = 2;
      ret->ptr = malloc(2);
      CHECK_PTR_U(ret->ptr);
      ret->ptr[0] = RplInstanceColumns[i];
      if (oid_el1 < RplInstanceColumns[i] || instance_loc(oid_el2) == -1) {
	ret->ptr[1] = instance_table[0].instance_id;

	//printf("Inside IF statement - 0.0 OID\n");
	//ret->ptr[1] = 0;
	//printf("Created [if]: %d.%d\n", ret->ptr[0], ret->ptr[1]);
      } else {
	//printf("Inside IF statement - x.x OID\n");
	
	if(instance_loc(oid_el2) < RplInstanceTableSize) {
	  ret->ptr[1] =  instance_table[instance_loc(oid_el2)].instance_id;	  
	  //ret->ptr[1] =  instance_loc(oid_el2);	  
	} else {
	  return 0;
	}	
	//printf("Created [else]: %d.%d\n", ret->ptr[0], ret->ptr[1]);
      }
      break;
    }
  }
  return ret;
}

/*
 * rplDodagTable group
 *
 * rplDodagTable(5)
 *  +-rplDodagEntry(1) [rplInstanceID,rplDodagIndex]
 *     +- --- Unsigned32            rplDodagIndex(1)
 *     +- r-n InetAddressIPv6       rplDodagID(2)
 *     +- r-n RplDodagVersionNumber rplDodagVersion(3)
 *     +- r-n RplRank               rplDodagRank(4)
 *     +- r-n Enumeration           rplDodagState(5)
 *     +- r-n RplObjectiveCodePoint rplDodagOCP(6)
 *     +- r-n RplDAODelay           rplDodagDAODelay(7)
 *     +- r-n TruthValue            rplDodagDAOAckEnabled(8)
 *     +- r-n RplDodagPreference    rplDodagPreference(9)
 *     +- r-n RplMinHopRankIncrease rplDodagMinHopRankIncrease(10)
 *     +- r-n Unsigned32            rplDodagMaxRankIncrease(11)
 *     +- r-n Unsigned32            rplDodagIntervalDoublings(12)
 *     +- r-n Unsigned32            rplDodagIntervalMin(13)
 *     +- r-n Unsigned32            rplDodagRedundancyConstant(14)
 *     +- r-n RplPathControlSize    rplDodagPathControlSize(15)
 */

/* rplDodagTable */

static const u8t ber_oid_rplDodagEntry[] PROGMEM = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0xF2, 0x06, 0x01, 0x02, 0x01, 0x05, 0x01};
static const ptr_t oid_rplDodagEntry PROGMEM     = {ber_oid_rplDodagEntry, 13};

#define rplDodagID                  2
#define rplDodagVersion             3
#define rplDodagRank                4
#define rplDodagState               5
#define rplDodagOCP                 6
#define rplDodagDAODelay            7
#define rplDodagDAOAckEnabled       8
#define rplDodagPreference          9
#define rplDodagMinHopRankIncrease 10
#define rplDodagMaxRankIncrease    11
#define rplDodagIntervalDoublings  12
#define rplDodagIntervalMin        13
#define rplDodagRedundancyConstant 14
#define rplDodagPathControlSize    15

s8t getRplDodagEntry(mib_object_t* object, u8t* oid, u8t len) {
  u32t oid_el1, oid_el2, oid_el3;
  u8t i;
  rpl_instance_t *instance;
  
  if (len != 3) {
    return -1;
  }

  i = ber_decode_oid_item(oid, len, &oid_el1);
  i = i + ber_decode_oid_item(oid + i, len - i, &oid_el2);
  i = i + ber_decode_oid_item(oid + i, len - i, &oid_el3);
  printf("getRplDodagEntry - oid_el1.oid_el2.oid_el3: %d.%d.%d\n", oid_el1, oid_el2, oid_el3);

  instance = rpl_get_instance(oid_el2);
  if (instance == NULL) {
    return -1;
  }

  if (oid_el3 <= 0 || oid_el3 > RPL_MAX_DAG_PER_INSTANCE) {
    return -1;
  }

  if (!instance->dag_table[oid_el3-1].used) {
    return -1;
  }

  switch (oid_el1)
    {
    case rplDodagID:      
      object->varbind.value_type = BER_TYPE_OCTET_STRING;
      object->varbind.value.p_value.ptr = (u8t*) instance->dag_table[oid_el3-1].dag_id.u8;
      object->varbind.value.p_value.len = 16;
      break;
    case rplDodagVersion:
      object->varbind.value_type = BER_TYPE_UNSIGNED32;
      object->varbind.value.i_value = instance->dag_table[oid_el3-1].version;
      //object->varbind.value.i_value = 0;
      break;
    case rplDodagRank:
      object->varbind.value_type = BER_TYPE_UNSIGNED32;
      object->varbind.value.i_value = instance->dag_table[oid_el3-1].rank;
      //object->varbind.value.i_value = 0;
      break;
    case rplDodagState:
      object->varbind.value_type = BER_TYPE_INTEGER;
      object->varbind.value.i_value = instance->dag_table[oid_el3-1].grounded;
      //object->varbind.value.i_value = 0;
      break;
    case rplDodagOCP:
      object->varbind.value_type = BER_TYPE_UNSIGNED32;
      object->varbind.value.i_value = RPL_OF.ocp;
      break;
    case rplDodagDAODelay:
      object->varbind.value_type = BER_TYPE_UNSIGNED32;
      object->varbind.value.i_value = etimer_expiration_time(&instance->dao_timer.etimer);
      //object->varbind.value.i_value = 0;
      break;
    case rplDodagDAOAckEnabled:
      object->varbind.value_type = BER_TYPE_INTEGER;
#ifdef RPL_CONF_DAO_ACK
      object->varbind.value.i_value = 1; //True(1)
#else
      object->varbind.value.i_value = 2; //False(2)
#endif
      break;
    case rplDodagPreference:
      object->varbind.value_type = BER_TYPE_UNSIGNED32;
      object->varbind.value.i_value = instance->dag_table[oid_el3-1].preference;
      //object->varbind.value.i_value = 0;
      break;
    case rplDodagMinHopRankIncrease:
      object->varbind.value_type = BER_TYPE_UNSIGNED32;
      object->varbind.value.i_value = instance->min_hoprankinc;
      //object->varbind.value.i_value = 0;
      break;
    case rplDodagMaxRankIncrease:
      object->varbind.value_type = BER_TYPE_UNSIGNED32;
      object->varbind.value.i_value = instance->max_rankinc;
      //object->varbind.value.i_value = 0;
      break;
    case rplDodagIntervalDoublings:
      object->varbind.value_type = BER_TYPE_UNSIGNED32;
      object->varbind.value.i_value = instance->dio_intdoubl;
      //object->varbind.value.i_value = 0;
      break;
    case rplDodagIntervalMin:
      object->varbind.value_type = BER_TYPE_UNSIGNED32;
      object->varbind.value.i_value = instance->dio_intmin;
      //object->varbind.value.i_value = 0;
      break;
    case rplDodagRedundancyConstant:
      object->varbind.value_type = BER_TYPE_UNSIGNED32;
      object->varbind.value.i_value = instance->dio_redundancy;
      //object->varbind.value.i_value = 0;
      break;
    case rplDodagPathControlSize:
      object->varbind.value_type = BER_TYPE_UNSIGNED32;
      object->varbind.value.i_value = instance->min_hoprankinc;
      //object->varbind.value.i_value = 0;
      break;
    default:
      return -1;
    }
  return 0;
}

u8t RplDodagColumns[] = {rplDodagID, rplDodagVersion, rplDodagRank, rplDodagState, rplDodagOCP, rplDodagDAODelay, rplDodagDAOAckEnabled, rplDodagPreference, rplDodagMinHopRankIncrease, rplDodagMaxRankIncrease, rplDodagIntervalDoublings, rplDodagIntervalMin, rplDodagRedundancyConstant, rplDodagPathControlSize};
#define RplDodagTableSize RPL_MAX_DAG_PER_INSTANCE

ptr_t* getNextOIDRplDodagEntry(mib_object_t* object, u8t* oid, u8t len) {
  ptr_t* ret = 0;
  u32t oid_el1, oid_el2, oid_el3;
  u8t i;
  u8t columnNumber = 14;
  
  extern rpl_instance_t instance_table[];
  
  i = ber_decode_oid_item(oid, len, &oid_el1);
  i = i + ber_decode_oid_item(oid + i, len - i, &oid_el2);
  i = i + ber_decode_oid_item(oid + i, len - i, &oid_el3);

  //printf("\ngetNextOIDRplDodagEntry\n");
  printf("oid_el1: %d\n", oid_el1);
  printf("oid_el2: %d\n", oid_el2);
  printf("oid_el3: %d\n", oid_el3);
  
  for(i = 0; i < columnNumber; i++) {
    printf("i: %d, columnNumber: %d, oid_el1: %d, RplDodagColumns[i]: %d, oid_el2: %d, RplInstanceTableSize: %d, oid_el3: %d, RplDodagTableSize: %d\n", i, columnNumber, oid_el1, RplDodagColumns[i], instance_loc(oid_el2), RplInstanceTableSize, oid_el3, RplDodagTableSize);
    if ((oid_el1 < RplDodagColumns[i]) || 
	(oid_el1 == RplDodagColumns[i] && instance_loc(oid_el2) < RplInstanceTableSize) ||
	(oid_el1 == RplDodagColumns[i] && oid_el3 < RplDodagTableSize)) {
      printf("Inside IF statement\n");
      ret = oid_create();
      CHECK_PTR_U(ret);
      ret->len = 3;
      ret->ptr = malloc(3);
      CHECK_PTR_U(ret->ptr);
      if (oid_el1 < RplDodagColumns[i]) {
	printf("Inside IF statement - 0.0.0 OID (%d < %d)\n", oid_el1, RplDodagColumns[i]);
	ret->ptr[0] = RplDodagColumns[i];
	ret->ptr[1] = instance_table[0].instance_id;
	ret->ptr[2] = 1;
	printf("Created [if]: %d.%d.%d\n", ret->ptr[0], ret->ptr[1], ret->ptr[2]);
      } else {
	printf("Inside IF statement - x.x.x OID (%d == %d)\n", oid_el1, RplDodagColumns[i]);
	printf("oid_el2: %d, first instance: %d\n", oid_el2, instance_table[0].instance_id);
	if(instance_loc(oid_el2) == -1 && oid_el2 < instance_table[0].instance_id) {
	  printf("Inside instance not found\n");
	  ret->ptr[0] = RplDodagColumns[i];
	  ret->ptr[1] = instance_table[0].instance_id;
	  ret->ptr[2] = 1;	  
	  return ret;
	} 
	if(instance_loc(oid_el2) < RplInstanceTableSize && oid_el3 < RplDodagTableSize) {
	  printf("Inside oid_el2 < RplInstanceTableSize && oid_el3 < RplDodagTableSize\n");
	  ret->ptr[0] = oid_el1;
	  ret->ptr[1] = instance_table[instance_loc(oid_el2)].instance_id;
	  ret->ptr[2] = oid_el3 + 1;
	} else if (instance_loc(oid_el2) < RplInstanceTableSize && oid_el3 == RplDodagTableSize) {
	  printf("Inside oid_el2 < RplInstanceTableSize && oid_el3 == RplDodagTableSize\n");
	  if(instance_loc(oid_el2) + 1 <= RplInstanceTableSize) {
	    ret->ptr[1] = instance_table[instance_loc(oid_el2)+1].instance_id;
	  } else {
	    return 0;
	  }
	  ret->ptr[0] = oid_el1;
	  ret->ptr[2] = 1;
	} else if (instance_loc(oid_el2) == RplInstanceTableSize && oid_el3 < RplDodagTableSize) {
	  printf("Inside oid_el2 == RplInstanceTableSize && oid_el3 < RplDodagTableSize\n");
	  ret->ptr[0] = oid_el1;
	  ret->ptr[1] = instance_table[instance_loc(oid_el2)].instance_id;
	  ret->ptr[2] = oid_el3 + 1;
	} else {
	  return 0;
	}
	printf("Created [if]: %d.%d.%d\n", ret->ptr[0], ret->ptr[1], ret->ptr[2]);
      }
      break;
    }
  }
  return ret;
}

/*
 * rplDodagParentTable group
 *
 * rplDodagParentTable(6)
 *  +-rplDodagParentEntry(1) [rplInstanceID,rplDodagIndex,rplDodagParentID]
 *     +- --- InetAddressIPv6 rplDodagParentID(1)
 *     +- r-n InterfaceIndex  rplDodagParentIf(2)
 */

/* rplDodagParentTable */

static const u8t ber_oid_rplDodagParentEntry[] PROGMEM = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0xF2, 0x06, 0x01, 0x02, 0x01, 0x06, 0x01};
static const ptr_t oid_rplDodagParentEntry PROGMEM     = {ber_oid_rplDodagParentEntry, 13};

#define rplDodagParentIf 2

s8t getRplDodagParentEntry(mib_object_t* object, u8t* oid, u8t len) {
  u32t oid_el1, oid_el2, oid_el3, oid_el4;
  u8t i=0, j=0;
  u8t searchid[16];
  rpl_instance_t *instance;
  rpl_parent_t *currentparent;

  if (len < 19) {
    return -1;
  }

  i = ber_decode_oid_item(oid, len, &oid_el1);

  i = i + ber_decode_oid_item(oid + i, len - i, &oid_el2);
  instance = rpl_get_instance(oid_el2);
  if (instance == NULL) {
    return -1;
  }

  i = i + ber_decode_oid_item(oid + i, len - i, &oid_el3);
  if(!instance->dag_table[oid_el3-1].used || oid_el3 > RPL_MAX_DAG_PER_INSTANCE) {
    return -1;
  }

  currentparent = list_head(instance->dag_table[oid_el3-1].parents);

  printf("\nRequested OID: %d.%d.%d", oid_el1, oid_el2, oid_el3);
  
  for (j = 0; j < 16; j++) {
    i = i + ber_decode_oid_item(oid + i, len - i, &oid_el4);
    searchid[j] = oid_el4; //*( u8t* ) &oid_el4;
    printf(".%d", oid_el4);
  }
  printf("\n");

  for (j = 0; j < 16; j++) {
    if (searchid[j] != currentparent->addr.u8[j]) {
      if (currentparent->next == NULL) {
	return -1;
      } else {
	currentparent = currentparent->next;
	j = 0;
      }
    }
  }

  switch(oid_el1)
    {
    case rplDodagParentIf:
      object->varbind.value_type = BER_TYPE_INTEGER;
      object->varbind.value.i_value = 1;
      break;
    default:
      return -1;
    }  
  return 0;
}

u8t RplDodagParentColumns[] = {rplDodagParentIf};

ptr_t* getNextOIDRplDodagParentEntry(mib_object_t* object, u8t* oid, u8t len) {
  ptr_t* ret = 0;
  u32t oid_el1, oid_el2, oid_el3, oid_el4;
  u32t oid_n1, oid_n2, oid_n3;
  u8t i, j, parentLoc, columnNumber = 1, searchid[16];
  rpl_parent_t *currentparent;
  u32t leng, pos;
  
  extern rpl_instance_t instance_table[];
  
  i = ber_decode_oid_item(oid, len, &oid_el1);
  i = i + ber_decode_oid_item(oid + i, len - i, &oid_el2);
  i = i + ber_decode_oid_item(oid + i, len - i, &oid_el3);
  printf("getNextOIDRplDodagParentEntry - Provided OID: %d.%d.%d\n", oid_el1, oid_el2, oid_el3);

  if (instance_table[0].dag_table[0].parents == NULL) {
    return 0;
  }
  currentparent = list_head(instance_table[0].dag_table[0].parents);

  if(oid_el1 <= 0 || (instance_loc(oid_el2) == -1 && oid_el2 < instance_table[0].instance_id)) {
    printf("Inside IF\n");
    /* rplDodagParentIf, rplInstanceID, rplDodagIndex */
    leng = ber_encoded_oid_item_length(RplDodagParentColumns[0]);
    leng = leng + ber_encoded_oid_item_length(instance_table[0].instance_id);
    leng = leng + ber_encoded_oid_item_length(1);

    /* rplDodagParentID */
    for (j = 0; j < 16; j++) {
      leng = leng + ber_encoded_oid_item_length(currentparent->addr.u8[j]);
    }

    ret = oid_create();
    CHECK_PTR_U(ret);
    ret->len = leng;
    ret->ptr = malloc(leng);
    CHECK_PTR_U(ret->ptr);
    pos = 0;


    /* Encoding: rplDodagParentIf, rplInstanceID, rplDodagIndex */
    pos = EncodeTableOID(ret->ptr, pos, RplDodagParentColumns[0]);
    if (pos == -1) {
      return 0;
    }
    pos = EncodeTableOID(ret->ptr, pos, instance_table[0].instance_id);
    if (pos == -1) {
      return 0;
    }
    pos = EncodeTableOID(ret->ptr, pos, 1);
    if (pos == -1) {
      return 0;
    }
    /* Encoding: rplDodagParentID */
    for (j = 0; j < 16; j++) {
      pos = EncodeTableOID(ret->ptr, pos, currentparent->addr.u8[j]);
      if (pos == -1) {
        return 0;
      }
    }
  } else {
    printf("Inside ELSE");
    /* rplDodagParentIf, rplInstanceID, rplDodagIndex */
    leng = ber_encoded_oid_item_length(RplDodagParentColumns[0]);
    leng = leng + ber_encoded_oid_item_length(instance_table[0].instance_id);
    leng = leng + ber_encoded_oid_item_length(1);
    
    /* rplDodagParentID */
    for (j = 0; j < 16; j++) {
      i = i + ber_decode_oid_item(oid, len, &oid_el4);
      searchid[j] = *( u8t* ) &oid_el4;
    }

    if(oid_el2 < instance_table[0].instance_id && oid_el3 < 1) {
      for (j = 0; j < 16; j++) {
	leng = leng + ber_encoded_oid_item_length(currentparent->addr.u8[j]);
      }      
    } else {    
      while(currentparent->next != NULL) {
	for (j = 0; j < 16; j++) {
	  if(currentparent->addr.u8[j] != searchid[j]) {
	    break;
	  }
	}
	if (j != 16) {
	  currentparent = currentparent->next;
	} else {
	  for (j = 0; j < 16; j++) {
	    leng = leng + ber_encoded_oid_item_length(currentparent->addr.u8[j]);
	  }
	  break;
	}
      }
    }

    if(leng < 19) {
      return 0;
    }
    
    ret = oid_create();
    CHECK_PTR_U(ret);
    ret->len = leng;
    ret->ptr = malloc(leng);
    CHECK_PTR_U(ret->ptr);
    pos = 0;
    
    /* Encoding: rplDodagParentIf, rplInstanceID, rplDodagIndex */
    pos = EncodeTableOID(ret->ptr, pos, RplDodagParentColumns[0]);
    if (pos == -1) {
      return 0;
    }
    pos = EncodeTableOID(ret->ptr, pos, instance_table[0].instance_id);
    if (pos == -1) {
      return 0;
    }
    pos = EncodeTableOID(ret->ptr, pos, 1);
    if (pos == -1) {
      return 0;
    }
    /* Encoding: rplDodagParentID */
    for (j = 0; j < 16; j++) {
      pos = EncodeTableOID(ret->ptr, pos, currentparent->addr.u8[j]);
      if (pos == -1) {
        return 0;
      } 
    }
  }     
  return ret;
}

/*
 * rplDodagChildTable group
 *
 * rplDodagChildTable(7)
 *  +-rplDodagChildEntry(1) [rplInstanceID,rplDodagIndex,
 *     |                      rplDodagChildID]
 *     +- --- InetAddressIPv6 rplDodagChildID(1)
 *     +- r-n InterfaceIndex  rplDodagChildIf(2)
 */

/* rplDodagChildTable */

static const u8t ber_oid_rplDodagChildEntry[] PROGMEM = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0xF2, 0x06, 0x01, 0x02, 0x01, 0x07, 0x01};
static const ptr_t oid_rplDodagChildEntry PROGMEM     = {ber_oid_rplDodagChildEntry, 13};

#define rplDodagChildIf 2

s8t loc_route(u8t *searchid, rpl_dag_t *dag) {
  int i, j;
  extern uip_ds6_route_t uip_ds6_routing_table[]; //UIP_DS6_ROUTE_NB

  for (i = 0; i < UIP_DS6_ROUTE_NB; i++) {
    for (j = 0; j < 16; j++) {
      if (searchid[j] != uip_ds6_routing_table[i].nexthop.u8[j])
	break;
    }
    if (j == 16 && uip_ds6_routing_table[i].isused && uip_ds6_routing_table[i].state.dag == dag) {
      return i;
    }
  }
  return -1;
}

s8t getRplDodagChildEntry(mib_object_t* object, u8t* oid, u8t len) {
  u32t oid_el1, oid_el2, oid_el3, oid_el4;
  u8t i=0, j=0, pos=0;
  u8t searchid[16];
  rpl_instance_t *instance;
  extern uip_ds6_route_t uip_ds6_routing_table[]; //UIP_DS6_ROUTE_NB

  if (len < 19) {
    return -1;
  }

  i = ber_decode_oid_item(oid, len, &oid_el1);

  i = i + ber_decode_oid_item(oid + i, len - i, &oid_el2);
  instance = rpl_get_instance(oid_el2);
  if (instance == NULL) {
    return -1;
  }

  i = i + ber_decode_oid_item(oid + i, len - i, &oid_el3);
  if(!instance->dag_table[oid_el3-1].used || oid_el3 > RPL_MAX_DAG_PER_INSTANCE) {
    return -1;
  }

  /* search for child routes */
  for (j = 0; j < 16; j++) {
    i = i + ber_decode_oid_item(oid + i, len - i, &oid_el4);
    searchid[j] = *( u8t* ) &oid_el4;
  }
  
  pos = loc_route(searchid, &instance->dag_table[oid_el3-1]);
  if (pos == -1) {
    return -1;
  }
  
  switch(oid_el1)
    {
    case rplDodagParentIf:
      object->varbind.value_type = BER_TYPE_INTEGER;
      object->varbind.value.i_value = 1;
      break;
    default:
      return -1;
    }  
  return 0;
}

/*
 * rplStats group
 *
 * rplStats(8)
 *  +- r-n Counter32 rplMemOverflows(1)
 *  +- r-n Counter32 rplParseErrors(2)
 *  +- r-n Counter32 rplUnknownMsgTypes(3)
 *  +- r-n Counter32 rplSecurityPolicyViolations(4)
 *  +- r-n Counter32 rplIntegrityCheckFailures(5)
 *  +- r-n Counter32 rplReplayProtectionFailures(6)
 *  +- r-n Counter32 rplValidParentFailures(7)
 *  +- r-n Counter32 rplNoInstanceIDs(8)
 *  +- r-n Counter32 rplTriggeredLocalRepairs(9)
 *  +- r-n Counter32 rplTriggeredGlobalRepairs(10)
 *  +- r-n Counter32 rplNoParentSecs(11)
 *  +- r-n Counter32 rplActiveNoParentSecs(12)
 *  +- r-n Counter32 rplOBitSetDownwards(13)
 *  +- r-n Counter32 rplOBitClearedUpwards(14)
 *  +- r-n Counter32 rplFBitSet(15)
 *  +- r-n Counter32 rplRBitSet(16)
 *  +- r-n Counter32 rplTrickleTimerResets(17)
*/

#if RPL_CONF_STATS
extern rpl_stats_t rpl_stats;
#endif

extern uint32_t MIBrplOBitSetDownwards;
extern uint32_t MIBrplOBitClearedUpwards;
extern uint32_t MIBrplFBitSet;
extern uint32_t MIBrplRBitSet;
extern uint32_t MIBrplNoInstanceIDs;

s8t getRplMemOverflows(mib_object_t* object, u8t* oid, u8t len)
{
#if RPL_CONF_STATS
  object->varbind.value.i_value = rpl_stats.mem_overflows;
#else
  object->varbind.value.i_value = 0;
#endif
  return 0;  
}

s8t getRplParseErrors(mib_object_t* object, u8t* oid, u8t len)
{
#if RPL_CONF_STATS
  object->varbind.value.i_value = rpl_stats.malformed_msgs;
#else
  object->varbind.value.i_value = 0;
#endif
  return 0;  
}

s8t getRplUnknownMsgTypes(mib_object_t* object, u8t* oid, u8t len)
{
  object->varbind.value.i_value = 0;
  return 0;  
}

s8t getRplSecurityPolicyViolations(mib_object_t* object, u8t* oid, u8t len)
{
  object->varbind.value.i_value = 0;
  return 0;  
}

s8t getRplIntegrityCheckFailures(mib_object_t* object, u8t* oid, u8t len)
{
  object->varbind.value.i_value = 0;
  return 0;  
}

s8t getRplReplayProtectionFailures(mib_object_t* object, u8t* oid, u8t len)
{
  object->varbind.value.i_value = 0;
  return 0;  
}

s8t getRplValidParentFailures(mib_object_t* object, u8t* oid, u8t len)
{
  object->varbind.value.i_value = 0;
  return 0;  
}

s8t getRplNoInstanceIDs(mib_object_t* object, u8t* oid, u8t len)
{
  object->varbind.value.i_value = MIBrplNoInstanceIDs;
  return 0;  
}

s8t getRplTriggeredLocalRepairs(mib_object_t* object, u8t* oid, u8t len)
{
#if RPL_CONF_STATS
  object->varbind.value.i_value = rpl_stats.local_repairs;
#else
  object->varbind.value.i_value = 0;
#endif
  return 0;  
}

s8t getRplTriggeredGlobalRepairs(mib_object_t* object, u8t* oid, u8t len)
{
#if RPL_CONF_STATS
  object->varbind.value.i_value = rpl_stats.global_repairs;
#else
  object->varbind.value.i_value = 0;
#endif
  return 0;  
}

s8t getRplNoParentSecs(mib_object_t* object, u8t* oid, u8t len)
{
  object->varbind.value.i_value = 0;
  return 0;  
}

s8t getRplActiveNoParentSecs(mib_object_t* object, u8t* oid, u8t len)
{
  object->varbind.value.i_value = 0;
  return 0;  
}

s8t getRplOBitSetDownwards(mib_object_t* object, u8t* oid, u8t len)
{
  object->varbind.value.i_value = MIBrplOBitSetDownwards;
  return 0;  
}

s8t getRplOBitClearedUpwards(mib_object_t* object, u8t* oid, u8t len)
{
  object->varbind.value.i_value = MIBrplOBitClearedUpwards;
  return 0;  
}

s8t getRplFBitSet(mib_object_t* object, u8t* oid, u8t len)
{
  object->varbind.value.i_value = MIBrplFBitSet;
  return 0;  
}

s8t getRplRBitSet(mib_object_t* object, u8t* oid, u8t len)
{
  object->varbind.value.i_value = MIBrplRBitSet;
  return 0;  
}

s8t getRplTrickleTimerResets(mib_object_t* object, u8t* oid, u8t len)
{
#if RPL_CONF_STATS
  object->varbind.value.i_value = rpl_stats.resets;
#else
  object->varbind.value.i_value = 0;
#endif
  return 0;  
}

/*
 * rplMsgStatsTable group
 * 
 * rplMsgStatsTable(9)
 *  +-rplMsgStatsEntry(1) [rplMsgStatsType]
 *  +- --- RplMessageType rplMsgStatsType(1)
 *  +- r-n Counter32      rplMsgStatsInMsgs(2)
 *  +- r-n Counter32      rplMsgStatsOutMsgs(3)
 */

/* rplMsgStatsTable */
static const u8t ber_oid_rplMsgStatsEntry[] PROGMEM = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0xF2, 0x06, 0x01, 0x02, 0x01, 0x09, 0x01};
static const ptr_t oid_rplMsgStatsEntry PROGMEM     = {ber_oid_rplMsgStatsEntry, 13};

extern uint32_t MIBInDISCounter;
extern uint32_t MIBOutDISCounter;
extern uint32_t MIBInDIOCounter;
extern uint32_t MIBOutDIOCounter;
extern uint32_t MIBInDAOCounter;
extern uint32_t MIBOutDAOCounter;
extern uint32_t MIBInDAOAckCounter;
extern uint32_t MIBOutDAOAckCounter;

#define rplMsgStatsInMsgs  2
#define rplMsgStatsOutMsgs 3

s8t getRplMsgStatsEntry(mib_object_t* object, u8t* oid, u8t len) 
{
  u32t oid_el1, oid_el2;
  u8t i;
  
  if (len < 2) {
    return -1;
  }

  i = ber_decode_oid_item(oid, len, &oid_el1);
  i = ber_decode_oid_item(oid + i, len - i, &oid_el2);
  
  switch (oid_el2) 
    {
    case RPL_CODE_DIS:
      switch (oid_el1) 
	{
	case rplMsgStatsInMsgs:
	  object->varbind.value_type = BER_TYPE_COUNTER32;
	  object->varbind.value.i_value = MIBInDISCounter;
	  break;
	case rplMsgStatsOutMsgs:
	  object->varbind.value_type = BER_TYPE_COUNTER32;
	  object->varbind.value.i_value = MIBOutDISCounter;
	  break;
	default:
	  return -1;
	}
      break;
    case RPL_CODE_DIO:
      switch (oid_el1) 
	{
	case rplMsgStatsInMsgs:
	  object->varbind.value_type = BER_TYPE_COUNTER32;
	  object->varbind.value.i_value = MIBInDIOCounter;
	  break;
	case rplMsgStatsOutMsgs:
	  object->varbind.value_type = BER_TYPE_COUNTER32;
	  object->varbind.value.i_value = MIBOutDIOCounter;
	  break;
	default:
	  return -1;
	}
      break;
    case RPL_CODE_DAO:
      switch (oid_el1) 
	{
	case rplMsgStatsInMsgs:
	  object->varbind.value_type = BER_TYPE_COUNTER32;
	  object->varbind.value.i_value = MIBInDAOCounter;
	  break;
	case rplMsgStatsOutMsgs:
	  object->varbind.value_type = BER_TYPE_COUNTER32;
	  object->varbind.value.i_value = MIBOutDAOCounter;
	  break;
	default:
	  return -1;
	}
      break;
    case RPL_CODE_DAO_ACK:
      switch (oid_el1) 
	{
	case rplMsgStatsInMsgs:
	  object->varbind.value_type = BER_TYPE_COUNTER32;
	  object->varbind.value.i_value = MIBInDAOAckCounter;
	  break;
	case rplMsgStatsOutMsgs:
	  object->varbind.value_type = BER_TYPE_COUNTER32;
	  object->varbind.value.i_value = MIBOutDAOAckCounter;
	  break;
	default:
	  return -1;
	}
      break;
    case RPL_CODE_SEC_DIS:
      switch (oid_el1) 
	{
	case rplMsgStatsInMsgs:
	  object->varbind.value_type = BER_TYPE_COUNTER32;
	  object->varbind.value.i_value = 0;
	  break;
	case rplMsgStatsOutMsgs:
	  object->varbind.value_type = BER_TYPE_COUNTER32;
	  object->varbind.value.i_value = 0;
	  break;
	default:
	  return -1;
	}
      break;
    case RPL_CODE_SEC_DIO:
      switch (oid_el1) 
	{
	case rplMsgStatsInMsgs:
	  object->varbind.value_type = BER_TYPE_COUNTER32;
	  object->varbind.value.i_value = 0;
	  break;
	case rplMsgStatsOutMsgs:
	  object->varbind.value_type = BER_TYPE_COUNTER32;
	  object->varbind.value.i_value = 0;
	  break;
	default:
	  return -1;
	}
      break;
    case RPL_CODE_SEC_DAO:
      switch (oid_el1) 
	{
	case rplMsgStatsInMsgs:
	  object->varbind.value_type = BER_TYPE_COUNTER32;
	  object->varbind.value.i_value = 0;
	  break;
	case rplMsgStatsOutMsgs:
	  object->varbind.value_type = BER_TYPE_COUNTER32;
	  object->varbind.value.i_value = 0;
	  break;
	default:
	  return -1;
	}
      break;
    case RPL_CODE_SEC_DAO_ACK:
      switch (oid_el1) 
	{
	case rplMsgStatsInMsgs:
	  object->varbind.value_type = BER_TYPE_COUNTER32;
	  object->varbind.value.i_value = 0;
	  break;
	case rplMsgStatsOutMsgs:
	  object->varbind.value_type = BER_TYPE_COUNTER32;
	  object->varbind.value.i_value = 0;
	  break;
	default:
	  return -1;
	}
      break;
    case RPL_CODE_CONS_CHECK:
      switch (oid_el1) 
	{
	case rplMsgStatsInMsgs:
	  object->varbind.value_type = BER_TYPE_COUNTER32;
	  object->varbind.value.i_value = 0;
	  break;
	case rplMsgStatsOutMsgs:
	  object->varbind.value_type = BER_TYPE_COUNTER32;
	  object->varbind.value.i_value = 0;
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

u8t RplMsgStatsColumns[] = {rplMsgStatsInMsgs, rplMsgStatsOutMsgs};

ptr_t* getNextOIDRplMsgStatsEntry(mib_object_t* object, u8t* oid, u8t len) {
  ptr_t* ret = 0;
  u32t oid_el1, oid_el2, pos = 0;
  u8t i;
  u8t columnNumber = 2;
  
  i = ber_decode_oid_item(oid, len, &oid_el1);
  i = ber_decode_oid_item(oid + i, len - i, &oid_el2);

  for(i = 0; i < columnNumber; i++) {
    if (oid_el1 < RplMsgStatsColumns[i] || (oid_el1 == RplMsgStatsColumns[i] && oid_el2 < RPL_CODE_CONS_CHECK)) {
      if (oid_el1 < RplMsgStatsColumns[i]) {
	ret = oid_create();
        CHECK_PTR_U(ret);
        ret->len = 2;
        ret->ptr = malloc(2);
        CHECK_PTR_U(ret->ptr);
	ret->ptr[0] = RplMsgStatsColumns[i];
	ret->ptr[1] = RPL_CODE_DIS;
      } else {
	if(oid_el2 == RPL_CODE_DIS) {
	  ret = oid_create();
	  CHECK_PTR_U(ret);
	  ret->len = 2;
	  ret->ptr = malloc(2);
	  CHECK_PTR_U(ret->ptr);	  
	  ret->ptr[0] = RplMsgStatsColumns[i];
	  ret->ptr[1] = RPL_CODE_DIO;	  
	} else if (oid_el2 == RPL_CODE_DIO) {
	  ret = oid_create();
	  CHECK_PTR_U(ret);
	  ret->len = 2;
	  ret->ptr = malloc(2);
	  CHECK_PTR_U(ret->ptr);	  
	  ret->ptr[0] = RplMsgStatsColumns[i];
	  ret->ptr[1] = RPL_CODE_DAO;
	} else if (oid_el2 == RPL_CODE_DAO) {
	  ret = oid_create();
	  CHECK_PTR_U(ret);
	  ret->len = 2;
	  ret->ptr = malloc(2);
	  CHECK_PTR_U(ret->ptr);	  
	  ret->ptr[0] = RplMsgStatsColumns[i];
	  ret->ptr[1] = RPL_CODE_DAO_ACK;
	} else if (oid_el2 >= RPL_CODE_DAO_ACK && oid_el2 < RPL_CODE_SEC_DIS) {
	  ret = oid_create();
	  CHECK_PTR_U(ret);
	  ret->len = 1 + ber_encoded_oid_item_length(RPL_CODE_SEC_DIS);
	  ret->ptr = malloc(1 + ber_encoded_oid_item_length(RPL_CODE_SEC_DIS));
	  CHECK_PTR_U(ret->ptr);
	  pos = EncodeTableOID(ret->ptr, pos, RplMsgStatsColumns[i]);
	  EncodeTableOID(ret->ptr, pos, RPL_CODE_SEC_DIS);
	} else if (oid_el2 == RPL_CODE_SEC_DIS) {
	  ret = oid_create();
	  CHECK_PTR_U(ret);
	  ret->len = 1 + ber_encoded_oid_item_length(RPL_CODE_SEC_DIO);
	  ret->ptr = malloc(1 + ber_encoded_oid_item_length(RPL_CODE_SEC_DIO));
	  CHECK_PTR_U(ret->ptr);
	  pos = EncodeTableOID(ret->ptr, pos, RplMsgStatsColumns[i]);
	  EncodeTableOID(ret->ptr, pos, RPL_CODE_SEC_DIO);
	} else if (oid_el2 == RPL_CODE_SEC_DIO) {
	  ret = oid_create();
	  CHECK_PTR_U(ret);
	  ret->len = 1 + ber_encoded_oid_item_length(RPL_CODE_SEC_DAO);
	  ret->ptr = malloc(1 + ber_encoded_oid_item_length(RPL_CODE_SEC_DAO));
	  CHECK_PTR_U(ret->ptr);
	  pos = EncodeTableOID(ret->ptr, pos, RplMsgStatsColumns[i]);
	  EncodeTableOID(ret->ptr, pos, RPL_CODE_SEC_DAO);
	} else if (oid_el2 == RPL_CODE_SEC_DAO) {
	  ret = oid_create();
	  CHECK_PTR_U(ret);
	  ret->len = 1 + ber_encoded_oid_item_length(RPL_CODE_SEC_DAO_ACK);
	  ret->ptr = malloc(1 + ber_encoded_oid_item_length(RPL_CODE_SEC_DAO_ACK));
	  CHECK_PTR_U(ret->ptr);
	  pos = EncodeTableOID(ret->ptr, pos, RplMsgStatsColumns[i]);
	  EncodeTableOID(ret->ptr, pos, RPL_CODE_SEC_DAO_ACK);
	} else if (oid_el2 >= RPL_CODE_SEC_DAO_ACK && oid_el2 < RPL_CODE_CONS_CHECK) {
	  ret = oid_create();
	  CHECK_PTR_U(ret);
	  ret->len = 1 + ber_encoded_oid_item_length(RPL_CODE_CONS_CHECK);
	  ret->ptr = malloc(1 + ber_encoded_oid_item_length(RPL_CODE_CONS_CHECK));
	  CHECK_PTR_U(ret->ptr);
	  pos = EncodeTableOID(ret->ptr, pos, RplMsgStatsColumns[i]);
	  EncodeTableOID(ret->ptr, pos, RPL_CODE_CONS_CHECK);
	} else {
	  return 0;
	}	
      }
      break;
    }
  }
  return ret;
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
  char* sysDesc = "AVR Raven (RPL Mote)";
  char* sysContact = "Anuj Sehgal <s.anuj@jacobs-university.de>";
  char* sysName = "RPL-MIB Test Mote";
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


  // rplDefaults group
  if (add_scalar(&oid_rplDefaultDISMode, FLAG_ACCESS_READONLY, BER_TYPE_INTEGER, 0, &getRplDefaultDISMode, 0) == -1 ||
      add_scalar(&oid_rplDefaultDISMessages, FLAG_ACCESS_READONLY, BER_TYPE_UNSIGNED32, 0, &getRplDefaultDISMessages, 0) == -1 ||
      add_scalar(&oid_rplDefaultDISTimeout, FLAG_ACCESS_READONLY, BER_TYPE_UNSIGNED32, 0, &getRplDefaultDISTimeout, 0) == -1 ||
      add_scalar(&oid_rplDefaultDAODelay, FLAG_ACCESS_READONLY, BER_TYPE_UNSIGNED32, 0, &getRplDefaultDAODelay, 0) == -1 ||
      add_scalar(&oid_rplDefaultDAOAckEnabled, FLAG_ACCESS_READONLY, BER_TYPE_INTEGER, 0, &getRplDefaultDAOAckEnabled, 0) == -1 ||
      add_scalar(&oid_rplDefaultPreference, FLAG_ACCESS_READONLY, BER_TYPE_UNSIGNED32, 0, getRplDefaultPreference, 0) == -1 ||
      add_scalar(&oid_rplDefaultMinHopRankIncrease, FLAG_ACCESS_READONLY, BER_TYPE_UNSIGNED32, 0, &getRplDefaultMinHopRankIncrease, 0) == -1 ||
      add_scalar(&oid_rplDefaultMaxRankIncrease, FLAG_ACCESS_READONLY, BER_TYPE_UNSIGNED32, 0, &getRplDefaultMaxRankIncrease, 0) == -1 ||
      add_scalar(&oid_rplDefaultModeOfOperation, FLAG_ACCESS_READONLY, BER_TYPE_INTEGER, 0, &getRplDefaultModeOfOperation, 0) == -1 ||
      add_scalar(&oid_rplDefaultIntervalDoublings, FLAG_ACCESS_READONLY, BER_TYPE_UNSIGNED32, 0, &getRplDefaultIntervalDoublings, 0) == -1 ||
      add_scalar(&oid_rplDefaultIntervalMin, FLAG_ACCESS_READONLY, BER_TYPE_UNSIGNED32, 0, &getRplDefaultIntervalMin, 0) == -1 ||
      add_scalar(&oid_rplDefaultRedundancyConstant, FLAG_ACCESS_READONLY, BER_TYPE_UNSIGNED32, 0, &getRplDefaultRedundancyConstant, 0) == -1) {
    return -1;
  }
  
  // rplActive group
  if (add_scalar(&oid_rplActiveInstance, FLAG_ACCESS_READONLY, BER_TYPE_UNSIGNED32, 0, &getRplActiveInstance, 0) == -1 ||
      add_scalar(&oid_rplActiveDodag, FLAG_ACCESS_READONLY, BER_TYPE_OCTET_STRING, 0, &getRplActiveDodag, 0) == -1 ||
      add_scalar(&oid_rplActiveDodagTriggerSequence, FLAG_ACCESS_READONLY, BER_TYPE_UNSIGNED32, 0, &getRplActiveDodagTriggerSequence, 0) == -1) {
    return -1;
  }
  
  // rplOCPTable group
  if (add_table(&oid_rplOCPEntry, &getRplOCPEntry, &getNextOIDRplOCPEntry, 0) == -1) {
    return -1;
  }
  
  // rplInstanceTable group
  if (add_table(&oid_rplInstanceEntry, &getRplInstanceEntry, &getNextOIDRplInstanceEntry, 0) == -1) {
    return -1;
  }

  // rplDodagTable group
  if (add_table(&oid_rplDodagEntry, &getRplDodagEntry, &getNextOIDRplDodagEntry, 0) == -1) {
    return -1;
  }
  
  // rplDodagParentTable group
  if (add_table(&oid_rplDodagParentEntry, &getRplDodagParentEntry, &getNextOIDRplDodagParentEntry, 0) == -1) {
    return -1;
  }

  // rplStats group
  if (add_scalar(&oid_rplMemOverflows, FLAG_ACCESS_READONLY, BER_TYPE_COUNTER32, 0, &getRplMemOverflows, 0) == -1 ||
      add_scalar(&oid_rplParseErrors, FLAG_ACCESS_READONLY, BER_TYPE_COUNTER32, 0, &getRplParseErrors, 0) == -1 ||
      add_scalar(&oid_rplUnknownMsgTypes, FLAG_ACCESS_READONLY, BER_TYPE_COUNTER32, 0, &getRplUnknownMsgTypes, 0) == -1 ||
      add_scalar(&oid_rplSecurityPolicyViolations, FLAG_ACCESS_READONLY, BER_TYPE_COUNTER32, 0, &getRplSecurityPolicyViolations, 0) == -1 ||
      add_scalar(&oid_rplIntegrityCheckFailures, FLAG_ACCESS_READONLY, BER_TYPE_COUNTER32, 0, &getRplIntegrityCheckFailures, 0) == -1 ||
      add_scalar(&oid_rplReplayProtectionFailures, FLAG_ACCESS_READONLY, BER_TYPE_COUNTER32, 0, &getRplReplayProtectionFailures, 0) == -1 ||
      add_scalar(&oid_rplValidParentFailures, FLAG_ACCESS_READONLY, BER_TYPE_COUNTER32, 0, &getRplValidParentFailures, 0) == -1 ||
      add_scalar(&oid_rplNoInstanceIDs, FLAG_ACCESS_READONLY, BER_TYPE_COUNTER32, 0, &getRplNoInstanceIDs, 0) == -1 ||
      add_scalar(&oid_rplTriggeredLocalRepairs, FLAG_ACCESS_READONLY, BER_TYPE_COUNTER32, 0, &getRplTriggeredLocalRepairs, 0) == -1 ||
      add_scalar(&oid_rplTriggeredGlobalRepairs, FLAG_ACCESS_READONLY, BER_TYPE_COUNTER32, 0, &getRplTriggeredGlobalRepairs, 0) == -1 ||
      add_scalar(&oid_rplNoParentSecs, FLAG_ACCESS_READONLY, BER_TYPE_COUNTER32, 0, &getRplNoParentSecs, 0) == -1 ||
      add_scalar(&oid_rplActiveNoParentSecs, FLAG_ACCESS_READONLY, BER_TYPE_COUNTER32, 0, &getRplActiveNoParentSecs, 0) == -1 ||
      add_scalar(&oid_rplOBitSetDownwards, FLAG_ACCESS_READONLY, BER_TYPE_COUNTER32, 0, &getRplOBitSetDownwards, 0) == -1 ||
      add_scalar(&oid_rplOBitClearedUpwards, FLAG_ACCESS_READONLY, BER_TYPE_COUNTER32, 0, &getRplOBitClearedUpwards, 0) == -1 ||
      add_scalar(&oid_rplFBitSet, FLAG_ACCESS_READONLY, BER_TYPE_COUNTER32, 0, &getRplFBitSet, 0) == -1 ||
      add_scalar(&oid_rplRBitSet, FLAG_ACCESS_READONLY, BER_TYPE_COUNTER32, 0, &getRplRBitSet, 0) == -1 ||
      add_scalar(&oid_rplTrickleTimerResets, FLAG_ACCESS_READONLY, BER_TYPE_COUNTER32, 0, &getRplTrickleTimerResets, 0) == -1) {
    return -1;
  }
  
  // rplMsgStatsTable group
  if (add_table(&oid_rplMsgStatsEntry, &getRplMsgStatsEntry, &getNextOIDRplMsgStatsEntry, 0) == -1) {
    return -1;
  }
  
  return 0;
}
