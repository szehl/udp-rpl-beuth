#include <stdlib.h>
#include <string.h>

#include "contiki.h"

#define PRINTF(...)

#include "mib-init.h"
#include "ber.h"
#include "utils.h"
#include "logging.h"
#include "dispatcher.h"
#include "snmpd.h"
#include "net/uip-ds6.h"

#include "net/rpl/rpl-private.h"
#include "net/rpl/rpl.h"

#define PROGMEM
#define RPL_SNMP_WRITE 0

/*-----------------------------------------------------------------------------------*/
/*
 *  Helper function
 */

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

/*-----------------------------------------------------------------------------------*/
/*
 *  "system" group
 */

static u8t ber_oid_system_sysDesc[] PROGMEM             = {0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00};
static ptr_t oid_system_sysDesc PROGMEM                 = {ber_oid_system_sysDesc, 8};
static u8t ber_oid_system_sysObjectId [] PROGMEM        = {0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x02, 0x00};
static ptr_t oid_system_sysObjectId PROGMEM             = {ber_oid_system_sysObjectId, 8};
static u8t ber_oid_system_sysUpTime [] PROGMEM          = {0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x03, 0x00};
static ptr_t oid_system_sysUpTime PROGMEM               = {ber_oid_system_sysUpTime, 8};
static u8t ber_oid_system_sysContact [] PROGMEM         = {0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x04, 0x00};
static ptr_t oid_system_sysContact PROGMEM              = {ber_oid_system_sysContact, 8};
static u8t ber_oid_system_sysName [] PROGMEM            = {0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x05, 0x00};
static ptr_t oid_system_sysName PROGMEM                 = {ber_oid_system_sysName, 8};
static u8t ber_oid_system_sysLocation [] PROGMEM        = {0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x06, 0x00};
static ptr_t oid_system_sysLocation PROGMEM             = {ber_oid_system_sysLocation, 8};
static u8t ber_oid_system_sysServices [] PROGMEM        = {0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x07, 0x00};
static ptr_t oid_system_sysServices PROGMEM             = {ber_oid_system_sysServices, 8};
static u8t ber_oid_system_sysORLastChange [] PROGMEM    = {0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x08, 0x00};
static ptr_t oid_system_sysORLastChange PROGMEM         = {ber_oid_system_sysORLastChange, 8};
static u8t ber_oid_system_sysOREntry [] PROGMEM         = {0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x09, 0x01};
static ptr_t oid_system_sysOREntry PROGMEM              = {ber_oid_system_sysOREntry, 8};



s8t getTimeTicks(mib_object_t* object, u8t* oid, u8t len)
{
  object->varbind.value.u_value = clock_time();
  return 0;
}

/*-----------------------------------------------------------------------------------*/
/*
 * The RPL General.
 */
static u8t ber_oid_ber_globalDisMode [] PROGMEM         = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0xf2, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00};
static ptr_t oid_ber_globalDisMode PROGMEM              = {ber_oid_ber_globalDisMode, 14};


/*-----------------------------------------------------------------------------------*/
/*
 * The RPL Stats.
 */

#if RPL_CONF_STATS
static u8t ber_oid_ber_memOverflow [] PROGMEM         = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0xf2, 0x06, 0x01, 0x02, 0x01, 0x09, 0x01, 0x00};
static ptr_t oid_ber_memOverflow PROGMEM              = {ber_oid_ber_memOverflow, 14};
static u8t ber_oid_ber_LocalRepairs [] PROGMEM         = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0xf2, 0x06, 0x01, 0x02, 0x01, 0x09, 0x04, 0x00};
static ptr_t oid_ber_LocalRepairs PROGMEM              = {ber_oid_ber_LocalRepairs, 14};
static u8t ber_oid_ber_GlobalRepairs [] PROGMEM         = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0xf2, 0x06, 0x01, 0x02, 0x01, 0x09, 0x05, 0x00};
static ptr_t oid_ber_GlobalRepairs PROGMEM              = {ber_oid_ber_GlobalRepairs, 14};
static u8t ber_oid_ber_MalformedMsgs [] PROGMEM         = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0xf2, 0x06, 0x01, 0x02, 0x01, 0x09, 0x06, 0x00};
static ptr_t oid_ber_MalformedMsgs PROGMEM              = {ber_oid_ber_MalformedMsgs, 14};
static u8t ber_oid_ber_NoParent [] PROGMEM         = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0xf2, 0x06, 0x01, 0x02, 0x01, 0x09, 0x02, 0x00};
static ptr_t oid_ber_NoParent PROGMEM              = {ber_oid_ber_NoParent, 14};

extern rpl_stats_t rpl_stats;
#endif

/*-----------------------------------------------------------------------------------*/
/*
 * The RPL Active.
 * Needs editing ones more then one instance is supported
 *  +-rplActive(2)
 *  |  |
 *  |  +- rwn RplInstanceID   rplActiveInstance(1)
 *  |  +- rwn InetAddressIPv6 rplActiveDodag(2)
 *  |  +- rwn Unsigned32      rplActiveDodagTriggerSequence(3)
 */

static u8t ber_oid_ber_rpl_rplActiveInstance [] PROGMEM         = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0xf2, 0x06, 0x01, 0x02, 0x01, 0x02, 0x01, 0x00};
static ptr_t oid_ber_rpl_rplActiveInstance PROGMEM              = {ber_oid_ber_rpl_rplActiveInstance, 14};  
s8t getrplActiveInstance(mib_object_t* object, u8t* oid, u8t len)
{
  rpl_dag_t *dag;
  //dag = rpl_get_dag(RPL_ANY_INSTANCE);
  dag = rpl_get_any_dag();
  if(dag == NULL) {
    return -1;
  }
  
  object->varbind.value.i_value = dag->instance->instance_id;
  return 0;
}

static u8t ber_oid_ber_rpl_rplActiveDodag [] PROGMEM            = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0xf2, 0x06, 0x01, 0x02, 0x01, 0x02, 0x02, 0x00};

static ptr_t oid_ber_rpl_rplActiveDodag PROGMEM                 = {ber_oid_ber_rpl_rplActiveDodag, 14};  
s8t getrplActiveDodag(mib_object_t* object, u8t* oid, u8t len)
{
  rpl_dag_t *dag;
  //int i;
  //dag = rpl_get_dag(RPL_ANY_INSTANCE);
  dag = rpl_get_any_dag();
  if(dag == NULL) {
    return -1;
  }
  
  object->varbind.value.p_value.ptr = (u8t*) dag->dag_id.u8;
  object->varbind.value.p_value.len = 16;
  return 0;
}

static u8t ber_oid_ber_rpl_rplActiveDodagTriggerSequence [] PROGMEM         = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0xf2, 0x06, 0x01, 0x02, 0x01, 0x02, 0x03, 0x00};
static ptr_t oid_ber_rpl_rplActiveDodagTriggerSequence PROGMEM              = {ber_oid_ber_rpl_rplActiveDodagTriggerSequence, 14};  
s8t getActiveDodagTriggerSequence(mib_object_t* object, u8t* oid, u8t len)
{
  rpl_dag_t *dag;
  
  //dag = rpl_get_dag(RPL_ANY_INSTANCE);
  dag = rpl_get_any_dag();
  if(dag == NULL) {
    return -1;
  }
  
  object->varbind.value.i_value = dag->instance->dtsn_out;
  return 0;
}

#if RPL_SNMP_WRITE
#define SET_ACTIVE_DODAG_TRIGGER_SEQUENCE &setActiveDodagTriggerSequence
#define ACTIVE_DODAG_TRIGGER_SEQUENCE_FLAG FLAG_SET_VALUE
s8t setActiveDodagTriggerSequence(mib_object_t* object, u8t* oid, u8t len, varbind_value_t value)
{
  rpl_dag_t *dag;
  
  dag = rpl_get_dag(RPL_ANY_INSTANCE);
  if(dag == NULL) {
    return -1;
  }
  
  dag->dtsn_out = value.i_value;
  return 0;
}
#else
#define SET_ACTIVE_DODAG_TRIGGER_SEQUENCE 0
#define ACTIVE_DODAG_TRIGGER_SEQUENCE_FLAG FLAG_ACCESS_READONLY
#endif

/*-----------------------------------------------------------------------------------*/
/* The OCP TABLE.
 * Needs editing ones more then one instance is supported
 * 
 * +-rplOCPTable(3)
 * |  |
 * |  +-rplOCPEntry(1) [rplOCPCodepoint]
 * |     |
 * |     +- --- RplObjectiveCodePoint rplOCPCodepoint(1)
 * |     +- rwn TruthValue            rplOCPEnabled(2)
 * |
 */

static u8t ber_oid_ber_rpl_rplOCPTable [] PROGMEM         = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0xf2, 0x06, 0x01, 0x02, 0x01, 0x03, 0x01};
static ptr_t oid_ber_rpl_rplOCPTable PROGMEM              = {ber_oid_ber_rpl_rplOCPTable, 13};  
extern rpl_of_t RPL_OF;

#define rplOCPEnabled 2

s8t getRplOCPEntry(mib_object_t* object, u8t* oid, u8t len)
{
  u32t oid_el1, oid_el2;
  u8t i;
  
  i = ber_decode_oid_item(oid, len, &oid_el1);
  i = ber_decode_oid_item(oid + i, len - i, &oid_el2);
  
  if (len != 2) {
    return -1;
  }

  if (oid_el2 != RPL_OF.ocp) {
    return -1;
  }
  
  switch (oid_el1) {

    case rplOCPEnabled:
      object->varbind.value_type = BER_TYPE_INTEGER;
      object->varbind.value.i_value = 1;
      break;
    default:
      return -1;
  }
  
  return 0;
}

u8t RPLOPCColumns[] = {rplOCPEnabled};
#define RPLOCPSize     1

ptr_t* getNextRplOCPEntry(mib_object_t* object, u8t* oid, u8t len)
{
  //u8t columnNumber = 1;
  ptr_t* ret = 0;
  u32t oid_el1, oid_el2;
  u8t i;

  i = ber_decode_oid_item(oid, len, &oid_el1); //queried column
  i = ber_decode_oid_item(oid + i, len - i, &oid_el2); //rplOCPCodepoint
  
  if (oid_el1 < RPLOPCColumns[0] || (oid_el1 == RPLOPCColumns[0] && oid_el2 < RPLOCPSize)) {
    ret = oid_create();
    CHECK_PTR_U(ret);
    ret->len = 2;
    ret->ptr = malloc(2);
    CHECK_PTR_U(ret->ptr);
    ret->ptr[0] = RPLOPCColumns[0];
    ret->ptr[1] = RPL_OF.ocp;
  }
  return ret;
}

/*-----------------------------------------------------------------------------------*/
/* The RPL Instance TABLE.
 * Needs editing ones more then one instance is supported
 * 
 *  +-rplRPLInstanceTable(4)
 *  |  |
 *  |  +-rplRPLInstanceEntry(1) [rplRPLInstanceID]
 *  |     |
 *  |     +- --- RplInstanceID         rplRPLInstanceID(1)
 *  |     +- rwn RplDISMode            rplRPLInstanceDISMode(2)
 *  |     +- rwn RplObjectiveCodePoint rplRPLInstanceOCP(2)
 *  |     +- rwn Enumeration           rplRPLInstanceDAOAcknowledgement(4)
 *  |     +- rwn RplModeOfOperation    rplRPLInstanceModeOfOperation(5)
 */

static u8t ber_oid_ber_rpl_RPLInstanceTabel [] PROGMEM         = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0xf2, 0x06, 0x01, 0x02, 0x01, 0x04, 0x01};
static ptr_t oid_ber_rpl_RPLInstanceTabel PROGMEM              = {ber_oid_ber_rpl_RPLInstanceTabel, 13}; 

#define rplRPLInstanceDISMode 2
#define rplRPLInstanceDISMessages 3
#define rplRPLInstanceDISTimeout 4
#define rplRPLInstanceModeOfOperation 5

s8t getRPLInstanceEntry(mib_object_t* object, u8t* oid, u8t len)
{
  u32t oid_el1, oid_el2;
  u8t i;
  rpl_instance_t *instance;
  
  i = ber_decode_oid_item(oid, len, &oid_el1);
  i = ber_decode_oid_item(oid + i, len - i, &oid_el2);
  
  if (len != 2) {
    return -1;
  }
  
  instance = rpl_get_instance(oid_el2);
  if(instance == NULL) {
    return -1;
  }

  switch (oid_el1) { 
     case rplRPLInstanceDISMode:
       object->varbind.value_type = BER_TYPE_INTEGER;
#if RPL_DIS_SEND
       object->varbind.value.i_value = 2;
#else
       object->varbind.value.i_value = 1;
#endif
       break;
     case rplRPLInstanceDISMessages:
       object->varbind.value_type = BER_TYPE_INTEGER;
       object->varbind.value.i_value = 1;
       break;
     case rplRPLInstanceDISTimeout:
       object->varbind.value_type = BER_TYPE_INTEGER;
       object->varbind.value.i_value = 0;
       break;
     case rplRPLInstanceModeOfOperation:
       object->varbind.value_type = BER_TYPE_INTEGER;
       object->varbind.value.i_value = instance->mop;
       break;
     default:
       return -1;
  }  
  return 0;
}

u8t RPLInstanceTableColumns[] = {rplRPLInstanceDISMode, rplRPLInstanceDISMessages, rplRPLInstanceDISTimeout, rplRPLInstanceModeOfOperation};
#define RPLInstanceTableSize     1

ptr_t* getNextRPLInstanceEntry(mib_object_t* object, u8t* oid, u8t len)
{
  u8t columnNumber = 4;
  ptr_t* ret = 0;
  u32t oid_el1, oid_el2;
  u8t i;

  i = ber_decode_oid_item(oid, len, &oid_el1);
  i = ber_decode_oid_item(oid + i, len - i, &oid_el2);

  for (i = 0; i < columnNumber; i++) {
    if (oid_el1 < RPLInstanceTableColumns[i] || (oid_el1 == RPLInstanceTableColumns[i] && oid_el2 < RPLInstanceTableSize)) {
      ret = oid_create();
      CHECK_PTR_U(ret);
      ret->len = 2;
      ret->ptr = malloc(2);
      CHECK_PTR_U(ret->ptr);
      ret->ptr[0] = RPLInstanceTableColumns[i];
      if (oid_el1 < RPLInstanceTableColumns[i]) {
	ret->ptr[1] = 2;
      } else {
	ret->ptr[1] = oid_el2 + 1;
      }
      break;
    }
  }
  return ret;
}

/*-----------------------------------------------------------------------------------*/
/* The RPL DODAG TABLE.
 * rplDodagTable(5)
 * |
 * +-rplDodagEntry(1) [rplRPLInstanceID,rplDodagIndex]
 *     +- --- Unsigned32            rplDodagIndex(1)
 *     +- --- InetAddressIPv6       rplDodagRoot(2)
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

static u8t ber_oid_ber_rpl_rplDODAGTabel [] PROGMEM         = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0xf2, 0x06, 0x01, 0x02, 0x01, 0x05, 0x01};
static ptr_t oid_ber_rpl_rplDODAGTabel PROGMEM              = {ber_oid_ber_rpl_rplDODAGTabel, 13}; 

#define rplDodagVersionOID 3
#define rplDodagRankOID 4
#define rplDodagStateOID 5
#define rplDodagOCPOID 6
#define rplDodagDAODelayOID 7
#define rplDodagDAOAckEnabledOID 8
#define rplDodagPreferenceOID 9
#define rplDodagMinHopRankIncreaseOID 10
#define rplDodagMaxRankIncreaseOID 11
#define rplDodagIntervalDoublingsOID 12
#define rplDodagIntervalMinOID 13
#define rplDodagRedundancyConstantOID 14
#define rplDodagPathControlSizeOID 15

s8t getDODAGEntry(mib_object_t* object, u8t* oid, u8t len)
{
  u32t oid_el1, oid_el2, oid_el3;
  u8t i;
  rpl_instance_t *instance;

  if (len != 3) {
    return -1;
  }

  i = ber_decode_oid_item(oid, len, &oid_el1);

  i = i + ber_decode_oid_item(oid + i, len - i, &oid_el2); 
  instance = rpl_get_instance(oid_el2);
  if(instance == NULL) {
    return -1;
  }

  i = i + ber_decode_oid_item(oid + i, len - i, &oid_el3);
  if(!instance->dag_table[oid_el3].used || oid_el3 > RPL_MAX_DAG_PER_INSTANCE) {
    return -1;
  }
  
  switch (oid_el1) {
    case rplDodagVersionOID:
      object->varbind.value_type = BER_TYPE_GAUGE;
      object->varbind.value.i_value = instance->dag_table[oid_el3].version;
      break;
    case rplDodagRankOID:
      object->varbind.value_type = BER_TYPE_GAUGE;
      object->varbind.value.i_value = instance->dag_table[oid_el3].rank;
      break;
    case rplDodagStateOID:
      object->varbind.value_type = BER_TYPE_INTEGER;
      object->varbind.value.i_value = instance->dag_table[oid_el3].grounded;
      break;
    case rplDodagOCPOID:
      object->varbind.value_type = BER_TYPE_INTEGER;
      object->varbind.value.i_value = RPL_OF.ocp;
      break;      
    case rplDodagDAODelayOID:
      object->varbind.value_type = BER_TYPE_GAUGE;
      object->varbind.value.i_value = etimer_expiration_time(&instance->dao_timer.etimer);
      break;
    case rplDodagDAOAckEnabledOID:
      object->varbind.value_type = BER_TYPE_GAUGE;
#ifdef RPL_CONF_DAO_ACK
      object->varbind.value.i_value = 1; //True(1)
#else
      object->varbind.value.i_value = 2; //False(2)
#endif
      break;
    case rplDodagPreferenceOID:
      object->varbind.value_type = BER_TYPE_GAUGE;
      object->varbind.value.i_value = instance->dag_table[oid_el3].preference;
      break;
    case rplDodagMinHopRankIncreaseOID:
      object->varbind.value_type = BER_TYPE_GAUGE;
      object->varbind.value.i_value = instance->min_hoprankinc;
      break;
    case rplDodagMaxRankIncreaseOID:
      object->varbind.value_type = BER_TYPE_GAUGE;
      object->varbind.value.i_value = instance->max_rankinc;
      break;
    case rplDodagIntervalDoublingsOID:
      object->varbind.value_type = BER_TYPE_GAUGE;
      object->varbind.value.i_value = instance->dio_intdoubl;
      break;
    case rplDodagIntervalMinOID:
      object->varbind.value_type = BER_TYPE_GAUGE;
      object->varbind.value.i_value = instance->dio_intmin;
      break;
    case rplDodagRedundancyConstantOID:
      object->varbind.value_type = BER_TYPE_GAUGE;
      object->varbind.value.i_value = instance->dio_redundancy;
      break;
    case rplDodagPathControlSizeOID:
      object->varbind.value_type = BER_TYPE_GAUGE;
      object->varbind.value.i_value = instance->min_hoprankinc;
      break;
    default:
      return -1;
  }
  
  return 0;
}

u8t DODAGTableColumns[] = {rplDodagVersionOID, rplDodagRankOID, rplDodagStateOID, rplDodagOCPOID, rplDodagDAODelayOID, rplDodagDAOAckEnabledOID, rplDodagPreferenceOID, rplDodagMinHopRankIncreaseOID, rplDodagMaxRankIncreaseOID, rplDodagIntervalDoublingsOID, rplDodagIntervalMinOID, rplDodagRedundancyConstantOID, rplDodagPathControlSizeOID};
#define DODAGTableSize     RPL_MAX_DAG_PER_INSTANCE

ptr_t* getNextDODAGEntry(mib_object_t* object, u8t* oid, u8t len)
{
  u8t columnNumber = 13;
  u8t rowNumber = DODAGTableSize;
  ptr_t* ret = 0;
  u32t oid_el1, oid_el2, oid_el3;
  u32t oid_n1, oid_n2;
  u8t leng,pos;
  u8t i,j;
  rpl_instance_t *instance;
  
  i = ber_decode_oid_item(oid, len, &oid_el1); //queried object
  i = ber_decode_oid_item(oid + i, len - i, &oid_el2); //rplInstanceID
  i = ber_decode_oid_item(oid + i, len - i, &oid_el3); //rplDodagIndex

  for (i = 0; i < columnNumber; i++) {
    if (oid_el1 < DODAGTableColumns[i] || (oid_el1 == DODAGTableColumns[i] && oid_el2 < rowNumber)) {
      oid_n1 = DODAGTableColumns[i];
      
      if (oid_el1 < DODAGTableColumns[i]) {
	oid_n2 = 0;
      } else {
	oid_n2 = oid_el2 + 1;
      }

      instance = rpl_get_instance(oid_n2);
      if(instance == NULL) {
	return 0;
      }

      leng = ber_encoded_oid_item_length(oid_n1);
      leng += ber_encoded_oid_item_length(oid_n2);

      for (j = 0; j < 16 ; j++){
	leng += ber_encoded_oid_item_length(instance->current_dag->dag_id.u8[j]);
      }
      
      ret = oid_create();
      CHECK_PTR_U(ret);
      ret->len = leng;
      ret->ptr = malloc(leng);
      CHECK_PTR_U(ret->ptr);
      pos=0;
      
      pos = EncodeTableOID(ret->ptr, pos, oid_n1);
      if (pos == -1)
      {
	return 0;
      }
      pos = EncodeTableOID(ret->ptr, pos, oid_n2);
      if (pos == -1)
      {
	return 0;
      }
      
      for (j = 0; j < 16 ; j++){
	pos = EncodeTableOID(ret->ptr, pos, instance->current_dag->dag_id.u8[j]);
        if (pos == -1)
        {
	  return 0;
        }
      }
      
      break;
    }
  }
  return ret;
}


/*-----------------------------------------------------------------------------------*/
/* The RPL Dodag Parent TABLE.
 * Needs editing ones more then one instance is supported
 * 
 *  +-rplDodagParentTable(6)
 *  |  +-rplDodagParentEntry(1) [rplRPLInstanceID,rplDodagIndex,
 *  |     |                      rplDodagParentID]
 *  |     +- --- InetAddressIPv6 rplDodagParentID(1)
 *  |     +- r-n InterfaceIndex  rplDodagParentIf(2)
 */

static u8t ber_oid_ber_rpl_RPLParentTabel [] PROGMEM         = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0xf2, 0x06, 0x01, 0x02, 0x01, 0x06, 0x01};
static ptr_t oid_ber_rpl_RPLParentTabel PROGMEM              = {ber_oid_ber_rpl_RPLParentTabel, 13}; 

#define rplDodagParentIf 2

s8t getRPLParentEntry(mib_object_t* object, u8t* oid, u8t len)
{
  u32t oid_el1, oid_el2, oid_el3;
  u8t i=0,j;
  u8t searchid[16];
  rpl_instance_t *instance;
  rpl_parent_t *currentparent;

  if (len < 19) {
    return -1;
  }
  
  i = ber_decode_oid_item(oid, len, &oid_el1);

  i = i + ber_decode_oid_item(oid + i, len - i, &oid_el2);
  instance = rpl_get_instance(oid_el2);
  if(instance == NULL) {
    return -1;
  }

  i = i + ber_decode_oid_item(oid + i, len - i, &oid_el3);
  if(!instance->dag_table[oid_el3].used || oid_el3 > RPL_MAX_DAG_PER_INSTANCE) {
    return -1;
  }  
  
  currentparent = list_head(instance->dag_table[oid_el3].parents);
  
  for (j = 0; j < 16 ; j++){
    i = i + ber_decode_oid_item(oid + i, len - i, &oid_el3);
    searchid[j] = *( u8t* )&oid_el3;
  }
 
  for (j = 0; j < 16 ; j++){
    if(searchid[j] != currentparent->addr.u8[j]){
      if (currentparent->next == NULL) {
	return -1;
      } else {
	currentparent = currentparent->next;
	j = 0;
      }
    }
  }
  
  switch (oid_el1) {
    case rplDodagParentIf:
      object->varbind.value_type = BER_TYPE_INTEGER;
      object->varbind.value.i_value = 1;
      break;
    default:
      return -1;
  }
  
  return 0;
}

u8t RPLParentTableColumns[] = {rplDodagParentIf};

ptr_t* getNextRPLParentEntry(mib_object_t* object, u8t* oid, u8t len)
{
  //u8t columnNumber = 1;
  //u8t rowNumber = DODAGTableSize;
  ptr_t* ret = 0;
  u32t oid_el1, oid_el2, oid_el3, oid_el4;
  u32t oid_n1, oid_n2;
  u32t leng,pos;
  u8t i,j,searchid[16];
  rpl_instance_t *instance;
  rpl_parent_t *currentparent = NULL;
  
  if (len < 1) {
    oid_el1 = rplDodagParentIf;
    oid_el2 = 0;
  } else if (len < 2) {
    i = ber_decode_oid_item(oid, len, &oid_el1);
    oid_el2 = 0;
  } else {
    i = ber_decode_oid_item(oid, len, &oid_el1);
    i += ber_decode_oid_item(oid + i, len - i, &oid_el2);
  }
  
  if (oid_el1 > rplDodagParentIf) {
    return 0;
  }

  if (oid_el1 < rplDodagParentIf) {
    oid_el1 = rplDodagParentIf;
  }
  
  if (len < 19) {
    instance = rpl_get_instance(oid_el2);
    if(instance == NULL){
      return 0;
    }
      
    currentparent = list_head(instance->current_dag->parents);
    if(currentparent == NULL){
      return 0;
    }

    oid_n1 = rplDodagParentIf;
    oid_n2 = 0;    
  } else {
    i = i + ber_decode_oid_item(oid + i, len - i, &oid_el3); //rplDodagIndex

    for (j = 0; j < 16 ; j++){
      i = i + ber_decode_oid_item(oid + i, len - i, &oid_el4);
      searchid[j] = *( u8t* )&oid_el4;
    } //searchid[j] has rplDodagParentID
    
    instance = rpl_get_instance(oid_el2);
    if (instance == NULL){
      return 0;
    }

    currentparent = list_head(instance->dag_table[oid_el3].parents);
    if (currentparent==NULL) {
      return 0;
    }

    for (j = 0; j < 16; j++)
    {
      if (searchid[j] < currentparent->addr.u8[j]) {
	oid_n1=rplDodagParentIf;
	oid_n2=0;
	break;
      } else if (searchid[j] > currentparent->addr.u8[j] || j==15 ) {
	if (currentparent->next != NULL) {
	  currentparent = currentparent->next;
	  j = 0;
	} else {
	  return 0;
	}
      }
    }
  }
  

  leng = ber_encoded_oid_item_length(oid_n1);
  leng += ber_encoded_oid_item_length(oid_n2);
  leng += ber_encoded_oid_item_length(oid_el3);

  for (j = 0; j < 16 ; j++){
    leng += ber_encoded_oid_item_length(currentparent->addr.u8[j]);
  }
      
  ret = oid_create();
  CHECK_PTR_U(ret);
  ret->len = leng;
  ret->ptr = malloc(leng);
  CHECK_PTR_U(ret->ptr);
  pos=0;
      
  pos = EncodeTableOID(ret->ptr, pos, oid_n1);
  if (pos == -1) {
    return 0;
  }
  pos = EncodeTableOID(ret->ptr, pos, oid_n2);
  if (pos == -1) {
    return 0;
  }
      
  pos = EncodeTableOID(ret->ptr, pos, oid_el3);
  if (pos == -1) {
    return 0;
  }

  for (j = 0; j < 16 ; j++){
    pos = EncodeTableOID(ret->ptr, pos, currentparent->addr.u8[j]);
    if (pos == -1) {
      return 0;
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
#if RPL_DIS_SEND
  s32t dismode = 2;
#else
  s32t dismode = 1;
#endif
  
  //System Stats
  if (add_scalar(&oid_system_sysDesc, FLAG_ACCESS_READONLY, BER_TYPE_OCTET_STRING, CONTIKI_VERSION_STRING, 0, 0) == -1 ||
      add_scalar(&oid_system_sysObjectId, FLAG_ACCESS_READONLY, BER_TYPE_OID, &oid_jacobs_raven, 0, 0) == -1 ||
      add_scalar(&oid_system_sysUpTime, FLAG_ACCESS_READONLY, BER_TYPE_TIME_TICKS, 0, &getTimeTicks, 0) == -1 ||
      add_scalar(&oid_system_sysContact, 0, BER_TYPE_OCTET_STRING, "<s.anuj@jacobs-university.de>", 0, 0) == -1 ||
      add_scalar(&oid_system_sysName, 0, BER_TYPE_OCTET_STRING, "RPL-MIB Test Node", 0, 0) == -1 ||
      add_scalar(&oid_system_sysLocation, 0, BER_TYPE_OCTET_STRING, "Jacobs University Bremen", 0, 0) == -1 ||
      add_scalar(&oid_system_sysServices, FLAG_ACCESS_READONLY, BER_TYPE_INTEGER, &defaultServiceValue, 0, 0) == -1 ||
      add_scalar(&oid_system_sysORLastChange, FLAG_ACCESS_READONLY, BER_TYPE_TIME_TICKS, 0, 0, 0) == -1)
    {
      return -1;
    }
  
  //rplGeneral
  if (add_scalar(&oid_ber_globalDisMode, FLAG_ACCESS_READONLY, BER_TYPE_INTEGER, &dismode, 0, 0) == -1)
    {
      return -1;
    }
  
  if (add_scalar(&oid_ber_rpl_rplActiveInstance, FLAG_ACCESS_READONLY, BER_TYPE_GAUGE,  0,  &getrplActiveInstance, 0) != ERR_NO_ERROR)
    {
      return -1;
    }  
  if (add_scalar(&oid_ber_rpl_rplActiveDodag, FLAG_ACCESS_READONLY, BER_TYPE_OCTET_STRING, 0, &getrplActiveDodag, 0)!= ERR_NO_ERROR )
    {
      return -1;
    }
  /*
  if (add_scalar(&oid_ber_rpl_rplActiveDodagDAOSequence, FLAG_ACCESS_READONLY, BER_TYPE_GAUGE, &dao_sequence, 0,0) != ERR_NO_ERROR)
    {
    return -1;
    } */

  if (add_scalar(&oid_ber_rpl_rplActiveDodagTriggerSequence, ACTIVE_DODAG_TRIGGER_SEQUENCE_FLAG, BER_TYPE_GAUGE, 0, &getActiveDodagTriggerSequence, SET_ACTIVE_DODAG_TRIGGER_SEQUENCE) != ERR_NO_ERROR)
    {
      return -1;
    }
  
  if (add_table(&oid_ber_rpl_rplOCPTable, &getRplOCPEntry, &getNextRplOCPEntry, 0) == -1) 
    {
      return -1;
    }
  if (add_table(&oid_ber_rpl_RPLInstanceTabel, &getRPLInstanceEntry, &getNextRPLInstanceEntry, 0) == -1)
    {
      return -1;
    }
  if (add_table(&oid_ber_rpl_rplDODAGTabel, &getDODAGEntry, &getNextDODAGEntry, 0) == -1)
    {
      return -1;
    }
  if (add_table(&oid_ber_rpl_RPLParentTabel, &getRPLParentEntry, &getNextRPLParentEntry, 0) == -1) 
    {
      return -1;
    }
  
  #if RPL_CONF_STATS
  if (add_scalar(&oid_ber_memOverflow, FLAG_ACCESS_READONLY, BER_TYPE_COUNTER, &rpl_stats.mem_overflows, 0, 0) == -1 ||
      add_scalar(&oid_ber_NoParent, FLAG_ACCESS_READONLY, BER_TYPE_COUNTER, &rpl_stats.parent_switch, 0, 0) == -1 ||
      add_scalar(&oid_ber_LocalRepairs, FLAG_ACCESS_READONLY, BER_TYPE_COUNTER, &rpl_stats.local_repairs, 0, 0) == -1 ||
      add_scalar(&oid_ber_GlobalRepairs, FLAG_ACCESS_READONLY, BER_TYPE_COUNTER, &rpl_stats.global_repairs, 0, 0) == -1 ||
      add_scalar(&oid_ber_MalformedMsgs, FLAG_ACCESS_READONLY, BER_TYPE_COUNTER, &rpl_stats.malformed_msgs, 0, 0) == -1
      )
    {
      return -1;
    }
  #endif  
  
  return 0;
}
