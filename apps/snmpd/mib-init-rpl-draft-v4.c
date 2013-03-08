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

static u8t ber_oid_jacobs_raven[]      = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x9b, 0x39, 0x01, 0x01};
static ptr_t oid_jacobs_raven          = {ber_oid_jacobs_raven, 9};

/*-----------------------------------------------------------------------------------*/
/*
 * The Forwarding MIB
 */
extern uip_ds6_route_t uip_ds6_routing_table[UIP_DS6_ROUTE_NB];

// inetCidrRouteNumber
static u8t ber_oid_ber_inetCidrRouteNumber [] PROGMEM         = {0x2b, 0x06, 0x01, 0x02, 0x01, 0x04, 0x18, 0x06, 0x00};
static ptr_t oid_ber_inetCidrRouteNumber PROGMEM              = {ber_oid_ber_inetCidrRouteNumber, 9};  

s8t getinetCidrRouteNumber(mib_object_t* object, u8t* oid, u8t len)
{
  u8t route_id;
  u8t route_counter;
  
  route_counter = 0;
  
  for (route_id = 0; route_id<UIP_DS6_ROUTE_NB; route_id++){
    route_counter += uip_ds6_routing_table[route_id].isused;
  }
  
  object->varbind.value.i_value = route_counter;
  return 0;
}

// inetCidrRouteNumber
static u8t ber_oid_forwarding_table[]      =  {0x2b, 0x06, 0x01, 0x02, 0x01, 0x04, 0x18, 0x07, 0x01};
static ptr_t oid_forwarding_table          = {ber_oid_forwarding_table, 9};

#define inetCidrRouteIfIndex      7
#define inetCidrRouteType         8
#define inetCidrRouteProto        9
#define inetCidrRouteAge          10
#define inetCidrRouteNextHopAS    11
#define inetCidrRouteMetric1      12
#define inetCidrRouteMetric2      13
#define inetCidrRouteMetric3      14
#define inetCidrRouteMetric4      15
#define inetCidrRouteMetric5      16
#define inetCidrRouteStatus       17

s8t getRoutingTableEntry(mib_object_t* object, u8t* oid, u8t len)
{
  u32t oid_el1, oid_el[38];
  u8t i,j,routeid;
  //rpl_dag_t *dag;
  
  if(len<39){ //min 1entry+1type+16ip+1len+2policy+1type+16ip
    return -1;
  }
  
  i = ber_decode_oid_item(oid, len, &oid_el1);
  
  for(j=0;j<38;j++){
    i = i+ber_decode_oid_item(oid + i, len - i, &oid_el[j]);
  }
  
  //check type and policy fields
  if (oid_el[0]!=2 || oid_el[21]!=2 || oid_el[18]!=2 || oid_el[19]!=0 || oid_el[20]!=0 ) {
    return -1;
  }
  
  routeid = UIP_DS6_ROUTE_NB;
  i=UIP_DS6_ROUTE_NB;
  while (routeid == UIP_DS6_ROUTE_NB )
  {
    if(i<0 || i> UIP_DS6_ROUTE_NB){
      return -1;
    }
    if(!uip_ds6_routing_table[i].isused){
      i--;
      continue;
    }
    if(uip_ds6_routing_table[i].length!=oid_el[17]){
      i--;
      continue;
    }
    for (j = 0; j < 16 ; j++){
      if(j==15 && uip_ds6_routing_table[i].ipaddr.u8[j] == oid_el[j+1] && uip_ds6_routing_table[i].nexthop.u8[j] == oid_el[j+22] )
      {
	routeid = i;
	PRINTF("ROUTE ENTRY Found: %d %d; \n",i,routeid);
	break;
      }
      if(uip_ds6_routing_table[i].ipaddr.u8[j] != oid_el[j+1] || uip_ds6_routing_table[i].nexthop.u8[j] != oid_el[j+22])
      {
	i--;
	break;
      }
    }
  }
  
  switch (oid_el1) {

    case inetCidrRouteIfIndex:
      object->varbind.value_type = BER_TYPE_INTEGER;
      object->varbind.value.i_value = 259;
      break;
    case inetCidrRouteType:
      object->varbind.value_type = BER_TYPE_INTEGER;
      object->varbind.value.i_value = 4;
      break;
    case inetCidrRouteProto:
      object->varbind.value_type = BER_TYPE_INTEGER;
      object->varbind.value.i_value = 18;
      break;
    case inetCidrRouteAge:
      object->varbind.value_type = BER_TYPE_GAUGE;
      object->varbind.value.i_value = 0;
      break;
    case inetCidrRouteNextHopAS:
      object->varbind.value_type = BER_TYPE_GAUGE;
      object->varbind.value.i_value = 0;
      break;
    case inetCidrRouteMetric1:
      object->varbind.value_type = BER_TYPE_INTEGER;
      object->varbind.value.i_value = uip_ds6_routing_table[routeid].metric;
      break;
    case inetCidrRouteMetric2:
      object->varbind.value_type = BER_TYPE_INTEGER;
      object->varbind.value.i_value = -1;
      break;
    case inetCidrRouteMetric3:
      object->varbind.value_type = BER_TYPE_INTEGER;
      object->varbind.value.i_value = -1;
      break;
    case inetCidrRouteMetric4:
      object->varbind.value_type = BER_TYPE_INTEGER;
      object->varbind.value.i_value = -1;
      break;
    case inetCidrRouteMetric5:
      object->varbind.value_type = BER_TYPE_INTEGER;
      object->varbind.value.i_value = -1;
      break;
    case inetCidrRouteStatus:
      object->varbind.value_type = BER_TYPE_INTEGER;
      object->varbind.value.i_value = 1;
      break;
    default:
      PRINTF("DEFAULT ERROR\n");
      return -1;
  }
  
  return 0;
}

u8t RoutingTableColumns[] = {inetCidrRouteIfIndex, inetCidrRouteType, inetCidrRouteProto, inetCidrRouteAge, inetCidrRouteNextHopAS, inetCidrRouteMetric1, inetCidrRouteMetric2, inetCidrRouteMetric3, inetCidrRouteMetric4, inetCidrRouteMetric5, inetCidrRouteStatus};

ptr_t* getNEXTRoutingTableEntry(mib_object_t* object, u8t* oid, u8t len)
{
  ptr_t* ret = 0;
  u32t oid_el1, oid_el[38];
  u8t i,j, routeid=0, breaker;
  u32t pos, leng;
  
  i = ber_decode_oid_item(oid, len, &oid_el1);
  if(oid_el1 < inetCidrRouteIfIndex){
    oid_el1 = inetCidrRouteIfIndex;
  }else if(oid_el1 > inetCidrRouteStatus){
    return 0;
  }
  
  PRINTF("in oid: ");
  for(j=0;j<38;j++){
    if (len-i>=0) {
      i = i+ber_decode_oid_item(oid + i, len - i, &oid_el[j]);
    } else {
      oid_el[j] = 0;
    }
    PRINTF("%d.",oid_el[j]);
  }
  PRINTF("\n");
  
  if (oid_el[0] > 2 ){
    return 0;
  }
  routeid = UIP_DS6_ROUTE_NB;
  
  while ( oid_el1 <= inetCidrRouteStatus ){

    i=0;
    
    while (i<UIP_DS6_ROUTE_NB )
    {  
      breaker=0;
      if(!uip_ds6_routing_table[i].isused){
	i++;
	continue;
      }
    
      for (j = 0; j < 16 ; j++){
        if(uip_ds6_routing_table[i].ipaddr.u8[j] < oid_el[j+1]  )
        {
	  breaker=1;
          break;
        }
        if(uip_ds6_routing_table[i].ipaddr.u8[j] > oid_el[j+1]  )
        {
	  routeid=i;
	  breaker=2;
          break;
        }
      }
      if (breaker == 1) {
	i++;
	continue;
      }
      if (breaker == 2) {
	i++;
	break;
      }
      if( uip_ds6_routing_table[i].length < oid_el[17] ) {
	  i++;
          continue;
      }
      if( uip_ds6_routing_table[i].length > oid_el[17] ) {
	  routeid=i;
	  i++;
          break;
      }
      if ( oid_el[18] > 2 || (oid_el[18] == 2 && (oid_el[19] != 0 || oid_el[20] != 0 )) || oid_el[21] > 2 ){
	  i++;
          break;
      }
      if ( oid_el[21] < 2 || oid_el[18] < 2){
	  routeid=i;
	  i++;
          break;
      }
      for (j = 0; j < 16 ; j++){
        if(uip_ds6_routing_table[i].nexthop.u8[j] < oid_el[j+22]  )
        {
          break;
        }
        if(uip_ds6_routing_table[i].nexthop.u8[j] > oid_el[j+22]  )
        {
	  routeid=i;
	  breaker=2;
          break;
        }
      }
      i++;
      if (breaker != 0) {
	break;
      }
      PRINTF("NON Breaking %d\n",i);
    }
    if (routeid != UIP_DS6_ROUTE_NB){
      break;
    }
    if( i>=UIP_DS6_ROUTE_NB){
      if (oid_el1 < inetCidrRouteStatus) {
	oid_el1++;
	i=0;
	for(j=0;j<38;j++){
	  oid_el[j] = 0;
	}
      }else{
        PRINTF("no matching route\n");
        return 0;
      }
    }
  }

  while (i<UIP_DS6_ROUTE_NB )
  {
    breaker = 0;
    
    if(!uip_ds6_routing_table[i].isused){
      i++;
      continue;
    }
    
    
    for (j = 0; j < 16 ; j++){
      if(uip_ds6_routing_table[i].ipaddr.u8[j] < oid_el[j+1] || uip_ds6_routing_table[i].ipaddr.u8[j] > uip_ds6_routing_table[routeid].ipaddr.u8[j] )
      {
	breaker = 1;
        break;
      }
      if(uip_ds6_routing_table[i].ipaddr.u8[j] > oid_el[j+1] && uip_ds6_routing_table[i].ipaddr.u8[j] < uip_ds6_routing_table[routeid].ipaddr.u8[j] )
      {
	routeid=i;
	breaker =1;
        break;
      }
    }
    if (breaker == 1) {
      i++;
      continue;
    }
    if( uip_ds6_routing_table[i].length < oid_el[17] || uip_ds6_routing_table[i].length > uip_ds6_routing_table[routeid].length ) {
      i++;
      continue;
    }
    if( uip_ds6_routing_table[i].length > oid_el[17] && uip_ds6_routing_table[i].length < uip_ds6_routing_table[routeid].length ) {
      routeid=i;
      i++;
      continue;
    }
    if ( oid_el[18] > 2 || (oid_el[18] == 2 && (oid_el[19] != 0 || oid_el[20] != 0 )) || oid_el[21] > 2 ){
	  i++;
          continue;
    }
    for (j = 0; j < 16 ; j++){
      if(uip_ds6_routing_table[i].nexthop.u8[j] < oid_el[j+22] || uip_ds6_routing_table[i].nexthop.u8[j] > uip_ds6_routing_table[routeid].nexthop.u8[j] )
      {
        break;
      }
      if(uip_ds6_routing_table[i].nexthop.u8[j] > oid_el[j+22] && uip_ds6_routing_table[i].nexthop.u8[j] < uip_ds6_routing_table[routeid].nexthop.u8[j] )
      {
	routeid=i;
        break;
      }
    }
    i++;
  }
  
  
  PRINTF("FOUND ONE at %d of %d with length %d\n\n",routeid,UIP_DS6_ROUTE_NB,uip_ds6_routing_table[routeid].length);
  leng = 6;
  leng += ber_encoded_oid_item_length(uip_ds6_routing_table[routeid].length);
  for (j = 0; j < 16 ; j++){
    leng += ber_encoded_oid_item_length(uip_ds6_routing_table[routeid].nexthop.u8[j]);
    leng += ber_encoded_oid_item_length(uip_ds6_routing_table[routeid].ipaddr.u8[j]);
  }
      
  ret = oid_create();
  CHECK_PTR_U(ret);
  ret->len = leng;
  ret->ptr = malloc(leng);
  CHECK_PTR_U(ret->ptr);
  pos=0;
      
  pos = EncodeTableOID(ret->ptr, pos, oid_el1);
  if (pos == -1)
  {
    return 0;
  }
  pos = EncodeTableOID(ret->ptr, pos, 2);
  if (pos == -1)
  {
    return 0;
  }
      
  for (j = 0; j < 16 ; j++){
    pos = EncodeTableOID(ret->ptr, pos, uip_ds6_routing_table[routeid].ipaddr.u8[j]);
    if (pos == -1)
    {
      return 0;
    }
  }
  pos = EncodeTableOID(ret->ptr, pos, uip_ds6_routing_table[routeid].length);
  if (pos == -1)
  {
    return 0;
  }
  pos = EncodeTableOID(ret->ptr, pos, 2);
  if (pos == -1)
  {
    return 0;
  }
  pos = EncodeTableOID(ret->ptr, pos, 0);
  if (pos == -1)
  {
    return 0;
  }
  pos = EncodeTableOID(ret->ptr, pos, 0);
  if (pos == -1)
  {
    return 0;
  }
  pos = EncodeTableOID(ret->ptr, pos, 2);
  if (pos == -1)
  {
    return 0;
  }
  for (j = 0; j < 16 ; j++){
    pos = EncodeTableOID(ret->ptr, pos, uip_ds6_routing_table[routeid].nexthop.u8[j]);
    if (pos == -1)
    {
      return 0;
    }
  }
  
  return ret;
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
  rpl_dag_t *dag;
  
  i = ber_decode_oid_item(oid, len, &oid_el1);
  i = ber_decode_oid_item(oid + i, len - i, &oid_el2);
  
  if (len != 2) {
    return -1;
  }
  if (oid_el2 != RPL_OF.ocp)
  {
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

#define RPLOPCSize     1

ptr_t* getNextRplOCPEntry(mib_object_t* object, u8t* oid, u8t len)
{
  //u8t columnNumber = 1;
  ptr_t* ret = 0;
  u32t oid_el1, oid_el2;
  u8t i;
  i = ber_decode_oid_item(oid, len, &oid_el1);
  i = ber_decode_oid_item(oid + i, len - i, &oid_el2);
  
  if (oid_el1 < RPLOPCColumns[0] || (oid_el1 == RPLOPCColumns[0] && oid_el2 < RPL_OF.ocp)) {
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

#define rplRPLInstanceOCP 2
#define rplRPLInstanceDisMode 3
#define rplRPLInstanceDAOAcknowledgement 4
#define rplRPLInstanceModeOfOperation 5

s8t getRPLInstanceEntry(mib_object_t* object, u8t* oid, u8t len)
{
  u32t oid_el1, oid_el2;
  u8t i;
  //rpl_dag_t *dag;
  rpl_instance_t *instance;
  
  i = ber_decode_oid_item(oid, len, &oid_el1);
  i = ber_decode_oid_item(oid + i, len - i, &oid_el2);
  
  if (len != 2) {
    return -1;
  }
  
  //dag = rpl_get_dag(oid_el2);
  instance = rpl_get_instance(oid_el2);
  /*if(dag == NULL) {
    return -1;
  }
  */
  if(instance == NULL) {
    return -1;
  }

  switch (oid_el1) { 
  case rplRPLInstanceOCP:
    object->varbind.value_type = BER_TYPE_GAUGE;
    //object->varbind.value.i_value = dag->of->ocp;
    object->varbind.value.i_value = instance->of->ocp;
    break;
  case rplRPLInstanceDisMode:
    object->varbind.value_type = BER_TYPE_INTEGER;
#if RPL_DIS_SEND
    object->varbind.value.i_value = 2;
#else
    object->varbind.value.i_value = 1;
#endif
    break;
  case rplRPLInstanceDAOAcknowledgement:
    object->varbind.value_type = BER_TYPE_INTEGER;
    //if (dag->mop>0) {
    if (instance->mop > 0) {
      object->varbind.value.i_value = 1;
    } else {
      object->varbind.value.i_value = 0;
    }
    break;
  case rplRPLInstanceModeOfOperation:
    object->varbind.value_type = BER_TYPE_INTEGER;
    //object->varbind.value.i_value = dag->mop;
    object->varbind.value.i_value = instance->mop;
    break;
  default:
    return -1;
  }
  
  return 0;
}

#if RPL_SNMP_WRITE
#define SET_RPL_INSTANCE_ENTRY &setRPLInstanceEntry

s8t setRPLInstanceEntry(mib_object_t* object, u8t* oid, u8t len, varbind_value_t value)
{
  u32t oid_el1, oid_el2;
  u8t i;
  rpl_dag_t *dag;
  
  i = ber_decode_oid_item(oid, len, &oid_el1);
  i = ber_decode_oid_item(oid + i, len - i, &oid_el2);
  
  if (len != 2) {
    return -1;
  }
  
  dag = rpl_get_dag(oid_el2);
  if(dag == NULL) {
    return -1;
  }
  
  switch (oid_el1) {
    
    case rplRPLInstanceOCP:
      dag->of->ocp = value.i_value;
      break;
    case rplRPLInstanceModeOfOperation:
      dag->mop = value.i_value;
      break;
    default:
      return -1;
  }
  
  return 0;
}
#else
#define SET_RPL_INSTANCE_ENTRY 0
#endif

u8t RPLInstanceTableColumns[] = {rplRPLInstanceOCP, rplRPLInstanceDisMode, rplRPLInstanceDAOAcknowledgement, rplRPLInstanceModeOfOperation};

#define RPLInstanceTableSize     0

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
	ret->ptr[1] = 0;
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
 * Needs editing ones more then one instance is supported
 * 
 * rplDodagTable(5)
 * |
 * +-rplDodagEntry(1) [rplRPLInstanceID,rplDodagRoot]
 *   |
 *   +- --- InetAddressIPv6       rplDodagRoot(1)
 *   +- r-n RplDodagVersionNumber rplDodagVersion(2)
 *   +- r-n RplRank               rplDodagRank(3)
 *   +- r-n Enumeration           rplDodagState(4)
 *   +- r-n RplDAODelay           rplDodagDAODelay(5)
 *   +- r-n RplDodagPreference    rplDodagPreference(6)
 *   +- r-n RplMinHopRankIncrease rplDodagMinHopRankIncrease(7)
 *   +- r-n RplPathControlSize    rplDodagPathControlSize(8)
 */

static u8t ber_oid_ber_rpl_rplDODAGTabel [] PROGMEM         = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0xf2, 0x06, 0x01, 0x02, 0x01, 0x05, 0x01};
static ptr_t oid_ber_rpl_rplDODAGTabel PROGMEM              = {ber_oid_ber_rpl_rplDODAGTabel, 13}; 

#define rplDodagVersionOID 2
#define rplDodagRankOID 3
#define rplDodagStateOID 4
#define rplDodagDAODelayOID 5
#define rplDodagPreferenceOID 6
#define rplDodagMinHopRankIncreaseOID 7
#define rplDodagPathControlSizeOID 8

s8t getDODAGEntry(mib_object_t* object, u8t* oid, u8t len)
{
  u32t oid_el1, oid_el2, oid_el3;
  u8t i,j;
  u8t test;
  u8t myint;
  //rpl_dag_t *dag;
  rpl_instance_t *instance;

  if (len < 18 ) {
    return -1;
  }
  
  i = ber_decode_oid_item(oid, len, &oid_el1);
  i = i + ber_decode_oid_item(oid + i, len - i, &oid_el2);
  
  //dag = rpl_get_dag(oid_el2);
  instance = rpl_get_instance(oid_el2);
  /*if(dag == NULL) {
    return -1;
  }
  */

  if(instance == NULL) {
    return -1;
  }
  
  for (j = 0; j < 16 ; j++){
    i = i + ber_decode_oid_item(oid + i, len - i, &oid_el3);
    myint = *( u8t* )&oid_el3;
    if(myint!=dag->dag_id.u8[j]){
      return -1;
    }
  }
  
  
  switch (oid_el1) {
    case rplDodagVersionOID:
      object->varbind.value_type = BER_TYPE_GAUGE;
      object->varbind.value.i_value = dag->version;
      break;
    case rplDodagRankOID:
      object->varbind.value_type = BER_TYPE_GAUGE;
      object->varbind.value.i_value = dag->rank;
      break;
    case rplDodagStateOID:
      object->varbind.value_type = BER_TYPE_INTEGER;
      object->varbind.value.i_value = dag->grounded;
      break;
    case rplDodagDAODelayOID:
      object->varbind.value_type = BER_TYPE_GAUGE;
      object->varbind.value.i_value = dag->dio_next_delay;
      break;
    case rplDodagPreferenceOID:
      object->varbind.value_type = BER_TYPE_GAUGE;
      object->varbind.value.i_value = dag->preference;
      break;
    case rplDodagMinHopRankIncreaseOID:
      object->varbind.value_type = BER_TYPE_GAUGE;
      object->varbind.value.i_value = dag->min_hoprankinc;
      break;
    case rplDodagPathControlSizeOID:
      object->varbind.value_type = BER_TYPE_GAUGE;
      object->varbind.value.i_value = dag->min_hoprankinc;
      break;
    default:
      return -1;
  }
  
  return 0;
}

u8t DODAGTableColumns[] = { rplDodagVersionOID, rplDodagRankOID, rplDodagStateOID, rplDodagDAODelayOID, rplDodagPreferenceOID, rplDodagMinHopRankIncreaseOID, rplDodagPathControlSizeOID};

#define DODAGTableSize     RPLInstanceTableSize
ptr_t* getNextDODAGEntry(mib_object_t* object, u8t* oid, u8t len)
{
  u8t columnNumber = 7;
  u8t rowNumber = DODAGTableSize;
  ptr_t* ret = 0;
  u32t oid_el1, oid_el2;
  u32t oid_n1, oid_n2;
  u8t leng,pos;
  u8t i,j;
  rpl_dag_t *dag;
  
  i = ber_decode_oid_item(oid, len, &oid_el1);
  i = ber_decode_oid_item(oid + i, len - i, &oid_el2);
  for (i = 0; i < columnNumber; i++) {
    if (oid_el1 < DODAGTableColumns[i] || (oid_el1 == DODAGTableColumns[i] && oid_el2 < rowNumber)) {
      oid_n1 = DODAGTableColumns[i];
      if (oid_el1 < DODAGTableColumns[i]) {
	oid_n2 = 0;
      } else {
	oid_n2 = oid_el2 + 1;
      }
      dag = rpl_get_dag(oid_n2);
      if(dag == NULL) {
	return 0;
      }
      leng = ber_encoded_oid_item_length(oid_n1);
      leng += ber_encoded_oid_item_length(oid_n2);
      for (j = 0; j < 16 ; j++){
	leng += ber_encoded_oid_item_length(dag->dag_id.u8[j]);
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
	pos = EncodeTableOID(ret->ptr, pos, dag->dag_id.u8[j]);
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
 *  |  |
 *  |  +-rplDodagParentEntry(1) [rplRPLInstanceID,rplDodagRoot,
 *  |     |                      rplDodagParentID]
 *  |     |
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
  u8t test,myint;
  u8t searchid[16];
  rpl_dag_t *dag;
  rpl_parent_t *currentparent;
  if (len < 34) {
    return -1;
  }
  
  i = ber_decode_oid_item(oid, len, &oid_el1);
  i = i + ber_decode_oid_item(oid + i, len - i, &oid_el2);
  dag = rpl_get_dag(oid_el2);
  
  
  if(dag == NULL) {
    return -1;
  }
  
  for (j = 0; j < 16 ; j++){
    i = i + ber_decode_oid_item(oid + i, len - i, &oid_el3);
    myint = *( u16t* )&oid_el3;
    if(myint!=dag->dag_id.u8[j]){
      return -1;
    }
  }
  
  currentparent=list_head(dag->parents);
  
  for (j = 0; j < 16 ; j++){
    i = i + ber_decode_oid_item(oid + i, len - i, &oid_el3);
    searchid[j] = *( u8t* )&oid_el3;
  }
 
  for (j = 0; j < 16 ; j++){
    if(searchid[j]!=currentparent->addr.u8[j]){
      if (currentparent->next == NULL) {
	return -1;
      } else {
	currentparent = currentparent->next;
	j=0;
      }
    }
  }
  
  switch (oid_el1) {
    case rplDodagParentIf:
      object->varbind.value_type = BER_TYPE_INTEGER;
      object->varbind.value.i_value = 259;
      break;
    default:
      return -1;
  }
  
  return 0;
}

u8t RPLParentTableColumns[] = {rplDodagParentIf};

ptr_t* getNextRPLParentEntry(mib_object_t* object, u8t* oid, u8t len)
{
  u8t columnNumber = 1;
  u8t rowNumber = DODAGTableSize;
  ptr_t* ret = 0;
  u32t oid_el1, oid_el2, oid_el3;
  u32t oid_n1, oid_n2;
  u32t leng,pos;
  u8t i,j,myint,searchid[16];
  rpl_dag_t *dag;
  rpl_parent_t *currentparent = NULL;
  
  if (len < 1){
    oid_el1=rplDodagParentIf;
    oid_el2=0;
  }else if (len < 2){
    i = ber_decode_oid_item(oid, len, &oid_el1);
    oid_el2=0;
  }else{
    i = ber_decode_oid_item(oid, len, &oid_el1);
    i += ber_decode_oid_item(oid + i, len - i, &oid_el2);
  }
  
  if(oid_el1>rplDodagParentIf){
    return 0;
  }
  if(oid_el1<rplDodagParentIf){
    oid_el1=rplDodagParentIf;
  }
  
  if ( len < 34) {
    dag = rpl_get_dag(oid_el2);
    if(dag==NULL){
      return 0;
    }
      
    currentparent=list_head(dag->parents);
    if(currentparent==NULL){
      return 0;
    }
    oid_n1=rplDodagParentIf;
    oid_n2=0;
    
  } else {
    for (j = 0; j < 16 ; j++){
      i = i + ber_decode_oid_item(oid + i, len - i, &oid_el3);
    }
    for (j = 0; j < 16 ; j++){
      i = i + ber_decode_oid_item(oid + i, len - i, &oid_el3);
      searchid[j] = *( u8t* )&oid_el3;
    }
    
    dag = rpl_get_dag(oid_el2);
    if(dag==NULL){
      return 0;
    }
    currentparent=list_head(dag->parents);
    if(currentparent==NULL){
      return 0;
    }
    for (j=0;j<16;j++)
    {
      if (searchid[j] < currentparent->addr.u8[j])
      {
        oid_n1=rplDodagParentIf;
        oid_n2=0;
        break;
      } else if (searchid[j] > currentparent->addr.u8[j] || j==15 ){
        if (currentparent->next != NULL) {
          currentparent = currentparent->next;
          j=0;
	} else {
	  //oid_el2++;
	  return 0;
	}
      }
    }
  }


  leng = ber_encoded_oid_item_length(oid_n1);
  leng += ber_encoded_oid_item_length(oid_n2);
  for (j = 0; j < 16 ; j++){
    leng += ber_encoded_oid_item_length(dag->dag_id.u8[j]);
  }
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
    pos = EncodeTableOID(ret->ptr, pos, dag->dag_id.u8[j]);
    if (pos == -1)
    {
      return 0;
    }
  }
  for (j = 0; j < 16 ; j++){
    pos = EncodeTableOID(ret->ptr, pos, currentparent->addr.u8[j]);
    if (pos == -1)
    {
      return 0;
    }
  }
  
  return ret;
}


/*-----------------------------------------------------------------------------------*/
/* The RPL Dodag Prefix TABLE.
 * Needs editing ones more then one instance or prefix is supported
 * 
 *  +-rplDodagPrefixTable(8)
 *  |
 *  +-rplDodagPrefixEntry(1) [rplRPLInstanceID,rplDodagRoot,
 *     |                      rplDodagPrefixIpv6Prefix,
 *     |                      rplDodagPrefixIpv6PrefixLength]
 *     |
 *     +- r-n InetAddressIPv6         rplDodagPrefixIpv6Prefix(1)
 *     +- r-n InetAddressPrefixLength rplDodagPrefixIpv6PrefixLength(2)
 */

static u8t ber_oid_ber_rpl_RPLPrefixTabel [] PROGMEM         = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0xf2, 0x06, 0x01, 0x02, 0x01, 0x08, 0x01};
static ptr_t oid_ber_rpl_RPLPrefixTabel PROGMEM              = {ber_oid_ber_rpl_RPLPrefixTabel, 13}; 

#define rplDodagPrefixIpv6Prefix 1
#define rplDodagPrefixIpv6PrefixLength 2

s8t getRPLPrefixEntry(mib_object_t* object, u8t* oid, u8t len)
{
  u32t oid_el1, oid_el2, oid_el3;
  u8t i=0,j;
  u8t test;
  u16t myint;
  rpl_dag_t *dag;
  if (len < 34) {
    PRINTF("length: %d\n",len);
    return -1;
  }
  
  i = ber_decode_oid_item(oid, len, &oid_el1);
  i = i + ber_decode_oid_item(oid + i, len - i, &oid_el2);
  dag = rpl_get_dag(oid_el2-1);
  
  
  if(dag == NULL) {
    return -1;
  }
  
  for (j = 0; j < 16 ; j++){
    i = i + ber_decode_oid_item(oid + i, len - i, &oid_el3);
    myint = *( u16t* )&oid_el3;
    if(myint!=dag->dag_id.u8[j]){
      return -1;
    }
  }

  for (j = 0; j < 16 ; j++){
    i = i + ber_decode_oid_item(oid + i, len - i, &oid_el3);
    myint = *( u8t* )&oid_el3;
    
    if(myint!=dag->prefix_info.prefix.u8[j]){
      PRINTF("ip: %d, oid: %d\n",dag->prefix_info.prefix.u8[j],myint);
      return -1;
    }
  }
  
  i = i + ber_decode_oid_item(oid + i, len - i, &oid_el3);
  myint = *( u8t* )&oid_el3;
  if(myint!=dag->prefix_info.length){
    PRINTF("ip: %d, oid: %d\n",dag->prefix_info.length,myint);
    return -1;
  }

  switch (oid_el1) {
    case rplDodagPrefixIpv6Prefix:
      object->varbind.value_type = BER_TYPE_OCTET_STRING;
      object->varbind.value.p_value.ptr = (u8t*)dag->prefix_info.prefix.u8;
      object->varbind.value.p_value.len = 16;
      break;
    case rplDodagPrefixIpv6PrefixLength:
      object->varbind.value_type = BER_TYPE_GAUGE;
      object->varbind.value.i_value = dag->prefix_info.length;
      break;
    default:
      return -1;
  }
  
  return 0;
}

u8t RPLPrefixTableColumns[] = {rplDodagPrefixIpv6Prefix,rplDodagPrefixIpv6PrefixLength };

ptr_t* getNextRPLPrefixEntry(mib_object_t* object, u8t* oid, u8t len)
{
  u8t columnNumber = 2;
  u8t rowNumber = DODAGTableSize;
  ptr_t* ret = 0;
  u32t oid_el1, oid_el2;
  u32t oid_n1, oid_n2;
  u8t leng,pos;
  u8t i,j;
  rpl_dag_t *dag;
  
  i = ber_decode_oid_item(oid, len, &oid_el1);
  i = ber_decode_oid_item(oid + i, len - i, &oid_el2);
  for (i = 0; i < columnNumber; i++) {
    if (oid_el1 < RPLPrefixTableColumns[i] || (oid_el1 == RPLPrefixTableColumns[i] && oid_el2 < rowNumber)) {
      oid_n1 = RPLPrefixTableColumns[i];
      if (oid_el1 < RPLPrefixTableColumns[i]) {
	oid_n2 = 0;
      } else {
	oid_n2 = oid_el2 + 1;
      }
      dag = rpl_get_dag(oid_n2);
      if(dag == NULL) {
	return 0;
      }
      leng = ber_encoded_oid_item_length(oid_n1);
      leng += ber_encoded_oid_item_length(oid_n2);
      for (j = 0; j < 16 ; j++){
	leng += ber_encoded_oid_item_length(dag->dag_id.u8[j]);
      }
      for (j = 0; j < 16 ; j++){
	leng += ber_encoded_oid_item_length(dag->prefix_info.prefix.u8[j]);
      }
      leng += ber_encoded_oid_item_length(dag->prefix_info.length);
      
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
	pos = EncodeTableOID(ret->ptr, pos, dag->dag_id.u8[j]);
        if (pos == -1)
        {
	  return 0;
        }
      }
      for (j = 0; j < 16 ; j++){
	pos = EncodeTableOID(ret->ptr, pos, dag->prefix_info.prefix.u8[j]);
        if (pos == -1)
        {
	  return 0;
        }
      }
      
      pos = EncodeTableOID(ret->ptr, pos, dag->prefix_info.length);
      if (pos == -1)
      {
	return 0;
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
  
  //route number
  if (add_scalar(&oid_ber_inetCidrRouteNumber, FLAG_ACCESS_READONLY, BER_TYPE_GAUGE, 0, &getinetCidrRouteNumber, 0) != ERR_NO_ERROR)
    {
      return -1;
    }
  
  //route table
  if (add_table(&oid_forwarding_table, &getRoutingTableEntry, &getNEXTRoutingTableEntry, 0) == -1) 
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
  if (add_table(&oid_ber_rpl_RPLInstanceTabel, &getRPLInstanceEntry, &getNextRPLInstanceEntry, SET_RPL_INSTANCE_ENTRY) == -1)
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
  if (add_table(&oid_ber_rpl_RPLPrefixTabel, &getRPLPrefixEntry, &getNextRPLPrefixEntry, 0) == -1) 
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
