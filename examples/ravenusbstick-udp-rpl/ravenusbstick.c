/*
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
 */

#include "contiki.h"
#include "contiki-lib.h"
#include "contiki-net.h"
#include "net/uip.h"
#include "net/rpl/rpl.h"

#include "net/netstack.h"
#include "dev/button-sensor.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define DEBUG DEBUG_NONE
#include "net/uip-debug.h"

#define UIP_IP_BUF   ((struct uip_ip_hdr *)&uip_buf[UIP_LLH_LEN])

#define UDP_CLIENT_PORT	8765
#define UDP_SERVER_PORT	5678

#define UDP_EXAMPLE_ID  190

static struct uip_udp_conn *server_conn;

PROCESS(udp_server_process, "UDP server process");
AUTOSTART_PROCESSES(&udp_server_process);
/*---------------------------------------------------------------------------*/

static void
tcpip_handler(void)
{
  char *appdata;
  char reply[250];
  char *replyp;
  replyp=reply;
  uip_ipaddr_t *ipaddrp;
  //extern uip_ds6_nbr_t uip_ds6_nbr_cache[];
  extern uip_ds6_route_t uip_ds6_routing_table[];
  //extern uip_ds6_netif_t uip_ds6_if;



  if(uip_newdata()) {
    
	uint8_t i,j;
	/*The routing table*/
	sprintf(replyp, "#Routes");
	replyp=reply+strlen(reply);
	uip_ipaddr_copy(&server_conn->ripaddr, &UIP_IP_BUF->srcipaddr);
  
	for(i = 0,j=1; i < UIP_DS6_ROUTE_NB; i++) {
		
		if(uip_ds6_routing_table[i].isused) {
			sprintf(replyp, "#");
			replyp=reply+strlen(reply);
			ipaddrp=&uip_ds6_routing_table[i].ipaddr;
			uint16_t a;
			int8_t p, f;
			for(p = 0, f = 0; p < sizeof(uip_ipaddr_t); p += 2) {
				a = (ipaddrp->u8[p] << 8) + ipaddrp->u8[p + 1];
				if(a == 0 && f >= 0) {
					if(f++ == 0) sprintf(replyp, "::");
					replyp=reply+strlen(reply);
				} 
				else {
					if(f > 0) {
						f = -1;
					} 
					else if(p > 0) {
						sprintf(replyp, ":");
						replyp=reply+strlen(reply);
					}
					sprintf(replyp, "%x",a);
					replyp=reply+strlen(reply);
				}
			}
		
			sprintf(replyp, "#");
			replyp=reply+strlen(reply);
			ipaddrp=&uip_ds6_routing_table[i].nexthop;
			uint16_t b;
			for(p = 0, f = 0; p < sizeof(uip_ipaddr_t); p += 2) {
				b = (ipaddrp->u8[p] << 8) + ipaddrp->u8[p + 1];
				if(b == 0 && f >= 0) {
					if(f++ == 0) sprintf(replyp, "::");
					replyp=reply+strlen(reply);
				} 
				else {
					if(f > 0) {
						f = -1;
					} 
					else if(p > 0) {
						sprintf(replyp, ":");
						replyp=reply+strlen(reply);
					}
					sprintf(replyp, "%x",b);
					replyp=reply+strlen(reply);
				}
			}
			j=0;
			sprintf(replyp, "##");
			replyp=reply+strlen(reply);
			*replyp='\0';
			//uip_ipaddr_copy(&server_conn->ripaddr, &UIP_IP_BUF->srcipaddr);
			uip_udp_packet_send(server_conn, reply, strlen(reply));
			//memset(&server_conn->ripaddr, 0, sizeof(server_conn->ripaddr));
			/*set pointer to beginning*/
			replyp=reply;
		}
		
	}
	if (j){
		sprintf(replyp, "#0#");
		replyp=reply+strlen(reply);
		*replyp='\0';
		//uip_ipaddr_copy(&server_conn->ripaddr, &UIP_IP_BUF->srcipaddr);
		uip_udp_packet_send(server_conn, reply, strlen(reply));
		//memset(&server_conn->ripaddr, 0, sizeof(server_conn->ripaddr));
		replyp=reply;
	}
	//*replyp='\0';
    //uip_ipaddr_copy(&server_conn->ripaddr, &UIP_IP_BUF->srcipaddr);
    uip_udp_packet_send(server_conn, "#LASTPACKET#", strlen("#LASTPACKET#"));
    memset(&server_conn->ripaddr, 0, sizeof(server_conn->ripaddr));
    //server_conn->rport=0;
  }
}
/*---------------------------------------------------------------------------*/

/*---------------------------------------------------------------------------*/


PROCESS_THREAD(udp_server_process, ev, data)
{
  uip_ipaddr_t ipaddr;
  struct uip_ds6_addr *root_if;

  PROCESS_BEGIN();

  PRINTF("UDP SERVER LAEUFT!!!!!!\n");
  server_conn = udp_new(NULL, UIP_HTONS(UDP_CLIENT_PORT), NULL);
  if(server_conn == NULL) {
    PRINTF("No UDP connection available, exiting the process!\n");
    PROCESS_EXIT();
  }
  udp_bind(server_conn, UIP_HTONS(UDP_SERVER_PORT));

  PRINTF("Created a server connection with remote address ");
  PRINT6ADDR(&server_conn->ripaddr);
  PRINTF(" local/remote port %u/%u\n", UIP_HTONS(server_conn->lport),
         UIP_HTONS(server_conn->rport));

  while(1) {
    PROCESS_YIELD();
    if(ev == tcpip_event) {
      tcpip_handler();
    } 
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
