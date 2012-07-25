/* Copyright 2011, 2012 SRI International
 * See LICENSE for other credits and copying information
 */

#ifndef _PAYLOADS_H
#define _PAYLOADS_H

/* three files:
   server_data, client data, protocol data
*/

/* this will be calledb by the constructor
void load_payloads(payloads& pl, const char* fname);
unsigned int find_client_payload(payloads& pl, char* buf, int len, int type);
/* Unused:
unsigned int find_server_payload(payloads& pl, char** buf, int len, int type,
int contentType);*/


/* never used */
/*int get_next_payload (payloads& pl, int contentType, char** buf, int* size,
  int* cap);*/
#endif
