#ifndef STEGERRORS_H
#define STEGERRORS_H

typedef enum stego_codes { 
  RCODE_ERROR = -3,
  RCODE_OK,
  RCODE_FIELD_NOT_FOUND,
} rcode_t;


typedef enum recv_codes { 
  RECV_BAD,
  RECV_GOOD,
  RECV_INCOMPLETE,
} recv_t;

typedef enum transmit_codes {
  NOT_TRANSMITTED,
  TRANSMIT_GOOD,
} transmit_t;


#endif
