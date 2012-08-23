/* Copyright 2011, 2012 SRI International
 * See LICENSE for other credits and copying information
 */

#include "util.h"
#include "chop_blk.h"
#include "crypt.h"

#include <event2/buffer.h>

/* The chopper is the core StegoTorus protocol implementation.
   For its design, see doc/chopper.txt.  Note that it is still
   being implemented, and may change incompatibly.  */

namespace chop_blk
{

const char *
opname(opcode_t o, char fallbackbuf[4])
{
  switch (o) {
  case op_DAT: return "DAT";
  case op_FIN: return "FIN";
  case op_RST: return "RST";
  case op_ACK: return "ACK";
  default: {
    unsigned int x = o;
    if (x < op_STEG0)
      xsnprintf(fallbackbuf, sizeof fallbackbuf, "R%02x", x);
    else
      xsnprintf(fallbackbuf, sizeof fallbackbuf, "S%02x", x - op_STEG0);
    return fallbackbuf;
  }
  }
}

header::header(uint32_t s, uint16_t d, uint16_t p, opcode_t f,
               ecb_encryptor &ec)
{
  if (f > op_LAST || (f >= op_RESERVED0 && f < op_STEG0)) {
    memset(clear, 0xFF, sizeof clear); // invalid!
    memset(ciphr, 0xFF, sizeof ciphr);
    return;
  }

  // sequence number
  clear[0] = (s >> 24) & 0xFF;
  clear[1] = (s >> 16) & 0xFF;
  clear[2] = (s >>  8) & 0xFF;
  clear[3] = (s      ) & 0xFF;

  // D field
  clear[4] = (d >>  8) & 0xFF;
  clear[5] = (d      ) & 0xFF;

  // P field
  clear[6] = (p >>  8) & 0xFF;
  clear[7] = (p      ) & 0xFF;

  // F field
  clear[8] = uint8_t(f);

  // Check field
  memset(clear + 9, 0, 7);

  ec.encrypt(ciphr, clear);
}

header::header(evbuffer *buf, ecb_decryptor &dc)
{
  if (evbuffer_copyout(buf, ciphr, sizeof ciphr) != sizeof ciphr) {
    memset(clear, 0xFF, sizeof clear);
    memset(ciphr, 0xFF, sizeof ciphr);
    return;
  }
  dc.decrypt(clear, ciphr);
}

ack_payload::ack_payload(evbuffer *wire, uint32_t hfloor)
  : hsn_(-1), maxusedbyte(0)
{
  memset(window, 0, sizeof window);

  uint8_t hsnwire[4];
  if (evbuffer_remove(wire, hsnwire, 4) != 4) {
    // invalid payload
    return;
  }
  hsn_ = (uint32_t(hsnwire[0]) << 24 |
          uint32_t(hsnwire[1]) << 16 |
          uint32_t(hsnwire[2]) <<  8 |
          uint32_t(hsnwire[3]));

  maxusedbyte = evbuffer_remove(wire, window, sizeof window);

  // there shouldn't be any _more_ data than that, and the hsn should
  // be in the range [hfloor, hfloor+256).
  if (evbuffer_get_length(wire) > 0 ||
      hsn_ < hfloor || hsn_ >= hfloor+256)
    hsn_ = -1; // invalidate
}

evbuffer *
ack_payload::serialize() const
{
  log_assert(valid());
  evbuffer *wire = evbuffer_new();
  evbuffer_iovec v;
  if (evbuffer_reserve_space(wire, 4 + maxusedbyte, &v, 1) != 1 ||
      v.iov_len < 4 + maxusedbyte) {
    evbuffer_free(wire);
    return 0;
  }

  uint8_t *p = (uint8_t *)v.iov_base;
  p[0] = (hsn_ & 0xFF000000U) >> 24;
  p[1] = (hsn_ & 0x00FF0000U) >> 16;
  p[2] = (hsn_ & 0x0000FF00U) >>  8;
  p[3] = (hsn_ & 0x000000FFU);

  if (maxusedbyte > 0)
    memcpy(&p[4], window, maxusedbyte);

  v.iov_len = 4 + maxusedbyte;
  if (evbuffer_commit_space(wire, &v, 1)) {
    evbuffer_free(wire);
    return 0;
  }
  return wire;
}

reassembly_queue::reassembly_queue()
  : next_to_process(0)
{
  memset(cbuf, 0, sizeof cbuf);
}

reassembly_queue::~reassembly_queue()
{
  for (int i = 0; i < 256; i++)
    if (cbuf[i].data)
      evbuffer_free(cbuf[i].data);
}

reassembly_elt
reassembly_queue::remove_next()
{
  reassembly_elt rv = { 0, op_DAT };
  uint8_t front = next_to_process & 0xFF;
  char fallbackbuf[4];

  log_debug("next_to_process=%d data=%p op=%s",
            next_to_process, cbuf[front].data,
            opname(cbuf[front].op, fallbackbuf));

  if (cbuf[front].data) {
    rv = cbuf[front];
    cbuf[front].data = 0;
    cbuf[front].op   = op_DAT;
    next_to_process++;
  }
  return rv;
}

bool
reassembly_queue::insert(uint32_t seqno, opcode_t op,
                         evbuffer *data, conn_t *conn)
{
  if (seqno - window() > 255) {
    log_info(conn, "block outside receive window");
    evbuffer_free(data);
    return false;
  }
  uint8_t front = next_to_process & 0xFF;
  uint8_t pos = front + (seqno - window());
  if (cbuf[pos].data) {
    log_info(conn, "duplicate block");
    evbuffer_free(data);
    return false;
  }

  cbuf[pos].data = data;
  cbuf[pos].op   = op;
  return true;
}

void
reassembly_queue::reset()
{
  for (int i = 0; i < 256; i++) {
    log_assert(!cbuf[i].data);
  }
  next_to_process = 0;
}

evbuffer *
reassembly_queue::gen_ack() const
{
  ack_payload payload(next_to_process - 1);
  uint8_t front = next_to_process & 0xFF;
  uint8_t pos = front;
  do {
    if (cbuf[pos].data)
      payload.set_block_received((next_to_process - 1) + (pos - front));
    pos++;
  } while (pos != front);

  return payload.serialize();
}

} // namespace chop_blk

// Local Variables:
// mode: c++
// c-basic-offset: 2
// c-file-style: "gnu"
// c-file-offsets: ((innamespace . 0) (brace-list-open . 0))
// End:
