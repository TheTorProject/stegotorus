/* Copyright 2011, 2012 SRI International
 * See LICENSE for other credits and copying information
 */

#include "util.h"
#include "chop_blk.h"

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
  case op_STEG0: return "STEG DAT";
  case op_STEG_FIN: return "STEG FIN";
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
  reassembly_elt rv = { 0, op_DAT, NULL };
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
  cbuf[pos].conn = conn;
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

} // namespace chop_blk

// Local Variables:
// mode: c++
// c-basic-offset: 2
// c-file-style: "gnu"
// c-file-offsets: ((innamespace . 0) (brace-list-open . 0))
// End:
