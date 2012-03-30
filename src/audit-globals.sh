#! /bin/sh

# Due to the multi-listener architecture of stegotorus, nearly all
# global variables are bugs.  This program enforces a white-list of
# global variables (in stegotorus itself) that are known to be okay.
# It's called from the Makefile with all of stegotorus's object files
# on the command line.  It produces no output, and exits successfully,
# if no new globals have appeared; otherwise it prints error messages
# and exits unsuccessfully.

status=0
symbols=$(nm -o "$@" |
c++filt |
sed '
  # Tidy up the list and remove all symbols we do not care about.
  / [DBdb] /!d

  s/^src\///
  s/\.o: */ /
  s/\.obj: */ /
  s/ [0-9a-fA-F][0-9a-fA-F]* [DBdb] / /

  # This is the whitelist, in the form of a bunch of sed "d" commands.
  # It cares about both the names and the object files that define
  # them.  The above commands have stripped any leading src/ and/or
  # .o or .obj extension.

  # These are genuinely OK.
  /^connections circuits$/d
  /^connections connections$/d
  /^connections closing_all_connections$/d
  /^connections last_ckt_serial$/d
  /^connections last_conn_serial$/d
  /^connections shutting_down$/d
  /^main allow_kq$/d
  /^main the_event_base$/d
  /^main handle_signal_cb(int, short, void\*)::got_sigint$/d
  /^network listeners$/d
  /^rng rng$/d
  /^util log_dest$/d
  /^util log_min_sev$/d
  /^util log_timestamps$/d
  /^util log_ts_base$/d
  /^util the_evdns_base$/d
  /^crypt log_crypto()::initialized$/d
  /^crypt init_crypto()::initialized$/d

  # These are grandfathered; they need to be removed.
  /^steg\/payloads payload_count$/d
  /^steg\/payloads payload_hdrs$/d
  /^steg\/payloads payloads$/d
  /^steg\/payloads initTypePayload$/d
  /^steg\/payloads max_HTML_capacity$/d
  /^steg\/payloads max_JS_capacity$/d
  /^steg\/payloads max_PDF_capacity$/d
  /^steg\/payloads typePayload$/d
  /^steg\/payloads typePayloadCap$/d
  /^steg\/payloads typePayloadCount$/d
')

if [ -n "$symbols" ]; then
    status=1
    echo '*** New global variables introduced:'
    set fnord $symbols
    shift
    while [ $# -gt 0 ]; do
        printf '  %s.o\t%s\n' "$1" "$2"
        shift 2
    done
fi
exit $status
