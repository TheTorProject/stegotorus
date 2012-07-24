#! /bin/sh
# Copyright 2012 SRI International
# See LICENSE for other credits and copying information

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
  s/^src/steg\///
  s/\.o: */ /
  s/\.obj: */ /
  s/ [0-9a-fA-F][0-9a-fA-F]* [DBdb] / /

  # This is the whitelist, in the form of a bunch of sed "d" commands.
  # It cares about both the names and the object files that define
  # them.  The above commands have stripped any leading src/ and/or
  # .o or .obj extension.

  /^compression ZLIB_CEILING$/d
  /^compression ZLIB_UINT_MAX$/d
  /^connections cgs$/d
  /^crypt bctx$/d
  /^crypt crypto_initialized$/d
  /^crypt crypto_errs_initialized$/d
  /^main allow_kq$/d
  /^main daemon_mode$/d
  /^main handle_signal_cb(int, short, void\*)::got_sigint$/d
  /^main pidfile_name$/d
  /^main registration_helper$/d
  /^main the_event_base$/d
  /^network listeners$/d
  /^rng rng$/d
  /^subprocess-unix already_waited$/d
  /^util log_dest$/d
  /^util log_min_sev$/d
  /^util log_timestamps$/d
  /^util log_ts_base$/d
  /^util-net the_evdns_base$/d
  /^apache_payload_server std::__ioinit$/d
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
