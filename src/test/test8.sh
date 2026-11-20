#!/bin/sh -xe

# Local DNS-over-HTTPS end-to-end tests.
#
# Unlike test5.sh these do not rely on any external helper daemon: a small
# HTTP/2 DoH server implemented in Python (doh_server.py, needs the h2
# module) is started on the loopback interface and dnsperf is run against
# it over GET and POST, with multiple threads and concurrent streams.

python3 -c 'import h2' 2>/dev/null || exit 77
command -v openssl >/dev/null 2>&1 || exit 77

# Use an uncommon high port: common HTTPS ports can be intercepted by
# transparent proxies in sandboxed CI environments.
PORT=18080
URI="https://127.0.0.1:${PORT}/dns-query"

rm -f test8.key test8.cert test8.out test8.err
trap 'kill "$srvpid" 2>/dev/null || true' EXIT

openssl req -x509 -newkey rsa:2048 -keyout test8.key -out test8.cert \
  -days 365 -nodes -subj "/CN=localhost" 2>/dev/null

python3 "$srcdir/doh_server.py" 127.0.0.1 "$PORT" test8.key test8.cert \
  2>test8.err &
srvpid=$!

# Wait for the server to start accepting connections.
i=0
while [ "$i" -lt 50 ]; do
    if python3 - "$PORT" <<'PY' 2>/dev/null
import socket, sys
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=1)
s.close()
PY
    then
        break
    fi
    i=$((i + 1))
    sleep 0.1
done
[ "$i" -lt 50 ] || { cat test8.err; exit 1; }

# Basic GET and POST: every query must complete with HTTP code 200.
for method in GET POST; do
    ../dnsperf -s 127.0.0.1 -p "$PORT" -m doh -O doh-uri="$URI" \
      -O doh-method="$method" -d "$srcdir/datafile" -n 1 -t 5 \
      >test8.out 2>&1
    grep -q "Queries sent:         2$" test8.out
    grep -q "Queries completed:    2 (100.00%)" test8.out
    grep -q "Queries lost:         0 (0.00%)" test8.out
    grep -q "DNS-over-HTTPS statistics:" test8.out
    grep -q "HTTP/2 return codes:  200: 2" test8.out
done

# Concurrency: repeated file, multiple sender threads and many concurrent
# HTTP/2 streams, all queries must still be answered exactly once.
yes "test.example A" | head -500 > test8.queries
../dnsperf -s 127.0.0.1 -p "$PORT" -m doh -O doh-uri="$URI" \
  -d test8.queries -T 4 -Q 1000 -t 10 >test8.out 2>&1
grep -q "Queries sent:         500$" test8.out
grep -q "Queries completed:    500 (100.00%)" test8.out
grep -q "Queries lost:         0 (0.00%)" test8.out
grep -q "HTTP/2 return codes:  200: 500" test8.out

# Error paths exercise the DoH HTTP status and content-type statistics.
../dnsperf -s 127.0.0.1 -p "$PORT" -m doh \
  -O doh-uri="https://127.0.0.1:${PORT}/http-error" \
  -d "$srcdir/datafile" -n 1 -t 3 >test8.out 2>&1
grep -q "Queries lost:         2 (100.00%)" test8.out
grep -q "HTTP/2 return codes:  500: 2" test8.out

../dnsperf -s 127.0.0.1 -p "$PORT" -m doh \
  -O doh-uri="https://127.0.0.1:${PORT}/not-dns" \
  -d "$srcdir/datafile" -n 1 -t 3 >test8.out 2>&1
grep -q "Queries lost:         2 (100.00%)" test8.out
grep -q "HTTP/2 return codes:  200: 2" test8.out
grep -q "Non-DNS responses:    2$" test8.out

kill "$srvpid"
wait "$srvpid" 2>/dev/null || true
srvpid=""
