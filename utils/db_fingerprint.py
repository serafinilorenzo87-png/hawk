"""Active DB fingerprinting helper for HAWK STEP 4 / Fase 2.

Walks a list of (host, port) pairs and tries to identify each as
one of the 9 supported DB protocols.  HTTP-based DBs (Elasticsearch,
CouchDB, InfluxDB, ClickHouse, ArangoDB) are probed with a minimal
HTTP/1.1 GET; binary-protocol DBs (Redis, Memcached, MongoDB,
Cassandra) are probed with their wire-protocol magic.

Output (one machine-readable line per identification):
    [HAWK_DB port=NNN svc=KEY version=X.Y confidence=high|medium|low]

Plus diagnostic lines (one per tool run):
    [HAWK_DB_DIAG: scanning N ports on HOST]
    [HAWK_DB_DIAG: port=NNN error: <details>]
    [HAWK_DB_DIAG: done]

The parser in card_parsers_service.py converts the HAWK_DB lines
into fp.open_ports upgrades and Target Intel findings.

Confidence semantics:
  high   – protocol-specific magic confirmed + version extracted
           (or auth-required hint that uniquely identifies the proto)
  medium – server identity confirmed without version
  low    – weak heuristic (banner contains the keyword but no
           protocol-level confirmation)

Usage:
    python3 db_fingerprint.py HOST PORT1 [PORT2 PORT3 ...]
    python3 db_fingerprint.py HOST PORT1,PORT2,PORT3

Exit code: always 0.  No exceptions propagate to the shell — every
network/socket error becomes a [HAWK_DB_DIAG: ... error: ...] line.
"""
import re
import socket
import sys


# ════════════════════════════════════════════════════════════════════════
# Low-level helpers
# ════════════════════════════════════════════════════════════════════════
def _http_get(host, port, path="/", timeout=3, recv_size=8192):
    """Send a minimal HTTP/1.1 GET and return ``(status, headers, body)``.

    ``headers`` is a dict with lowercase keys.  ``body`` is decoded
    via latin-1 (replace on errors) — banners are 8-bit clean and
    we never want to crash on weird bytes.  Returns ``None`` on any
    network error / non-HTTP response.
    """
    s = None
    try:
        s = socket.socket()
        s.settimeout(timeout)
        s.connect((host, port))
        req = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            f"User-Agent: HAWK-db-fingerprint/1.0\r\n"
            f"Connection: close\r\n"
            f"Accept: */*\r\n\r\n"
        ).encode("ascii", "replace")
        s.sendall(req)
        data = b""
        while True:
            try:
                chunk = s.recv(recv_size)
            except socket.timeout:
                break
            if not chunk:
                break
            data += chunk
            if len(data) > 64 * 1024:
                break
    except OSError:
        return None
    finally:
        try:
            if s is not None:
                s.close()
        except Exception:
            pass

    if not data:
        return None
    # Split head/body.
    try:
        header_end = data.index(b"\r\n\r\n")
        head = data[:header_end].decode("latin-1", "replace")
        body = data[header_end + 4:].decode("latin-1", "replace")
    except ValueError:
        head = data.decode("latin-1", "replace")
        body = ""
    lines = head.split("\r\n")
    status = ""
    if lines and lines[0].startswith("HTTP/"):
        parts = lines[0].split(" ", 2)
        if len(parts) >= 2:
            status = parts[1]
    headers = {}
    for ln in lines[1:]:
        if ":" in ln:
            k, v = ln.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    return status, headers, body


def _tcp_send_recv(host, port, payload, timeout=3, recv_size=4096):
    """Open TCP, send ``payload`` (or none), read up to ``recv_size``
    bytes, return the response or ``None`` on error.
    """
    s = None
    try:
        s = socket.socket()
        s.settimeout(timeout)
        s.connect((host, port))
        if payload:
            s.sendall(payload)
        try:
            data = s.recv(recv_size)
        except socket.timeout:
            data = b""
        return data
    except OSError:
        return None
    finally:
        try:
            if s is not None:
                s.close()
        except Exception:
            pass


# ════════════════════════════════════════════════════════════════════════
# HTTP-API DB probes
# ════════════════════════════════════════════════════════════════════════
def probe_elasticsearch(host, port):
    """Identify Elasticsearch via GET /.

    Vanilla ES response:
      {"name":"node","cluster_name":"docker-cluster",
       "version":{"number":"7.10.0", ...}, ...}
    Returns (svc, version, confidence) or None.
    """
    r = _http_get(host, port, "/")
    if not r:
        return None
    _status, headers, body = r
    if "cluster_name" in body and "version" in body:
        m = re.search(r'"number"\s*:\s*"([^"]+)"', body)
        ver = m.group(1) if m else ""
        return ("elasticsearch", ver, "high")
    # Weaker signals.
    if (headers.get("x-elastic-product", "").lower()
            == "elasticsearch"):
        return ("elasticsearch", "", "medium")
    if "elasticsearch" in body.lower() and "cluster" in body.lower():
        return ("elasticsearch", "", "low")
    return None


def probe_couchdb(host, port):
    """Identify CouchDB via GET /.

    1.x: {"couchdb":"Welcome","version":"1.6.1",...}
    2.x+: {"couchdb":"Welcome","version":"3.3.2","git_sha":"...",
          "uuid":"...","features":[...]}
    """
    r = _http_get(host, port, "/")
    if not r:
        return None
    _status, headers, body = r
    if '"couchdb"' in body and '"Welcome"' in body:
        m = re.search(r'"version"\s*:\s*"([^"]+)"', body)
        ver = m.group(1) if m else ""
        return ("couchdb", ver, "high")
    if headers.get("server", "").lower().startswith("couchdb"):
        return ("couchdb", "", "medium")
    return None


def probe_influxdb(host, port):
    """Identify InfluxDB via GET /ping (works on both v1 and v2).

    v1 sets header `X-Influxdb-Version: <ver>` and returns 204.
    v2 returns JSON {"name":"influxdb","version":"..."} on /health.
    """
    r = _http_get(host, port, "/ping")
    if r:
        _status, headers, _body = r
        if "x-influxdb-version" in headers:
            return ("influxdb", headers["x-influxdb-version"], "high")
        if "x-influxdb-build" in headers:
            return ("influxdb",
                    headers.get("x-influxdb-version", ""), "high")
    # InfluxDB 2.x v2 fallback.
    r = _http_get(host, port, "/health")
    if r:
        _status, _headers, body = r
        if '"name":"influxdb"' in body or '"name": "influxdb"' in body:
            m = re.search(r'"version"\s*:\s*"([^"]+)"', body)
            ver = m.group(1) if m else ""
            return ("influxdb", ver, "high")
    return None


def probe_clickhouse(host, port):
    """Identify ClickHouse via GET /?query=SELECT+version().

    Sets header `X-ClickHouse-Server-Display-Name` on every response.
    Body of the version() query is a single line with the version.
    """
    r = _http_get(host, port, "/?query=SELECT+version()")
    if not r:
        # /ping is also distinctive — returns "Ok.\n"
        r = _http_get(host, port, "/ping")
        if not r:
            return None
        _status, headers, body = r
        if "x-clickhouse-server-display-name" in headers:
            return ("clickhouse", "", "medium")
        if body.strip() == "Ok." and "x-clickhouse" in " ".join(
                headers.keys()).lower():
            return ("clickhouse", "", "medium")
        return None
    _status, headers, body = r
    if "x-clickhouse-server-display-name" in headers:
        ver = body.strip().split("\n", 1)[0].strip()
        return ("clickhouse", ver, "high")
    if "clickhouse" in headers.get("server", "").lower():
        return ("clickhouse", "", "medium")
    return None


def probe_arangodb(host, port):
    """Identify ArangoDB via GET /_api/version.

    Returns JSON: {"server":"arango","version":"3.11.6","license":...}
    """
    r = _http_get(host, port, "/_api/version")
    if not r:
        return None
    _status, headers, body = r
    if '"server"' in body and "arango" in body.lower():
        m = re.search(r'"version"\s*:\s*"([^"]+)"', body)
        ver = m.group(1) if m else ""
        return ("arangodb", ver, "high")
    if "arangodb" in headers.get("server", "").lower():
        return ("arangodb", "", "medium")
    return None


# ════════════════════════════════════════════════════════════════════════
# Binary-protocol DB probes
# ════════════════════════════════════════════════════════════════════════
def probe_redis(host, port):
    """Identify Redis via the RESP PING command.

    Response on auth-less server: +PONG\\r\\n
    Response on auth-required:   -NOAUTH Authentication required.\\r\\n
    Both are uniquely Redis.
    """
    # Inline PING command (server interprets the simple form too).
    data = _tcp_send_recv(host, port, b"*1\r\n$4\r\nPING\r\n", timeout=2)
    if data is None or not data:
        return None
    if data.startswith(b"+PONG"):
        info = _tcp_send_recv(host, port, b"*1\r\n$4\r\nINFO\r\n",
                              timeout=2, recv_size=4096)
        ver = ""
        if info:
            m = re.search(rb"redis_version:([^\r\n]+)", info)
            if m:
                ver = m.group(1).decode("latin-1", "replace").strip()
        return ("redis", ver, "high")
    if b"NOAUTH" in data or b"WRONGTYPE" in data \
            or data.startswith(b"-ERR"):
        return ("redis", "", "high")
    return None


def _classify_memcached(data):
    """Classify a memcached `version\\r\\n` reply → (svc, ver, conf) | None."""
    if not data:
        return None
    if data.startswith(b"VERSION "):
        ver = data[8:].decode("latin-1", "replace").strip()
        # Trim any trailing \r/\n
        ver = ver.split("\r", 1)[0].split("\n", 1)[0]
        return ("memcached", ver, "high")
    # memcached's unknown-verb reply is EXACTLY "ERROR\r\n".  Match only
    # that — an IRC server (UnrealIRCd on 6667/6697) answering our junk
    # line with "ERROR :Closing Link: ... (Throttled: ...)" ALSO starts
    # with "ERROR", and the old startswith() check re-classified those
    # IRC ports as memcached, overwriting nmap's correct 'irc' label.
    if data.split(b"\n", 1)[0].strip() == b"ERROR":
        return ("memcached", "", "medium")
    return None


def probe_memcached(host, port):
    """Identify Memcached via the `version\\r\\n` text-protocol command.

    Response: VERSION 1.6.21\\r\\n  (always — protocol-mandatory).
    memcached's unknown-verb reply is exactly `ERROR\\r\\n`.
    """
    data = _tcp_send_recv(host, port, b"version\r\n", timeout=2)
    if data is None or not data:
        return None
    return _classify_memcached(data)


def probe_mongodb(host, port):
    """Identify MongoDB via legacy OP_QUERY isMaster.

    OP_QUERY (opcode 2004) is deprecated in 5.1+ but every server
    >= 2.6 still handles it for back-compat.  We send a minimal
    BSON document {"isMaster": 1} on the admin.$cmd collection.
    """
    bson = bytes([
        0x13, 0x00, 0x00, 0x00,                  # doc len 19
        0x10,                                     # int32 type
        0x69, 0x73, 0x4D, 0x61, 0x73, 0x74,       # "isMaste"
        0x65, 0x72, 0x00,                         # "r\0"
        0x01, 0x00, 0x00, 0x00,                   # value 1
        0x00,                                     # end of doc
    ])
    full_coll = b"admin.$cmd\x00"
    body = (b"\x00\x00\x00\x00"               # flags
            + full_coll
            + b"\x00\x00\x00\x00"             # numberToSkip
            + b"\x01\x00\x00\x00"             # numberToReturn
            + bson)
    msg_len = 16 + len(body)
    header = (msg_len.to_bytes(4, "little")
              + b"\x01\x00\x00\x00"            # requestID
              + b"\x00\x00\x00\x00"            # responseTo
              + b"\xd4\x07\x00\x00")           # opCode 2004 OP_QUERY
    data = _tcp_send_recv(host, port, header + body, timeout=3,
                           recv_size=4096)
    if data is None or len(data) < 20:
        return None
    body = data[20:]   # past OP_REPLY headers
    if (b"ismaster" in body or b"maxBsonObjectSize" in body
            or b"hosts" in body):
        ver = ""
        m = re.search(rb"version\x00[^\x00]*?([0-9]+\.[0-9]+\.[0-9]+)",
                       body)
        if m:
            ver = m.group(1).decode("latin-1", "replace")
        return ("mongodb", ver, "high")
    return None


def probe_cassandra(host, port):
    """Identify Cassandra via the CQL Native Protocol OPTIONS frame.

    v3 OPTIONS frame:
      version(0x03) flags(0x00) stream(0x00 0x00) opcode(0x05)
      length(0x00 0x00 0x00 0x00)
    Response opcode is 0x06 SUPPORTED, body is a string multi-map
    containing keys like ``CQL_VERSION`` and ``COMPRESSION``.
    """
    payload = b"\x03\x00\x00\x00\x05\x00\x00\x00\x00"
    data = _tcp_send_recv(host, port, payload, timeout=3,
                           recv_size=4096)
    if data is None or len(data) < 9:
        return None
    # Header: version, flags, stream(2), opcode, length(4)
    if len(data) >= 5 and data[4] == 0x06:
        m = re.search(rb"CQL_VERSION.*?([0-9]+\.[0-9]+\.[0-9]+)",
                       data, re.DOTALL)
        ver = m.group(1).decode("latin-1", "replace") if m else ""
        return ("cassandra", ver, "high")
    # Some Cassandra servers reject v3 with an ERROR — still
    # distinctive (opcode 0x00 in response).
    if len(data) >= 5 and data[4] == 0x00:
        return ("cassandra", "", "medium")
    return None


# ════════════════════════════════════════════════════════════════════════
# Per-port dispatch
# ════════════════════════════════════════════════════════════════════════
PORT_HINTS = {
    # HTTP-API DBs
    9200: ["elasticsearch"], 9300: ["elasticsearch"],
    5984: ["couchdb"], 6984: ["couchdb"],
    8086: ["influxdb"],
    8123: ["clickhouse"],
    8529: ["arangodb"],
    # Binary DBs
    6379: ["redis"], 6380: ["redis"],
    11211: ["memcached"],
    27017: ["mongodb"], 27018: ["mongodb"], 27019: ["mongodb"],
    9042: ["cassandra"],
}

_PROBES = {
    "elasticsearch":   probe_elasticsearch,
    "couchdb":         probe_couchdb,
    "influxdb":        probe_influxdb,
    "clickhouse":      probe_clickhouse,
    "arangodb":        probe_arangodb,
    "redis":           probe_redis,
    "memcached":       probe_memcached,
    "mongodb":         probe_mongodb,
    "cassandra":       probe_cassandra,
}
_HTTP_PROBES = ["elasticsearch", "couchdb", "influxdb",
                "clickhouse", "arangodb"]
_BINARY_PROBES = ["redis", "memcached", "mongodb", "cassandra"]


def fingerprint_port(host, port):
    """Run probes for ``port`` in hint-ordered priority.

    Returns ``(svc_key, version, confidence)`` or ``None``.
    """
    hints = PORT_HINTS.get(port, [])
    tried = set()
    # 1) Port hint
    for name in hints:
        try:
            r = _PROBES[name](host, port)
        except Exception:
            r = None
        tried.add(name)
        if r:
            return r
    # 2) HTTP probes (cheap)
    for name in _HTTP_PROBES:
        if name in tried:
            continue
        try:
            r = _PROBES[name](host, port)
        except Exception:
            r = None
        tried.add(name)
        if r:
            return r
    # 3) Binary probes (expensive — separate TCP per probe)
    for name in _BINARY_PROBES:
        if name in tried:
            continue
        try:
            r = _PROBES[name](host, port)
        except Exception:
            r = None
        tried.add(name)
        if r:
            return r
    return None


# ════════════════════════════════════════════════════════════════════════
# CLI entry point
# ════════════════════════════════════════════════════════════════════════
def _parse_ports(argv_rest):
    """Accept ports as space-separated and/or comma-separated values."""
    out = []
    for arg in argv_rest:
        for p in arg.split(","):
            p = p.strip()
            if not p:
                continue
            try:
                n = int(p)
                if 1 <= n <= 65535:
                    out.append(n)
            except ValueError:
                continue
    # Dedup while preserving order
    seen = set()
    uniq = []
    for n in out:
        if n in seen:
            continue
        seen.add(n)
        uniq.append(n)
    return uniq


def main(argv):
    if len(argv) < 3:
        sys.stderr.write(
            "usage: db_fingerprint.py HOST PORT1[,PORT2,...] [PORT2 ...]"
            "\n")
        return 2
    host = argv[1]
    ports = _parse_ports(argv[2:])
    if not ports:
        sys.stderr.write("no valid ports given\n")
        return 2
    print(f"[HAWK_DB_DIAG: scanning {len(ports)} port(s) on {host}]")
    for port in ports:
        try:
            result = fingerprint_port(host, port)
        except Exception as e:
            print(f"[HAWK_DB_DIAG: port={port} error: {e}]")
            continue
        if result:
            svc, ver, conf = result
            print(f"[HAWK_DB port={port} svc={svc} "
                  f"version={ver or '?'} confidence={conf}]")
    print("[HAWK_DB_DIAG: done]")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
