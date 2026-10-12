#!/usr/bin/env python3
"""
fpstore — append-only client-observation store.

Replaces the SQLite database the fingerprint module used to keep. The
reason for the change is inspectability, not performance: a .db file is a
binary blob you cannot grep, eyeball or diff, and it is one more piece of
state that must never leave the machine. These files are the opposite of
that - `tail` shows you what is happening, and a tester can paste a line
into a bug report.

Layout, under the state directory:

    clients.json      current known-client state, one object
    observations.jsonl one sighting per line, append-only
    probed.jsonl      probe requests, append-only
    meta.json         schema version and counters

Append-only is what makes this viable. Rewriting a JSON array on every
sighting is O(n) per write and falls over at a few thousand rows; appending
a line is O(1) and does not care how large the file gets.

Not implemented, deliberately: efficient aggregation over millions of
rows. If that ever becomes the requirement, this is the wrong shape and
SQLite was the right answer. For assessment work it is not.
"""

import json
import os
import sys
import time

SCHEMA = 1
CLIENTS = "clients.json"
OBS = "observations.jsonl"
PROBED = "probed.jsonl"
META = "meta.json"


def _paths(state):
    return (os.path.join(state, CLIENTS),
            os.path.join(state, OBS),
            os.path.join(state, PROBED),
            os.path.join(state, META))


def cmd_init(state, *_):
    os.makedirs(state, exist_ok=True)
    clients, obs, probed, meta = _paths(state)
    for path, seed in ((clients, "{}"), (obs, ""), (probed, "")):
        if not os.path.exists(path):
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(seed)
    if not os.path.exists(meta):
        _write_json(meta, {"schema": SCHEMA, "created": int(time.time())})
    print("ok\t%s" % state)
    return 0


def _write_json(path, obj):
    """Atomic replace, so a crash mid-write cannot truncate the file."""
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=1, sort_keys=True)
        fh.write("\n")
    os.replace(tmp, path)


def _read_json(path, default):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return default


def _load_clients(state):
    return _read_json(_paths(state)[0], {})


def _save_clients(state, clients):
    _write_json(_paths(state)[0], clients)


def _append(state, path, obj):
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(obj, sort_keys=True) + "\n")


def cmd_observe(state, mac, ts=None, chan=None, rssi=None):
    """Record one sighting. Append-only, so this stays O(1)."""
    obs = _paths(state)[1]
    rec = {"mac": mac.lower(), "ts": int(ts or time.time())}
    if chan not in (None, ""):
        rec["ch"] = int(chan)
    if rssi not in (None, ""):
        rec["rssi"] = int(rssi)
    _append(state, obs, rec)

    # Touch the client summary too, so `clients` answers "last seen"
    # without scanning the whole observation log.
    clients = _load_clients(state)
    c = clients.setdefault(mac.lower(), {})
    c["last_seen"] = rec["ts"]
    c.setdefault("first_seen", rec["ts"])
    c["sightings"] = c.get("sightings", 0) + 1
    _save_clients(state, clients)
    return 0


def cmd_probe(state, mac, ssid, ts=None):
    probed = _paths(state)[2]
    _append(state, probed, {"mac": mac.lower(), "ssid": ssid,
                            "ts": int(ts or time.time())})
    clients = _load_clients(state)
    c = clients.setdefault(mac.lower(), {})
    known = c.setdefault("probes", [])
    if ssid not in known:
        known.append(ssid)
    _save_clients(state, clients)
    return 0


def cmd_client_set(state, mac, *pairs):
    clients = _load_clients(state)
    c = clients.setdefault(mac.lower(), {})
    for p in pairs:
        if "=" not in p:
            continue
        k, v = p.split("=", 1)
        c[k] = v
    _save_clients(state, clients)
    return 0


def cmd_client_get(state, mac):
    c = _load_clients(state).get(mac.lower())
    if c is None:
        print("ERROR\tno such client: %s" % mac)
        return 1
    for k in sorted(c):
        v = c[k]
        if isinstance(v, list):
            v = ",".join(str(x) for x in v)
        print("%s\t%s" % (k, v))
    return 0


def cmd_clients_tsv(state, *_):
    clients = _load_clients(state)
    print("MAC\tVENDOR\tDEVICE\tFIRST_SEEN\tLAST_SEEN\tSIGHTINGS\tPROBES")
    for mac in sorted(clients):
        c = clients[mac]
        probes = c.get("probes", [])
        print("\t".join(str(x) for x in (
            mac, c.get("vendor", ""), c.get("device", ""),
            c.get("first_seen", ""), c.get("last_seen", ""),
            c.get("sightings", 0), ",".join(probes))))
    return 0


def _iter_jsonl(path):
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except ValueError:
                    # A torn final line from an interrupted write. Skip it
                    # rather than failing the whole read.
                    continue
    except OSError:
        return


def cmd_history(state, mac, limit="50"):
    n = int(limit)
    rows = [r for r in _iter_jsonl(_paths(state)[1])
            if r.get("mac") == mac.lower()]
    print("TS\tCHANNEL\tRSSI")
    for r in rows[-n:]:
        print("%s\t%s\t%s" % (r.get("ts", ""), r.get("ch", ""), r.get("rssi", "")))
    return 0


def cmd_probes(state, mac=None):
    print("MAC\tSSID\tTS")
    for r in _iter_jsonl(_paths(state)[2]):
        if mac and r.get("mac") != mac.lower():
            continue
        print("%s\t%s\t%s" % (r.get("mac", ""), r.get("ssid", ""), r.get("ts", "")))
    return 0


def cmd_prune(state, days="30"):
    """Rewrite the append logs without entries older than N days.

    The one operation that is not O(1), which is why it is explicit and
    never runs as part of a normal recording path.
    """
    cutoff = int(time.time()) - int(days) * 86400
    obs_path, probed_path = _paths(state)[1], _paths(state)[2]
    kept = dropped = 0
    for path in (obs_path, probed_path):
        rows = [r for r in _iter_jsonl(path) if r.get("ts", 0) >= cutoff]
        dropped += sum(1 for _ in _iter_jsonl(path)) - len(rows)
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            for r in rows:
                fh.write(json.dumps(r, sort_keys=True) + "\n")
        os.replace(tmp, path)
        kept += len(rows)
    print("kept\t%d\ndropped\t%d" % (kept, dropped))
    return 0


def cmd_stats(state, *_):
    clients = _load_clients(state)
    obs = sum(1 for _ in _iter_jsonl(_paths(state)[1]))
    prb = sum(1 for _ in _iter_jsonl(_paths(state)[2]))
    print("clients\t%d" % len(clients))
    print("observations\t%d" % obs)
    print("probes\t%d" % prb)
    print("schema\t%s" % _read_json(_paths(state)[3], {}).get("schema", "?"))
    return 0


def cmd_selftest(*_):
    import tempfile
    bad = 0

    def chk(name, got, want):
        nonlocal bad
        if str(got) == str(want):
            print("%s\tPASS" % name)
        else:
            print("%s\tFAIL\twant=%s got=%s" % (name, want, got))
            bad += 1

    with tempfile.TemporaryDirectory() as d:
        cmd_init(d)
        chk("init-clients", os.path.exists(os.path.join(d, CLIENTS)), True)
        chk("init-obs", os.path.exists(os.path.join(d, OBS)), True)
        chk("init-schema", _read_json(os.path.join(d, META), {}).get("schema"), SCHEMA)

        cmd_observe(d, "AA:BB:CC:00:00:01", ts=1000, chan=6, rssi=-45)
        cmd_observe(d, "aa:bb:cc:00:00:01", ts=1001, chan=6, rssi=-50)
        cmd_observe(d, "AA:BB:CC:00:00:02", ts=1002, chan=11, rssi=-70)
        clients = _load_clients(d)
        chk("mac-case-normalised", len(clients), 2)
        chk("sightings-counted", clients["aa:bb:cc:00:00:01"]["sightings"], 2)
        chk("first-seen", clients["aa:bb:cc:00:00:01"]["first_seen"], 1000)
        chk("last-seen", clients["aa:bb:cc:00:00:01"]["last_seen"], 1001)

        cmd_probe(d, "AA:BB:CC:00:00:01", "CafeNet")
        cmd_probe(d, "AA:BB:CC:00:00:01", "CafeNet")
        cmd_probe(d, "AA:BB:CC:00:00:01", "HomeNet")
        chk("probes-deduped", len(_load_clients(d)["aa:bb:cc:00:00:01"]["probes"]), 2)

        cmd_client_set(d, "AA:BB:CC:00:00:01", "vendor=Apple", "device=phone")
        chk("client-set", _load_clients(d)["aa:bb:cc:00:00:01"]["vendor"], "Apple")

        # Append-only really does append: two writes, two lines.
        with open(os.path.join(d, OBS), encoding="utf-8") as fh:
            chk("obs-append-only", len([l for l in fh if l.strip()]), 3)

        chk("obs-count", sum(1 for _ in _iter_jsonl(os.path.join(d, OBS))), 3)

        # prune removes old rows and keeps recent ones
        cmd_observe(d, "AA:BB:CC:00:00:03", ts=int(time.time()))
        cmd_prune(d, days=30)
        remaining = [r["mac"] for r in _iter_jsonl(os.path.join(d, OBS))]
        chk("prune-dropped-old", "aa:bb:cc:00:00:01" in remaining, False)
        chk("prune-kept-new", "aa:bb:cc:00:00:03" in remaining, True)

        # a torn line must not break the read
        with open(os.path.join(d, OBS), "a", encoding="utf-8") as fh:
            fh.write('{"mac": "trunc\n')
        chk("torn-line-survives",
            sum(1 for _ in _iter_jsonl(os.path.join(d, OBS))), 1)

    print("RESULT\t%s" % ("PASS" if bad == 0 else "FAIL(%d)" % bad))
    return 1 if bad else 0


CMDS = {
    "init": cmd_init, "observe": cmd_observe, "probe": cmd_probe,
    "client-set": cmd_client_set, "client-get": cmd_client_get,
    "clients-tsv": cmd_clients_tsv, "history": cmd_history,
    "probes": cmd_probes, "prune": cmd_prune, "stats": cmd_stats,
    "selftest": cmd_selftest,
}

if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] not in CMDS:
        print("usage: fpstore.py {%s} ..." % "|".join(sorted(CMDS)))
        sys.exit(2)
    try:
        sys.exit(CMDS[sys.argv[1]](*sys.argv[2:]) or 0)
    except TypeError as e:
        print("ERROR\tbad arguments: %s" % e)
        sys.exit(2)
