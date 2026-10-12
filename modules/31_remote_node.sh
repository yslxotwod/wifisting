#!/usr/bin/env bash
# 31_remote_node.sh — fleet controller for remote nodes
: "${WIFISTING_ROOT:=$HOME/wifisting}"
# ── self-locate WIFISTING_ROOT ──
# When launched via pkexec, HOME is /root and any $HOME-relative path
# would land in the wrong place. Resolve WIFISTING_ROOT from this
# script's own path so state / loot / captures always end up in the
# project tree regardless of who runs us.
if [[ -z "${WIFISTING_ROOT:-}" ]]; then
    _sl_src="${BASH_SOURCE[0]}"
    while [ -L "$_sl_src" ]; do
        _sl_dir="$(cd -P "$(dirname "$_sl_src")" && pwd)"
        _sl_tgt="$(readlink "$_sl_src")"
        [[ "$_sl_tgt" != /* ]] && _sl_tgt="$_sl_dir/$_sl_tgt"
        _sl_src="$_sl_tgt"
    done
    WIFISTING_ROOT="$(cd -P "$(dirname "$_sl_src")/.." && pwd)"
    export WIFISTING_ROOT
    unset _sl_src _sl_dir _sl_tgt
fi

# Under pkexec, HOME=/root even though we're writing to the invoking
# user's tree. WIFISTING_ROOT is <real_home>/wifisting, so its parent
# is the real home. Reset HOME so downstream $HOME-relative defaults
# (LOOT_DIR, CAPTURES_DIR, LOGS_DIR, XDG_CONFIG_HOME, etc.) resolve
# to the user's paths instead of /root.
if [[ -n "${WIFISTING_ROOT:-}" ]]; then
    _real_home="$(dirname "$WIFISTING_ROOT")"
    if [[ -n "$_real_home" && -d "$_real_home" && "$HOME" != "$_real_home" ]]; then
        export HOME="$_real_home"
    fi
    unset _real_home
fi

: "${WIFISTING_HOME:=$WIFISTING_ROOT}"

: "${TMP_DIR:=/tmp/wifisting}"
: "${LOOT_DIR:=$WIFISTING_ROOT/loot}"
: "${LOGS_DIR:=$WIFISTING_ROOT/logs}"

RN_CONF_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/wifisting"
RN_DATA_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/wifisting/remote_node"
RN_CONFIG="$RN_CONF_DIR/nodes.ini"
RN_SPOOL="$RN_DATA_DIR/spool"
RN_STREAMS="$RN_DATA_DIR/streams"
RN_LOGS="$LOGS_DIR/remote_node"
RN_AGENT_SRC="$WIFISTING_ROOT/tools/remote_agent.sh"

mkdir -p "$RN_CONF_DIR" "$RN_SPOOL" "$RN_STREAMS" "$RN_LOGS"

# ---------- INI helpers (unchanged from original, kept for compat) ----------

rn_init_config() {
    [[ -f "$RN_CONFIG" ]] && return
    mkdir -p "$(dirname "$RN_CONFIG")"
    cat > "$RN_CONFIG" <<'HDR'
# wifisting remote nodes registry
# Sections: [node:NAME]
HDR
}

rn_ini_get() {
    local section="$1" key="$2"
    [[ -f "$RN_CONFIG" ]] || return 1
    awk -v sec="[$section]" -v k="$key" '
        $0 == sec { inside=1; next }
        inside && /^\[/ { exit }
        inside && $0 ~ "^" k "=" { sub("^" k "=", ""); print; exit }
    ' "$RN_CONFIG"
}

rn_ini_set() {
    local section="$1" key="$2" value="$3"
    rn_init_config
    local tmp
    tmp=$(mktemp)

    if ! grep -q "^\[$section\]" "$RN_CONFIG" 2>/dev/null; then
        printf '\n[%s]\n%s=%s\n' "$section" "$key" "$value" >> "$RN_CONFIG"
        return
    fi

    awk -v sec="[$section]" -v k="$key" -v v="$value" '
        $0 == sec { print; inside=1; written=0; next }
        inside && /^\[/ {
            if (!written) print k "=" v
            inside=0
            print
            next
        }
        inside && $0 ~ "^" k "=" {
            print k "=" v
            written=1
            next
        }
        { print }
        END {
            if (inside && !written) print k "=" v
        }
    ' "$RN_CONFIG" > "$tmp"
    mv "$tmp" "$RN_CONFIG"
}

rn_ini_remove_section() {
    local section="$1"
    [[ -f "$RN_CONFIG" ]] || return 1
    local tmp
    tmp=$(mktemp)
    awk -v sec="[$section]" '
        $0 == sec { skip=1; next }
        skip && /^\[/ { skip=0 }
        !skip { print }
    ' "$RN_CONFIG" > "$tmp"
    mv "$tmp" "$RN_CONFIG"
}

rn_ini_list_sections() {
    [[ -f "$RN_CONFIG" ]] || return 0
    grep -oP '^\[node:\K[^\]]+' "$RN_CONFIG" 2>/dev/null
}

# ---------- transport ----------

rn_transport_exec() {
    local node="$1"
    shift
    local transport address port
    transport=$(rn_ini_get "node:$node" transport)
    address=$(rn_ini_get "node:$node" address)
    port=$(rn_ini_get "node:$node" port)

    case "$transport" in
        ssh)
            local opts=(-o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=accept-new)
            [[ -n "$port" ]] && opts+=(-p "$port")
            ssh "${opts[@]}" "$address" "$@"
            ;;
        adb)
            adb -s "${address#adb://}" shell "$@"
            ;;
        *)
            printf 'ERROR\tunknown transport: %s\n' "$transport" >&2
            return 1
            ;;
    esac
}

rn_push_agent() {
    local node="$1"
    local transport address port
    transport=$(rn_ini_get "node:$node" transport)
    address=$(rn_ini_get "node:$node" address)
    port=$(rn_ini_get "node:$node" port)

    [[ -f "$RN_AGENT_SRC" ]] || {
        printf 'ERROR\tagent script not found: %s\n' "$RN_AGENT_SRC"
        return 1
    }

    case "$transport" in
        ssh)
            local opts=(-o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=accept-new)
            [[ -n "$port" ]] && opts+=(-P "$port")
            scp "${opts[@]}" "$RN_AGENT_SRC" "$address:/tmp/wifisting_agent.sh" >/dev/null 2>&1 && \
                rn_transport_exec "$node" 'chmod +x /tmp/wifisting_agent.sh'
            ;;
        adb)
            adb -s "${address#adb://}" push "$RN_AGENT_SRC" /data/local/tmp/wifisting_agent.sh >/dev/null 2>&1 && \
                adb -s "${address#adb://}" shell chmod +x /data/local/tmp/wifisting_agent.sh
            ;;
        *)
            printf 'ERROR\tcannot push via %s\n' "$transport"
            return 1
            ;;
    esac
}

# ---------- node management ----------

rn_add_node() {
    local name="$1" type="$2" transport="$3" address="$4"
    local port="${5:-}"

    [[ -z "$name" || -z "$type" || -z "$transport" || -z "$address" ]] && {
        printf 'ERROR\tusage: --add-node NAME TYPE TRANSPORT ADDRESS [PORT]\n'
        return 2
    }

    [[ "$name" =~ ^[a-zA-Z0-9_.-]+$ ]] || {
        printf 'ERROR\tinvalid name\n'; return 2
    }

    if [[ -n "$(rn_ini_get "node:$name" type 2>/dev/null)" ]]; then
        printf 'ERROR\tnode already exists: %s\n' "$name"
        return 1
    fi

    rn_ini_set "node:$name" type       "$type"
    rn_ini_set "node:$name" transport  "$transport"
    rn_ini_set "node:$name" address    "$address"
    [[ -n "$port" ]] && rn_ini_set "node:$name" port "$port"
    rn_ini_set "node:$name" created    "$(date +%s)"
    rn_ini_set "node:$name" status     unknown

    printf 'ADDED\t%s\n' "$name"
}

rn_remove_node() {
    local name="$1"
    [[ -z "$name" ]] && return 2
    rn_ini_remove_section "node:$name"
    rm -f "$RN_SPOOL/$name.tsv" "$RN_SPOOL/$name.pos"
    rm -f "$RN_STREAMS/$name.pid"
    printf 'REMOVED\t%s\n' "$name"
}

rn_probe_node() {
    local name="$1"
    [[ -z "$name" ]] && { printf 'ERROR\tmissing node\n' >&2; return 2; }

    rn_push_agent "$name" >/dev/null 2>&1 || true

    local out rc
    out=$(rn_transport_exec "$name" '/tmp/wifisting_agent.sh --probe' 2>/dev/null)
    rc=$?
    if (( rc != 0 )) || [[ -z "$out" ]]; then
        rn_ini_set "node:$name" status "unreachable"
        printf 'PROBE\tFAIL\treason=agent-not-responding\n'
        return 1
    fi

    local roles="" caps="" ifaces="" hostname="" uname_="" os="" distro="" kernel=""
    while IFS=$'\t' read -r k v; do
        case "$k" in
            ROLES)    roles="$v" ;;
            CAPS)     caps="$v" ;;
            IFACES)   ifaces="$v" ;;
            HOSTNAME) hostname="$v" ;;
            UNAME)    uname_="$v" ;;
            OS)       os="$v" ;;
            DISTRO)   distro="$v" ;;
            KERNEL)   kernel="$v" ;;
        esac
    done <<< "$out"

    rn_ini_set "node:$name" roles        "$roles"
    rn_ini_set "node:$name" capabilities "$caps"
    rn_ini_set "node:$name" ifaces       "$ifaces"
    rn_ini_set "node:$name" hostname     "$hostname"
    rn_ini_set "node:$name" uname        "$uname_"
    rn_ini_set "node:$name" os           "$os"
    rn_ini_set "node:$name" distro       "$distro"
    rn_ini_set "node:$name" kernel       "$kernel"
    rn_ini_set "node:$name" last_seen    "$(date +%s)"
    rn_ini_set "node:$name" status       online

    printf 'ROLES\t%s\n'   "$roles"
    printf 'CAPS\t%s\n'    "$caps"
    printf 'IFACES\t%s\n'  "$ifaces"
    printf 'HOSTNAME\t%s\n' "$hostname"
    printf 'DISTRO\t%s\n'  "$distro"
    printf 'STATUS\t%s\n'  online
}

# ── bulk ops ──
rn_bulk_probe() {
    local total=0 ok=0 fail=0
    local name
    while IFS= read -r name; do
        [[ -z "$name" ]] && continue
        total=$((total+1))
        printf 'PROBING\t%s\n' "$name"
        if rn_probe_node "$name" >/dev/null 2>&1; then
            ok=$((ok+1))
            printf 'OK\t%s\n' "$name"
        else
            fail=$((fail+1))
            printf 'FAIL\t%s\n' "$name"
        fi
    done < <(rn_ini_list_sections)
    printf 'BULK\t%s\t%s\t%s\n' "$total" "$ok" "$fail"
}

rn_remove_offline() {
    local removed=0
    local name
    while IFS= read -r name; do
        [[ -z "$name" ]] && continue
        local status
        status=$(rn_ini_get "node:$name" status)
        if [[ "$status" == "unreachable" || "$status" == "offline" ]]; then
            rn_remove_node "$name" >/dev/null
            removed=$((removed+1))
            printf 'REMOVED\t%s\n' "$name"
        fi
    done < <(rn_ini_list_sections)
    printf 'TOTAL_REMOVED\t%s\n' "$removed"
}


# ── presets ─────────────────────────────────────────────────────────────
# The wizard asks three things (transport, hardware, role) and the preset
# fills the first two so the operator only has to confirm what the probe
# finds. A Pi and a phone are not different kinds of node here, they are
# different combinations of the same three axes.
rn_presets_tsv() {
    printf 'preset\ttransport\texpected_caps\n'
    printf 'pi\tssh\twifi,monitor,inject,gps,cellular,gpio\n'
    printf 'phone\tadb\tgps,cellular\n'
    printf 'phone-nexmon\tadb\twifi,monitor,inject,gps,cellular\n'
    printf 'workstation\tssh\twifi,monitor,inject,gpu\n'
    printf 'vm\tssh\talways-on\n'
    printf 'vps\thttps\trelay,always-on\n'
    printf 'custom\t\t\n'
}

# ── role derivation ─────────────────────────────────────────────────────
# Roles are DERIVED from what a node can actually do rather than declared
# up front: the probe reports capabilities, and this decides what the node
# is for. Kept in one function so the wizard, the probe and any script
# agree on the rule instead of each inventing its own.
rn_suggest_roles() {
    local caps="${1:-}" roles=""

    has_cap() { [[ ",$caps," == *",$1,"* ]]; }

    # Sensing is not only Wi-Fi. The design defines the sensor role as
    # "passive Wi-Fi + cell + GPS observation", so a stock phone with only
    # GPS and cellular is a sensor, not a relay. Counting just wifi/monitor
    # here made every phone fall through to the relay fallback.
    if has_cap monitor || has_cap inject || has_cap wifi \
       || has_cap gps || has_cap cellular; then
        roles="sensor"
        has_cap inject && roles="sensor,attacker"
    fi

    # A GPU makes it a cracker whatever else it can do.
    has_cap gpu && roles="${roles:+$roles,}cracker"

    # No radio and no GPU means the only useful job is accepting and
    # queueing what other nodes send it. This single clause covers the
    # VM/VPS case; an earlier version added 'relay' here as well and
    # produced "relay,relay" for an always-on node with no radio.
    if [[ "$roles" != *sensor* && "$roles" != *cracker* ]]; then
        roles="${roles:+$roles,}relay"
    fi

    printf '%s' "${roles:-relay}"
}

rn_cli_suggest_roles_tsv() {
    local caps="${1:-}"
    [[ -n "$caps" ]] || { printf 'ERROR\tusage: --suggest-roles-tsv CAPS\n' >&2; return 2; }
    printf 'CAPS\t%s\n' "$caps"
    printf 'ROLES\t%s\n' "$(rn_suggest_roles "$caps")"
}

rn_cli_set_roles() {
    local name="${1:-}" roles="${2:-}"
    [[ -n "$name" && -n "$roles" ]] || {
        printf 'ERROR\tusage: --set-roles NAME ROLE[,ROLE...]\n' >&2; return 2; }
    [[ -n "$(rn_ini_get "node:$name" type 2>/dev/null)" ]] || {
        printf 'ERROR\tno such node: %s\n' "$name" >&2; return 1; }
    # Validate against the known set so a typo cannot silently create a role
    # nothing in the GUI knows how to render.
    local r
    IFS=',' read -ra parts <<< "$roles"
    for r in "${parts[@]}"; do
        case "$r" in
            sensor|attacker|cracker|relay|ap-host) ;;
            *) printf 'ERROR\tunknown role: %s (sensor, attacker, cracker, relay, ap-host)\n' \
                   "$r" >&2; return 2 ;;
        esac
    done
    rn_ini_set "node:$name" roles "$roles"
    printf 'ROLES\t%s\t%s\n' "$name" "$roles"
}

# ── node health (via agent probe subcommands if we add them later) ──
rn_node_health_tsv() {
    local name="$1"
    [[ -z "$name" ]] && { printf 'ERROR\tmissing node\n' >&2; return 2; }

    # Cheap local read: last_seen delta and status
    local status last_seen now delta
    status=$(rn_ini_get "node:$name" status)
    last_seen=$(rn_ini_get "node:$name" last_seen)
    now=$(date +%s)
    delta=$(( now - ${last_seen:-0} ))

    printf 'name\t%s\n'      "$name"
    printf 'status\t%s\n'    "$status"
    printf 'last_seen\t%s\n' "${last_seen:-}"
    printf 'age_sec\t%s\n'   "$delta"

    # If SSH is available, get real metrics in one call
    if [[ "$status" == "online" || "$status" == "streaming" ]]; then
        local metrics
        metrics=$(rn_transport_exec "$name" '
            echo -n "CPU\t"; grep "cpu " /proc/stat | awk "{u=\$2+\$4; t=\$2+\$3+\$4+\$5+\$6+\$7+\$8; print int(u*100/t)}"
            echo -n "MEM\t"; free -m | awk "/Mem:/ {print \$3\"/\"\$2\" MB\"}"
            echo -n "DISK\t"; df -h / | awk "NR==2 {print \$3\"/\"\$2}"
            echo -n "UPTIME\t"; uptime -p
            echo -n "LOAD\t"; cat /proc/loadavg | cut -d" " -f1-3
        ' 2>/dev/null)
        [[ -n "$metrics" ]] && printf '%s\n' "$metrics"
    fi
}

rn_node_info_tsv() {
    local name="$1"
    [[ -z "$name" ]] && { printf 'ERROR\tmissing node\n' >&2; return 2; }
    local fields=(type transport address port roles capabilities ifaces hostname uname os distro kernel created last_seen status)
    local f
    for f in "${fields[@]}"; do
        printf '%s\t%s\n' "$f" "$(rn_ini_get "node:$name" "$f" 2>/dev/null)"
    done
}

rn_list_nodes_tsv() {
    rn_init_config
    local name
    while IFS= read -r name; do
        [[ -z "$name" ]] && continue
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$name" \
            "$(rn_ini_get "node:$name" type)" \
            "$(rn_ini_get "node:$name" transport)" \
            "$(rn_ini_get "node:$name" address)" \
            "$(rn_ini_get "node:$name" roles)" \
            "$(rn_ini_get "node:$name" capabilities)" \
            "$(rn_ini_get "node:$name" status)" \
            "$(rn_ini_get "node:$name" last_seen)"
    done < <(rn_ini_list_sections)
}

# ---------- streams ----------

rn_start_stream() {
    local name="$1"
    [[ -z "$name" ]] && { printf 'ERROR\tmissing node\n' >&2; return 2; }

    rn_stop_stream "$name" >/dev/null 2>&1 || true

    local transport address port pidfile spool log
    transport=$(rn_ini_get "node:$name" transport)
    address=$(rn_ini_get "node:$name" address)
    port=$(rn_ini_get "node:$name" port)
    pidfile="$RN_STREAMS/$name.pid"
    spool="$RN_SPOOL/$name.tsv"
    log="$RN_LOGS/$name.log"

    touch "$spool"
    : > "$log"

    case "$transport" in
        ssh)
            local opts=(-o BatchMode=yes -o ServerAliveInterval=15 -o ServerAliveCountMax=3 -o StrictHostKeyChecking=accept-new)
            [[ -n "$port" ]] && opts+=(-p "$port")
            nohup ssh "${opts[@]}" "$address" '/tmp/wifisting_agent.sh --stream' \
                >> "$spool" 2>> "$log" &
            ;;
        adb)
            nohup adb -s "${address#adb://}" shell /data/local/tmp/wifisting_agent.sh --stream \
                >> "$spool" 2>> "$log" &
            ;;
        *)
            printf 'ERROR\tcannot stream via %s\n' "$transport"
            return 1
            ;;
    esac

    local pid=$!
    echo "$pid" > "$pidfile"
    rn_ini_set "node:$name" status streaming
    printf 'STARTED\t%s\t%s\n' "$pid" "$spool"
}

rn_stop_stream() {
    local name="$1"
    local pidfile="$RN_STREAMS/$name.pid"
    if [[ -f "$pidfile" ]]; then
        local pid
        pid=$(cat "$pidfile")
        if ! stop_kill_pid "$pid"; then
            printf 'ERROR\tstream pid %s survived SIGKILL (pidfile kept)\n' \
                "$pid" >&2
            return 1
        fi
        # Also kill the remote side
        rn_transport_exec "$name" 'pkill -f "wifisting_agent.sh --stream"' 2>/dev/null || true
        rm -f "$pidfile"
        rn_ini_set "node:$name" status online
        printf 'STOPPED\t%s\n' "$pid"
    else
        printf 'STOPPED\t0\n'
    fi
}

rn_stop_all_streams() {
    local name
    while IFS= read -r name; do
        [[ -z "$name" ]] && continue
        [[ -f "$RN_STREAMS/$name.pid" ]] && rn_stop_stream "$name" >/dev/null
    done < <(rn_ini_list_sections)
}

rn_stream_status_tsv() {
    local name="$1"
    local pidfile="$RN_STREAMS/$name.pid"
    local running=0 pid=""
    if [[ -f "$pidfile" ]]; then
        pid=$(cat "$pidfile")
        kill -0 "$pid" 2>/dev/null && running=1
    fi
    local spool_size=0
    [[ -f "$RN_SPOOL/$name.tsv" ]] && spool_size=$(wc -c < "$RN_SPOOL/$name.tsv")
    printf 'running\t%s\n' "$running"
    printf 'pid\t%s\n' "$pid"
    printf 'spool_bytes\t%s\n' "$spool_size"
}

# ---------- spool ----------

rn_spool_list_tsv() {
    local name
    while IFS= read -r name; do
        [[ -z "$name" ]] && continue
        local bytes=0 events=0
        if [[ -f "$RN_SPOOL/$name.tsv" ]]; then
            bytes=$(wc -c < "$RN_SPOOL/$name.tsv")
            events=$(wc -l < "$RN_SPOOL/$name.tsv")
        fi
        printf '%s\t%s\t%s\n' "$name" "$bytes" "$events"
    done < <(rn_ini_list_sections)
}

rn_spool_drain() {
    local name="$1"
    local spool="$RN_SPOOL/$name.tsv"
    local posfile="$RN_SPOOL/$name.pos"
    [[ -f "$spool" ]] || return 0

    local pos=0
    [[ -f "$posfile" ]] && pos=$(cat "$posfile")

    local size
    size=$(wc -c < "$spool")
    (( size <= pos )) && return 0

    tail -c +$((pos + 1)) "$spool" | grep -v '^$' || true
    echo "$size" > "$posfile"
}

rn_spool_peek() {
    local name="$1" n="${2:-50}"
    local spool="$RN_SPOOL/$name.tsv"
    [[ -f "$spool" ]] && tail -n "$n" "$spool" | grep -v '^$' || true
}

# ---------- whitelist / rules ----------

rn_whitelist_get() { rn_ini_get "node:$1" whitelist; }

rn_whitelist_set() {
    local name="$1" file="$2"
    [[ -f "$file" ]] || { printf 'ERROR\tfile not found\n' >&2; return 1; }
    local joined
    joined=$(tr '\n' ',' < "$file" | sed 's/,$//')
    rn_ini_set "node:$name" whitelist "$joined"
    printf 'SET\t%s\n' "$joined"
}

rn_rules_get() { rn_ini_get "node:$1" rules; }

rn_rules_set() {
    local name="$1" file="$2"
    [[ -f "$file" ]] || { printf 'ERROR\tfile not found\n' >&2; return 1; }
    rn_ini_set "node:$name" rules "$file"
    printf 'SET\t%s\n' "$file"
}

# ---------- attacks ----------

rn_attack_dispatch() {
    local name="$1" chain="$2" bssid="${3:-}" duration="${4:-60}"
    [[ -z "$name" || -z "$chain" ]] && {
        printf 'ERROR\tusage: --attack-dispatch NAME CHAIN [BSSID] [DURATION]\n'
        return 2
    }
    [[ -f "$chain" ]] || { printf 'ERROR\tchain not found: %s\n' "$chain" >&2; return 1; }

    local roles
    roles=$(rn_ini_get "node:$name" roles)
    [[ "$roles" == *"attacker"* ]] || {
        printf 'ERROR\tnode %s has no attacker role\n' "$name"
        return 1
    }

    # Push the chain file to the node first
    local transport address port
    transport=$(rn_ini_get "node:$name" transport)
    address=$(rn_ini_get "node:$name" address)
    port=$(rn_ini_get "node:$name" port)

    case "$transport" in
        ssh)
            local opts=(-o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=accept-new)
            [[ -n "$port" ]] && opts+=(-P "$port")
            scp "${opts[@]}" "$chain" "$address:/tmp/wifisting_chain.tsv" >/dev/null 2>&1 || {
                printf 'ERROR\tfailed to push chain\n'; return 1
            }
            ;;
    esac

    local rc=0
    rn_transport_exec "$name" "/tmp/wifisting_agent.sh --attack /tmp/wifisting_chain.tsv '$bssid' '$duration'" || rc=$?
    printf 'DISPATCHED\t%s\trc=%s\n' "$name" "$rc"
}

rn_attack_stop() {
    local name="$1"
    # The attack runs on the remote node, so the only signal we get is
    # whether the transport command itself succeeded. Report that honestly
    # rather than always claiming STOPPED.
    if rn_transport_exec "$name" \
         'pkill -f "wifisting_agent.sh --attack" 2>/dev/null; pkill -f "29_killchain.sh" 2>/dev/null; true' 2>/dev/null; then
        printf 'STOPPED\t%s\n' "$name"
        return 0
    fi
    printf 'ERROR\tcould not reach %s to stop the attack\n' "$name" >&2
    return 1
}

# ---------- crack queue ----------

rn_crack_queue_tsv() {
    local q="$RN_DATA_DIR/crack_queue.tsv"
    [[ -f "$q" ]] && cat "$q" || true
}

rn_crack_submit() {
    local name="$1" hashfile="$2"
    [[ -f "$hashfile" ]] || { printf 'ERROR\thashfile not found\n' >&2; return 1; }
    local roles
    roles=$(rn_ini_get "node:$name" roles)
    [[ "$roles" == *"crack-node"* ]] || {
        printf 'ERROR\tnode %s is not a crack-node\n' "$name"
        return 1
    }

    # Push the hash file
    local transport address port
    transport=$(rn_ini_get "node:$name" transport)
    address=$(rn_ini_get "node:$name" address)
    port=$(rn_ini_get "node:$name" port)

    if [[ "$transport" == "ssh" ]]; then
        local opts=(-o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=accept-new)
        [[ -n "$port" ]] && opts+=(-P "$port")
        scp "${opts[@]}" "$hashfile" "$address:/tmp/wifisting_crack.22000" >/dev/null 2>&1 || {
            printf 'ERROR\tfailed to push hashfile\n'; return 1
        }
    fi

    local q="$RN_DATA_DIR/crack_queue.tsv"
    printf '%s\t%s\t%s\tpending\n' "$(date +%s)" "$name" "$hashfile" >> "$q"
    printf 'QUEUED\t%s\n' "$hashfile"
}

rn_crack_status_tsv() {
    local q="$RN_DATA_DIR/crack_queue.tsv"
    [[ ! -f "$q" ]] && { printf 'total\t0\npending\t0\nrunning\t0\ndone\t0\n'; return; }
    awk -F'\t' '
        { total++; if ($4=="pending") pending++; else if ($4=="running") running++; else if ($4=="done"||$4=="cracked") done++ }
        END {
            printf "total\t%d\n", total+0
            printf "pending\t%d\n", pending+0
            printf "running\t%d\n", running+0
            printf "done\t%d\n", done+0
        }
    ' "$q"
}

# ---------- honeypot ----------

rn_honeypot_fleet_tsv() {
    local name
    while IFS= read -r name; do
        [[ -z "$name" ]] && continue
        local caps mode
        caps=$(rn_ini_get "node:$name" capabilities)
        [[ "$caps" != *"ap-mode"* ]] && continue
        mode=$(rn_ini_get "node:$name" honeypot_mode)
        [[ -z "$mode" ]] && mode=off
        printf '%s\t%s\t%s\n' "$name" "$mode" "$(rn_ini_get "node:$name" status)"
    done < <(rn_ini_list_sections)
}

rn_honeypot_mode() {
    local name="$1" mode="$2"
    [[ "$mode" =~ ^(off|passive|attack)$ ]] || {
        printf 'ERROR\tmode must be off|passive|attack\n'
        return 1
    }
    rn_ini_set "node:$name" honeypot_mode "$mode"

    # Actually flip the node's AP
    case "$mode" in
        off)
            rn_transport_exec "$name" 'pkill -f hostapd 2>/dev/null; pkill -f dnsmasq 2>/dev/null; true' || true
            ;;
        passive)
            rn_transport_exec "$name" 'hostapd /tmp/wifisting_hp.conf >/dev/null 2>&1 &' || true
            ;;
        attack)
            rn_transport_exec "$name" 'hostapd /tmp/wifisting_hp.conf >/dev/null 2>&1 &' || true
            # portal would go here
            ;;
    esac

    printf 'MODE\t%s\t%s\n' "$name" "$mode"
}

rn_honeypot_clients_tsv() {
    local name="$1"
    local f="$RN_DATA_DIR/honeypot/$name.clients.tsv"
    [[ -f "$f" ]] && cat "$f" || true
}

rn_honeypot_creds_tsv() {
    local name="$1"
    local f="$RN_DATA_DIR/honeypot/$name.creds.tsv"
    [[ -f "$f" ]] && cat "$f" || true
}

# ---------- nexmon ----------

rn_nexmon_install() {
    local name="$1"
    local type
    type=$(rn_ini_get "node:$name" type)
    [[ "$type" == "phone" ]] || {
        printf 'ERROR\tnexmon install only applies to phone nodes\n'
        return 1
    }
    rn_transport_exec "$name" '/tmp/wifisting_agent.sh --nexmon-install' || return $?
    rn_probe_node "$name"
}

# ---------- status ----------

rn_status_tsv() {
    rn_init_config
    local total=0 online=0 streaming=0
    local name
    while IFS= read -r name; do
        [[ -z "$name" ]] && continue
        total=$((total + 1))
        local st
        st=$(rn_ini_get "node:$name" status)
        case "$st" in
            online)    online=$((online + 1)) ;;
            streaming) streaming=$((streaming + 1)) ;;
        esac
    done < <(rn_ini_list_sections)

    local events=0
    for f in "$RN_SPOOL"/*.tsv; do
        [[ -f "$f" ]] || continue
        events=$((events + $(wc -l < "$f")))
    done

    printf 'nodes_total\t%s\n' "$total"
    printf 'nodes_online\t%s\n' "$online"
    printf 'nodes_streaming\t%s\n' "$streaming"
    printf 'events_seen\t%s\n' "$events"
    printf 'config_file\t%s\n' "$RN_CONFIG"
    printf 'spool_dir\t%s\n' "$RN_SPOOL"
    printf 'agent_src\t%s\n' "$RN_AGENT_SRC"
    printf 'agent_present\t%s\n' "$([[ -f "$RN_AGENT_SRC" ]] && echo yes || echo no)"
}

# ---------- dispatch ----------

# ── verified stop ──
# Escalating signals; returns 0 ONLY once the pid is actually gone. Signals
# the process group first so forked children die with the leader. Stops that
# print STOPPED and delete the pidfile without this can strand a capture with
# no remaining handle to it, making the stop button useless.
stop_kill_pid() {
    local pid="$1" i
    # Liveness via /proc, NOT `kill -0`: for a root-owned process we get EPERM,
    # and treating that as "gone" made stops report success while nothing died.
    [[ -d "/proc/$pid" ]] || return 0
    kill -INT  "-$pid" 2>/dev/null || kill -INT  "$pid" 2>/dev/null
    for i in 1 2 3 4 5 6 7 8 9 10; do
        [[ -d "/proc/$pid" ]] || return 0
        sleep 0.2
    done
    kill -TERM "-$pid" 2>/dev/null || kill -TERM "$pid" 2>/dev/null
    for i in 1 2 3 4 5; do
        [[ -d "/proc/$pid" ]] || return 0
        sleep 0.2
    done
    kill -KILL "-$pid" 2>/dev/null || kill -KILL "$pid" 2>/dev/null
    sleep 0.3
    [[ -d "/proc/$pid" ]] && return 1
    return 0
}
# Kill everything matching a pgrep -f pattern, never this shell or its parent.
# Returns non-zero only if something matched and SURVIVED.
stop_sweep() {
    local pat="$1" sp rs=0 any=0
    # Exclude this process AND its whole ancestor chain. Excluding only $$ and
    # $PPID is not enough: when invoked via `timeout` or pkexec the caller's
    # shell is further up, and a cmdline substring match would kill it — a
    # pattern like "mitm6" matches the very command line running this stop.
    local -A _skip=()
    sp=$$
    while [[ -n "$sp" && "$sp" != "0" && "$sp" != "1" ]]; do
        _skip[$sp]=1
        sp=$(ps -o ppid= -p "$sp" 2>/dev/null | tr -d ' ')
        [[ -z "$sp" ]] && break
    done
    for sp in $(pgrep -f "$pat" 2>/dev/null); do
        [[ -n "${_skip[$sp]:-}" ]] && continue
        any=1
        stop_kill_pid "$sp" || rs=1
    done
    (( any )) && return $rs
    return 0
}

# ── self-test ────────────────────────────────────────────────────────────
# Offline: the INI registry, node CRUD, spool byte-offset draining, role
# gating and argument validation are all local file logic. The real
# ~/.config/wifisting/nodes.ini and the spool/stream dirs are redirected
# into scratch space, and every node used here has a bogus transport so no
# ssh/adb call can escape.
rn_selftest() {
    local bad=0
    chk() {
        local n="$1" got="$2" want="$3"
        if [[ "$got" == "$want" ]]; then printf '%s\tPASS\n' "$n"
        else printf '%s\tFAIL want=%s got=%s\n' "$n" "$want" "$got"; bad=$((bad+1)); fi
    }
    fld() { printf '%s\n' "$1" | awk -F'\t' -v k="$2" '$1==k{print $2; exit}'; }
    rcount() { printf '%s\n' "$1" | grep -c . ; }

    local MOD_TMP="${TMP_DIR:-/tmp/wifisting}/remote_node/selftest"
    rm -rf "$MOD_TMP"; mkdir -p "$MOD_TMP/spool" "$MOD_TMP/streams" "$MOD_TMP/logs" "$MOD_TMP/data"
    local s_conf="$RN_CONFIG" s_spool="$RN_SPOOL" s_streams="$RN_STREAMS"
    local s_logs="$RN_LOGS" s_data="$RN_DATA_DIR"
    RN_CONFIG="$MOD_TMP/nodes.ini"
    RN_SPOOL="$MOD_TMP/spool"; RN_STREAMS="$MOD_TMP/streams"; RN_LOGS="$MOD_TMP/logs"
    RN_DATA_DIR="$MOD_TMP/data"

    local out rc

    # 1. INI registry: create, read, update, section isolation
    rn_ini_get "node:none" type >/dev/null 2>&1
    chk ini-get-missing-file-rc "$?" 1
    rn_init_config
    chk ini-init-creates "$([[ -f "$RN_CONFIG" ]] && echo 1 || echo 0)" 1
    chk ini-init-header  "$(grep -c '^# wifisting remote nodes registry$' "$RN_CONFIG")" 1
    local before; before=$(md5sum < "$RN_CONFIG")
    rn_init_config
    chk ini-init-idempotent "$(md5sum < "$RN_CONFIG")" "$before"

    rn_ini_set "node:alpha" type ap >/dev/null
    chk ini-set-get      "$(rn_ini_get "node:alpha" type)"  ap
    rn_ini_set "node:alpha" transport sneakernet >/dev/null
    chk ini-second-key   "$(rn_ini_get "node:alpha" transport)" sneakernet
    chk ini-one-section  "$(grep -c '^\[node:alpha\]$' "$RN_CONFIG")" 1
    rn_ini_set "node:alpha" type phone >/dev/null
    chk ini-update-value "$(rn_ini_get "node:alpha" type)" phone
    chk ini-update-nodup "$(grep -c '^type=' "$RN_CONFIG")" 1
    chk ini-unknown-key  "$(rn_ini_get "node:alpha" nosuchkey)" ""
    chk ini-unknown-key-rc "$(rn_ini_get "node:alpha" nosuchkey >/dev/null 2>&1; echo $?)" 0

    rn_ini_set "node:beta" type phone >/dev/null
    chk ini-second-section "$(rn_ini_get "node:beta" type)" phone
    chk ini-isolated       "$(rn_ini_get "node:alpha" type)" phone
    rn_ini_set "node:alpha" port 22 >/dev/null
    rn_ini_set "node:alpha" portx 99 >/dev/null
    chk ini-key-prefix     "$(rn_ini_get "node:alpha" port)" 22
    chk ini-key-prefix2    "$(rn_ini_get "node:alpha" portx)" 99
    rn_ini_set "node:alpha" address "ssh://user@host:2222" >/dev/null
    chk ini-value-with-colon "$(rn_ini_get "node:alpha" address)" "ssh://user@host:2222"
    rn_ini_set "node:alpha" note "a=b=c" >/dev/null
    chk ini-value-with-equals "$(rn_ini_get "node:alpha" note)" "a=b=c"
    chk ini-sections "$(rn_ini_list_sections | tr '\n' ' ')" "alpha beta "
    rn_ini_remove_section "node:alpha"
    chk ini-remove-section "$(rn_ini_get "node:alpha" type)" ""
    chk ini-remove-keeps-other "$(rn_ini_get "node:beta" type)" phone
    chk ini-remove-section-header "$(grep -c '^\[node:alpha\]$' "$RN_CONFIG")" 0

    # 2. node add: usage, name validation, duplicate protection
    rm -f "$RN_CONFIG"
    rn_add_node >/dev/null 2>&1;                      chk add-usage-rc "$?" 2
    out=$(rn_add_node "bad name!" ap sneakernet 1.2.3.4 2>&1); rc=$?
    chk add-badname-rc  "$rc" 2
    chk add-badname-msg "$(printf '%s\n' "$out" | awk -F'\t' '$1=="ERROR"{print $2}')" "invalid name"
    out=$(rn_add_node edge.node-1 ap sneakernet 10.0.0.1 2222); rc=$?
    chk add-rc      "$rc" 0
    chk add-says    "$(printf '%s\n' "$out" | awk -F'\t' '$1=="ADDED"{print $2}')" edge.node-1
    chk add-type    "$(rn_ini_get "node:edge.node-1" type)" ap
    chk add-transport "$(rn_ini_get "node:edge.node-1" transport)" sneakernet
    chk add-address "$(rn_ini_get "node:edge.node-1" address)" 10.0.0.1
    chk add-port    "$(rn_ini_get "node:edge.node-1" port)" 2222
    chk add-status  "$(rn_ini_get "node:edge.node-1" status)" unknown
    chk add-created-numeric "$(rn_ini_get "node:edge.node-1" created | grep -cE '^[0-9]+$')" 1
    out=$(rn_add_node node2 ap sneakernet 10.0.0.2); rc=$?
    chk add-noport-rc    "$rc" 0
    chk add-noport-absent "$(rn_ini_get "node:node2" port)" ""
    out=$(rn_add_node edge.node-1 ap sneakernet 10.0.0.1 2>&1); rc=$?
    chk add-dup-rc  "$rc" 1
    chk add-dup-msg "$(printf '%s\n' "$out" | awk -F'\t' '$1=="ERROR"{print $2}')" \
        "node already exists: edge.node-1"

    # 3. node list / info
    out=$(rn_list_nodes_tsv)
    chk list-rows   "$(rcount "$out")" 2
    chk list-fields "$(printf '%s\n' "$out" | awk -F'\t' 'NF!=8{c++} END{print c+0}')" 0
    chk list-type   "$(printf '%s\n' "$out" | awk -F'\t' '$1=="node2"{print $2}')" ap
    chk list-status "$(printf '%s\n' "$out" | awk -F'\t' '$1=="node2"{print $7}')" unknown
    out=$(rn_node_info_tsv edge.node-1)
    chk info-rows   "$(rcount "$out")" 15
    chk info-first  "$(printf '%s\n' "$out" | head -1 | cut -f1)" type
    chk info-last   "$(printf '%s\n' "$out" | tail -1 | cut -f1)" status
    chk info-address "$(fld "$out" address)" 10.0.0.1
    chk info-absent "$(fld "$(rn_node_info_tsv ghost)" address)" ""
    rn_node_info_tsv "" >/dev/null 2>&1; chk info-no-name-rc "$?" 2

    # 4. health: local age maths, and no invented metrics for an unreachable node
    rn_ini_set "node:node2" last_seen "$(( $(date +%s) - 100 ))" >/dev/null
    out=$(rn_node_health_tsv node2)
    chk health-rows    "$(rcount "$out")" 4
    chk health-name    "$(fld "$out" name)" node2
    chk health-status  "$(fld "$out" status)" unknown
    chk health-age     "$(printf '%s\n' "$out" | awk -F'\t' '$1=="age_sec"{print ($2>=100 && $2<=115)?"ok":"bad("$2")"}')" ok
    rn_ini_set "node:node2" status online >/dev/null
    out=$(rn_node_health_tsv node2)
    chk health-online-no-metrics "$(rcount "$out")" 4
    rn_node_health_tsv "" >/dev/null 2>&1; chk health-no-name-rc "$?" 2

    # 5. fleet status rollup
    rn_add_node n_online ap sneakernet 10.0.0.3 >/dev/null
    rn_add_node n_stream ap sneakernet 10.0.0.4 >/dev/null
    rn_ini_set "node:n_online" status online >/dev/null
    rn_ini_set "node:n_stream" status streaming >/dev/null
    printf 'a\nb\n' > "$RN_SPOOL/n_online.tsv"
    out=$(rn_status_tsv)
    chk status-rows      "$(rcount "$out")" 8
    chk status-total     "$(fld "$out" nodes_total)" 4
    chk status-online    "$(fld "$out" nodes_online)" 2
    chk status-streaming "$(fld "$out" nodes_streaming)" 1
    chk status-events    "$(fld "$out" events_seen)" 2
    chk status-config    "$(fld "$out" config_file)" "$RN_CONFIG"
    chk status-spool     "$(fld "$out" spool_dir)" "$RN_SPOOL"
    chk status-agent     "$(fld "$out" agent_present)" \
        "$([[ -f "$RN_AGENT_SRC" ]] && echo yes || echo no)"

    # 6. spool listing and byte-offset drain
    printf 'e1\ne2\n' > "$RN_SPOOL/node2.tsv"
    out=$(rn_spool_list_tsv)
    chk spool-list-rows   "$(rcount "$out")" 4
    chk spool-list-fields "$(printf '%s\n' "$out" | awk -F'\t' 'NF!=3{c++} END{print c+0}')" 0
    chk spool-list-bytes  "$(printf '%s\n' "$out" | awk -F'\t' '$1=="node2"{print $2}')" 6
    chk spool-list-events "$(printf '%s\n' "$out" | awk -F'\t' '$1=="node2"{print $3}')" 2
    chk spool-list-empty  "$(printf '%s\n' "$out" | awk -F'\t' '$1=="n_stream"{print $2":"$3}')" "0:0"

    out=$(rn_spool_drain node2)
    chk drain-first-content "$(printf '%s\n' "$out" | tr '\n' ' ')" "e1 e2 "
    chk drain-pos-written  "$(cat "$RN_SPOOL/node2.pos")" 6
    out=$(rn_spool_drain node2)
    chk drain-again-empty  "$(printf '%s\n' "$out" | grep -c .)" 0
    printf 'e3\n' >> "$RN_SPOOL/node2.tsv"
    out=$(rn_spool_drain node2)
    chk drain-incremental  "$(printf '%s\n' "$out" | tr '\n' ' ')" "e3 "
    chk drain-pos-updated  "$(cat "$RN_SPOOL/node2.pos")" 9
    printf '\n\n' >> "$RN_SPOOL/node2.tsv"
    out=$(rn_spool_drain node2)
    chk drain-skips-blank  "$(printf '%s\n' "$out" | grep -c .)" 0
    out=$(rn_spool_drain ghost); rc=$?
    chk drain-missing-rc  "$rc" 0
    chk drain-missing-out "$out" ""
    out=$(rn_spool_peek node2 1)
    chk peek-last "$(printf '%s\n' "$out" | grep -c .)" 0
    printf 'p1\np2\np3\n' > "$RN_SPOOL/node2.tsv"
    out=$(rn_spool_peek node2 2)
    chk peek-n     "$(printf '%s\n' "$out" | tr '\n' ' ')" "p2 p3 "
    chk peek-all   "$(rn_spool_peek node2 | grep -c .)" 3

    # 7. whitelist / rules
    printf 'aa:bb\ncc:dd\nee:ff\n' > "$MOD_TMP/wl.txt"
    out=$(rn_whitelist_set n_online "$MOD_TMP/wl.txt"); rc=$?
    chk whitelist-set-rc   "$rc" 0
    chk whitelist-set-says "$(printf '%s\n' "$out" | awk -F'\t' '$1=="SET"{print $2}')" "aa:bb,cc:dd,ee:ff"
    chk whitelist-get      "$(rn_whitelist_get n_online)" "aa:bb,cc:dd,ee:ff"
    rn_whitelist_set n_online "$MOD_TMP/absent.txt" >/dev/null 2>&1
    chk whitelist-missing-rc "$?" 1
    out=$(rn_rules_set n_online "$MOD_TMP/wl.txt"); rc=$?
    chk rules-set-rc "$rc" 0
    chk rules-get    "$(rn_rules_get n_online)" "$MOD_TMP/wl.txt"
    rn_rules_set n_online "$MOD_TMP/absent.txt" >/dev/null 2>&1
    chk rules-missing-rc "$?" 1

    # 8. transport selection and attack/crack role gating (all offline:
    #    every node here uses a transport that cannot reach anything)
    out=$(rn_transport_exec n_online true 2>&1); rc=$?
    chk transport-unknown-rc  "$rc" 1
    chk transport-unknown-msg "$(printf '%s\n' "$out" | awk -F'\t' '$1=="ERROR"{print $2}')" \
        "unknown transport: sneakernet"
    rn_attack_dispatch >/dev/null 2>&1;  chk attack-usage-rc "$?" 2
    rn_attack_dispatch n_online "$MOD_TMP/absent.tsv" >/dev/null 2>&1
    chk attack-nochain-rc "$?" 1
    printf 'step\topen_loot\n' > "$MOD_TMP/chain.tsv"
    out=$(rn_attack_dispatch n_online "$MOD_TMP/chain.tsv" 2>&1); rc=$?
    chk attack-norole-rc  "$rc" 1
    chk attack-norole-msg "$(printf '%s\n' "$out" | awk -F'\t' '$1=="ERROR"{print $2}')" \
        "node n_online has no attacker role"
    rn_ini_set "node:n_online" roles "attacker,sensor" >/dev/null
    out=$(rn_attack_dispatch n_online "$MOD_TMP/chain.tsv" AA:BB 30 2>&1); rc=$?
    chk attack-dispatch-honest "$(printf '%s\n' "$out" | awk -F'\t' '$1=="DISPATCHED"{print $3}')" "rc=1"
    rn_crack_submit n_online "$MOD_TMP/absent.22000" >/dev/null 2>&1
    chk crack-missing-hash-rc "$?" 1
    out=$(rn_crack_submit n_online "$MOD_TMP/wl.txt" 2>&1); rc=$?
    chk crack-norole-rc  "$rc" 1
    chk crack-norole-msg "$(printf '%s\n' "$out" | awk -F'\t' '$1=="ERROR"{print $2}')" \
        "node n_online is not a crack-node"

    # 9. crack queue roll-up
    chk crack-queue-empty "$(rn_crack_queue_tsv | grep -c .)" 0
    out=$(rn_crack_status_tsv)
    chk crack-status-empty "$(fld "$out" total)" 0
    chk crack-status-rows  "$(rcount "$out")" 4
    {
        printf '1\tn1\t/tmp/a.22000\tpending\n'
        printf '2\tn1\t/tmp/b.22000\trunning\n'
        printf '3\tn2\t/tmp/c.22000\tdone\n'
        printf '4\tn2\t/tmp/d.22000\tcracked\n'
    } > "$RN_DATA_DIR/crack_queue.tsv"
    out=$(rn_crack_status_tsv)
    chk crack-total   "$(fld "$out" total)" 4
    chk crack-pending "$(fld "$out" pending)" 1
    chk crack-running "$(fld "$out" running)" 1
    chk crack-done    "$(fld "$out" done)" 2
    chk crack-queue-rows "$(rn_crack_queue_tsv | grep -c .)" 4

    # 10. honeypot
    out=$(rn_honeypot_mode n_online bogus 2>&1); rc=$?
    chk honeypot-badmode-rc  "$rc" 1
    chk honeypot-badmode-msg "$(printf '%s\n' "$out" | awk -F'\t' '$1=="ERROR"{print $2}')" \
        "mode must be off|passive|attack"
    out=$(rn_honeypot_mode n_online off 2>/dev/null); rc=$?
    chk honeypot-off-rc   "$rc" 0
    chk honeypot-off-says "$(printf '%s\n' "$out" | awk -F'\t' '$1=="MODE"{print $2" "$3}')" "n_online off"
    chk honeypot-off-saved "$(rn_ini_get "node:n_online" honeypot_mode)" off
    rn_honeypot_mode n_online passive >/dev/null 2>&1
    chk honeypot-passive-saved "$(rn_ini_get "node:n_online" honeypot_mode)" passive
    chk honeypot-fleet-empty "$(rn_honeypot_fleet_tsv | grep -c .)" 0
    rn_ini_set "node:n_online" capabilities "ap-mode,monitor" >/dev/null
    out=$(rn_honeypot_fleet_tsv)
    chk honeypot-fleet-rows "$(rcount "$out")" 1
    chk honeypot-fleet-fields "$(printf '%s\n' "$out" | awk -F'\t' 'NF!=3{c++} END{print c+0}')" 0
    chk honeypot-fleet-mode "$(printf '%s\n' "$out" | cut -f2)" passive
    rn_ini_set "node:node2" capabilities "ap-mode" >/dev/null
    chk honeypot-fleet-default-mode "$(rn_honeypot_fleet_tsv | awk -F'\t' '$1=="node2"{print $2}')" off
    mkdir -p "$RN_DATA_DIR/honeypot"
    printf 'c1\tc2\n' > "$RN_DATA_DIR/honeypot/node2.clients.tsv"
    printf 'u\tp\n'   > "$RN_DATA_DIR/honeypot/node2.creds.tsv"
    chk honeypot-clients "$(rn_honeypot_clients_tsv node2 | grep -c .)" 1
    chk honeypot-creds   "$(rn_honeypot_creds_tsv node2 | grep -c .)" 1
    chk honeypot-clients-missing "$(rn_honeypot_clients_tsv ghost | grep -c .)" 0
    rn_nexmon_install n_online >/dev/null 2>&1
    chk nexmon-nonphone-rc "$?" 1

    # 11. streams
    rm -f "$RN_STREAMS/node2.pid"
    out=$(rn_stream_status_tsv node2)
    chk stream-status-rows    "$(rcount "$out")" 3
    chk stream-status-running "$(fld "$out" running)" 0
    chk stream-status-bytes   "$(fld "$out" spool_bytes)" "$(wc -c < "$RN_SPOOL/node2.tsv")"
    printf '%s\n' "$$" > "$RN_STREAMS/node2.pid"
    chk stream-status-live "$(fld "$(rn_stream_status_tsv node2)" running)" 1
    rm -f "$RN_STREAMS/node2.pid"
    out=$(rn_stop_stream node2); rc=$?
    chk stream-stop-nopid-rc   "$rc" 0
    chk stream-stop-nopid-says "$(printf '%s\n' "$out" | cut -f2)" 0

    # 12. remove-offline prunes exactly the offline nodes
    rn_add_node n_off ap sneakernet 10.0.0.5 >/dev/null
    rn_add_node n_unreach ap sneakernet 10.0.0.6 >/dev/null
    rn_ini_set "node:n_off" status offline >/dev/null
    rn_ini_set "node:n_unreach" status unreachable >/dev/null
    printf 'x\n' > "$RN_SPOOL/n_off.tsv"
    printf '1\n' > "$RN_STREAMS/n_off.pid"
    out=$(rn_remove_offline)
    chk remove-offline-total   "$(fld "$out" TOTAL_REMOVED)" 2
    chk remove-offline-removed "$(printf '%s\n' "$out" | grep -c $'^REMOVED\t')" 2
    chk remove-offline-gone    "$(rn_ini_get "node:n_off" type)" ""
    chk remove-offline-spool   "$([[ -f "$RN_SPOOL/n_off.tsv" ]] && echo present || echo gone)" gone
    chk remove-offline-pid     "$([[ -f "$RN_STREAMS/n_off.pid" ]] && echo present || echo gone)" gone
    chk remove-offline-keeps   "$(rn_ini_get "node:n_online" type)" ap
    chk remove-offline-keeps-spool "$([[ -f "$RN_SPOOL/n_online.tsv" ]] && echo present || echo gone)" present

    # 13. probe failure is reported, and recorded as unreachable
    out=$(rn_probe_node n_online 2>/dev/null); rc=$?
    chk probe-fail-rc   "$rc" 1
    chk probe-fail-says "$(printf '%s\n' "$out" | grep -c $'^PROBE\tFAIL\treason=agent-not-responding$')" 1
    chk probe-fail-status "$(rn_ini_get "node:n_online" status)" unreachable
    rn_probe_node "" >/dev/null 2>&1; chk probe-no-name-rc "$?" 2

    RN_CONFIG="$s_conf"; RN_SPOOL="$s_spool"; RN_STREAMS="$s_streams"
    RN_LOGS="$s_logs"; RN_DATA_DIR="$s_data"
    rm -rf "$MOD_TMP"
    # role derivation: the rule the wizard relies on
    chk role-sensor   "$(rn_suggest_roles 'wifi')" "sensor"
    chk role-sa       "$(rn_suggest_roles 'monitor,inject')" "sensor,attacker"
    chk role-cracker  "$(rn_suggest_roles 'wifi,gpu')" "sensor,cracker"
    chk role-all      "$(rn_suggest_roles 'monitor,inject,gpu')" "sensor,attacker,cracker"
    chk role-relay    "$(rn_suggest_roles 'always-on')" "relay"
    # a stock phone senses by cell and GPS, and must NOT be a relay
    chk role-phone    "$(rn_suggest_roles 'gps,cellular')" "sensor"
    chk role-gpsonly  "$(rn_suggest_roles 'gps')" "sensor"
    chk role-vps      "$(rn_suggest_roles 'relay,always-on')" "relay"
    chk role-empty    "$(rn_suggest_roles '')" "relay"
    # no role may appear twice - the duplicate was a real bug
    chk role-nodup    "$(rn_suggest_roles 'always-on,gpu' | tr ',' '\n' | sort | uniq -d | wc -l)" 0
    chk presets-count "$(rn_presets_tsv | grep -c .)" 8
    chk setroles-bad  "$(rn_cli_set_roles nosuchnode sensor >/dev/null 2>&1; echo $?)" 1
    chk setroles-typo "$(rn_cli_set_roles self bogusrole >/dev/null 2>&1; echo $?)" 2

    printf 'RESULT\t%s\n' "$([[ $bad -eq 0 ]] && echo PASS || echo "FAIL($bad)")"
    return $(( bad > 0 ))
}

rn_cli_main() {
    local cmd="${1:-}"
    (($# > 0)) && shift
    case "$cmd" in
        --status-tsv)         rn_status_tsv ;;
        --list-nodes-tsv)     rn_list_nodes_tsv ;;
        --add-node)           rn_add_node "$@" ;;
        --remove-node)        rn_remove_node "$@" ;;
        --remove-offline)     rn_remove_offline ;;
        --bulk-probe)         rn_bulk_probe ;;
        --presets-tsv)         rn_presets_tsv ;;
        --suggest-roles-tsv)   rn_cli_suggest_roles_tsv "$@" ;;
        --set-roles)           rn_cli_set_roles "$@" ;;
        --probe-node)         rn_probe_node "$@" ;;
        --node-info-tsv)      rn_node_info_tsv "$@" ;;
        --node-health-tsv)    rn_node_health_tsv "$@" ;;
        --start-stream)       rn_start_stream "$@" ;;
        --stop-stream)        rn_stop_stream "$@" ;;
        --stop-all-streams)   rn_stop_all_streams ;;
        --stream-status-tsv)  rn_stream_status_tsv "$@" ;;
        --spool-list-tsv)     rn_spool_list_tsv ;;
        --spool-drain)        rn_spool_drain "$@" ;;
        --spool-peek)         rn_spool_peek "$@" ;;
        --whitelist-get)      rn_whitelist_get "$@" ;;
        --whitelist-set)      rn_whitelist_set "$@" ;;
        --rules-get)          rn_rules_get "$@" ;;
        --rules-set)          rn_rules_set "$@" ;;
        --attack-dispatch)    rn_attack_dispatch "$@" ;;
        --attack-stop)        rn_attack_stop "$@" ;;
        --crack-queue-tsv)    rn_crack_queue_tsv ;;
        --crack-submit)       rn_crack_submit "$@" ;;
        --crack-status-tsv)   rn_crack_status_tsv ;;
        --honeypot-fleet-tsv) rn_honeypot_fleet_tsv ;;
        --honeypot-mode)      rn_honeypot_mode "$@" ;;
        --honeypot-clients-tsv) rn_honeypot_clients_tsv "$@" ;;
        --honeypot-creds-tsv) rn_honeypot_creds_tsv "$@" ;;
        --nexmon-install)     rn_nexmon_install "$@" ;;
        --selftest)           rn_selftest ;;
        *)
            cat >&2 <<USAGE
Usage: $0 COMMAND
  --status-tsv
  --list-nodes-tsv
  --add-node NAME TYPE TRANSPORT ADDRESS [PORT]
  --remove-node NAME
  --remove-offline
  --bulk-probe
  --probe-node NAME
  --node-info-tsv NAME
  --node-health-tsv NAME
  --start-stream NAME
  --stop-stream NAME
  --stop-all-streams
  --stream-status-tsv NAME
  --spool-list-tsv
  --spool-drain NAME
  --spool-peek NAME [N]
  --whitelist-get NAME
  --whitelist-set NAME FILE
  --rules-get NAME
  --rules-set NAME FILE
  --attack-dispatch NAME CHAIN [BSSID] [DURATION]
  --attack-stop NAME
  --crack-queue-tsv
  --crack-submit NAME HASHFILE
  --crack-status-tsv
  --honeypot-fleet-tsv
  --honeypot-mode NAME off|passive|attack
  --honeypot-clients-tsv NAME
  --honeypot-creds-tsv NAME
  --nexmon-install NAME
  --selftest
USAGE
            return 2 ;;
    esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    set -o pipefail
    declare -F info >/dev/null 2>&1 || info() { printf '[info] %s\n' "$*" >&2; }
    command -v warn >/dev/null 2>&1 || warn() { printf '[warn] %s\n' "$*" >&2; }
    command -v err  >/dev/null 2>&1 || err()  { printf '[err]  %s\n' "$*" >&2; }
    command -v ok   >/dev/null 2>&1 || ok()   { printf '[ok]   %s\n' "$*" >&2; }
    rn_cli_main "$@"
fi
