#!/bin/sh
# ============================================================================================================================
# stunmon.sh - Asus-Merlin stunnel Connection Monitor and Manager
# Version: 0.1.0
# Companion to VPNMON-R3  |  https://github.com/ViktorJp/VPNMON-R3
# ============================================================================================================================
#
# Description:
#   Standalone stunnel lifecycle manager for Asus Merlin routers running Entware. Manages, monitors, and displays stunnel
#   connections for one or more OpenVPN client slots. stunnel wraps OpenVPN TCP traffic inside a genuine TLS session, making
#   it appear as standard HTTPS to deep packet inspection systems. Designed to operate independently of VPNMON-R3 while
#   writing a small status file that VPNMON-R3 can optionally read to show [STUN] in its display and skip monitoring any slot
#   that STUNMON owns.
#
# File layout (created automatically):
#   /jffs/addons/stunmon.d/stunmon.cfg          : user configuration
#   /jffs/addons/stunmon.d/stunmon.status       : live status (read by VPNMON-R3)
#   /jffs/addons/stunmon.d/stunmon.log          : application log
#   /jffs/addons/stunmon.d/configs/slotN.conf   : generated stunnel config
#   /jffs/addons/stunmon.d/configs/slotN.crt    : working CA cert copy
#   /tmp/stunmon/slotN/stunnel.pid              : runtime PID file
#   /tmp/stunmon/slotN/stunnel.log              : stunnel process log
#
# Prerequisites (Entware):
#   opkg install stunnel curl
#
# Usage:
#   stunmon.sh                                  : interactive monitoring display
#   stunmon.sh -setup                           : configuration menu
#   stunmon.sh -start  [slot]                   : start stunnel for slot (default: all)
#   stunmon.sh -stop   [slot]                   : stop  stunnel for slot (default: all)
#   stunmon.sh -restart[slot]                   : restart stunnel for slot
#   stunmon.sh -status [slot]                   : print status; exit 0=running 1=stopped
#   stunmon.sh -check                           : run one health check cycle (cron-callable)
#   stunmon.sh -reset  [slot]                   : stop, remove runtime files, clear errors
#   stunmon.sh -screen [-now]                   : execute script in screen session, use -now to bypass timer/reminder
# ============================================================================================================================

export PATH="/opt/bin:/opt/sbin:/sbin:/bin:/usr/sbin:/usr/bin:$PATH"
unset LD_LIBRARY_PATH

# -- Version -------------------------------------------------------------------
Version="0.1.0"

# Color variables
CBlack="\e[1;30m"
InvBlack="\e[1;40m"
CRed="\e[1;31m"
InvRed="\e[1;41m"
CGreen="\e[1;32m"
InvGreen="\e[1;42m"
CDkGray="\e[1;90m"
InvDkGray="\e[1;100m"
InvLtGray="\e[1;47m"
CYellow="\e[1;33m"
InvYellow="\e[1;43m"
CBlue="\e[1;34m"
InvBlue="\e[1;44m"
CMagenta="\e[1;35m"
CCyan="\e[1;36m"
InvCyan="\e[1;46m"
CWhite="\e[1;37m"
InvWhite="\e[1;107m"
CClear="\e[0m"

# -- Application directories ---------------------------------------------------
APPPATH="/jffs/scripts/stunmon.sh"
STUNMON_DIR="/jffs/addons/stunmon.d"
STUNMON_CFG="${STUNMON_DIR}/stunmon.cfg"
STUNMON_STATUS="${STUNMON_DIR}/stunmon.status"
STUNMON_LOG="${STUNMON_DIR}/stunmon.log"
CONFIGS_DIR="${STUNMON_DIR}/configs"
RUNDIR="/tmp/stunmon"

# -- Global config defaults (overwritten by load_config) ----------------------
STUNMON_MANAGED_SLOTS=""         # space-separated list of slot numbers
STUNMON_LOGRETENTION=2500        # rows to keep log entries
STUNMON_HEALTHINTERVAL=30        # seconds between health checks in display mode
STUNMON_DISPLAY_REFRESH=30       # display auto-refresh interval (seconds)

# -- Runtime state (populated at start / updated by health checks) -------------
DISPLAY_MODE=0                   # 1 when running interactive display loop

# -- Slot-specific variable accessors-------------------------------------------
# Convention: SLOT${N}_VARNAME  e.g. SLOT5_PROVIDER, SLOT5_LOCAL_PORT
# get_sv SLOT VARNAME  -> prints the value
# set_sv SLOT VARNAME VALUE  -> sets the variable
get_sv () { eval echo "\${SLOT${1}_${2}:-}"; }
set_sv () { eval "SLOT${1}_${2}=\"${3}\""; }

# -- Runtime path helpers per slot ---------------------------------------------
slot_rundir  () { echo "${RUNDIR}/slot${1}"; }
slot_pidfile () { echo "${RUNDIR}/slot${1}/stunnel.pid"; }
slot_stlog   () { echo "${RUNDIR}/slot${1}/stunnel.log"; }
slot_conf    () { echo "${CONFIGS_DIR}/slot${1}.conf"; }
slot_cert    () { echo "${CONFIGS_DIR}/slot${1}.crt"; }

# -- Timestamp -----------------------------------------------------------------
ts  () { date +'%b %d %Y %X'; }
tss () { date +'%H:%M:%S'; }     # short form for display

# -- Router identity -----------------------------------------------------------
ROUTERMODEL=$(nvram get model 2>/dev/null)
ROUTERNAME=$(nvram get router_name 2>/dev/null)
ROUTERMODEL=${ROUTERMODEL:-"Unknown"}
ROUTERNAME=${ROUTERNAME:-"Router"}

# -- OpenSSL and stunnel binary locations (populated by find_binaries) ---------
STUNNEL_BIN=""
OPENSSL_BIN=""

# ============================================================================================================================
# Section 1 -- Configuration read / write
# ============================================================================================================================

# Create all required directories
create_dirs () {
    mkdir -p "$STUNMON_DIR" "$ENDPOINTS_DIR" "$CONFIGS_DIR" 2>/dev/null
    chmod 700 "$STUNMON_DIR" 2>/dev/null
}

# Write stunmon.cfg from current globals
save_config () {
    create_dirs
    {
        echo "# stunmon.cfg -- stunnel Connection Manager configuration"
        echo "# Written by stunmon.sh v${Version} on $(ts)"
        echo "# Do not edit manually while stunmon is running."
        echo ""
        echo "# -- Global settings ----------------------------------------------------------"
        echo "STUNMON_MANAGED_SLOTS=\"${STUNMON_MANAGED_SLOTS}\""
        echo "STUNMON_LOGRETENTION=${STUNMON_LOGRETENTION}"
        echo "STUNMON_HEALTHINTERVAL=${STUNMON_HEALTHINTERVAL}"
        echo "STUNMON_DISPLAY_REFRESH=${STUNMON_DISPLAY_REFRESH}"
        echo ""
        echo "# -- Per-slot settings --------------------------------------------------------"
        for S in $STUNMON_MANAGED_SLOTS; do
            echo ""
            echo "# Slot ${S}"
            echo "SLOT${S}_ENABLED=$(get_sv $S ENABLED)"
            echo "SLOT${S}_PROVIDER=\"$(get_sv $S PROVIDER)\""
            echo "SLOT${S}_SSL_CONF=\"$(get_sv $S SSL_CONF)\""
            echo "SLOT${S}_CERT=\"$(get_sv $S CERT)\""
            echo "SLOT${S}_LOCAL_HOST=\"$(get_sv $S LOCAL_HOST)\""
            echo "SLOT${S}_LOCAL_PORT=\"$(get_sv $S LOCAL_PORT)\""
            echo "SLOT${S}_REMOTE_HOST=\"$(get_sv $S REMOTE_HOST)\""
            echo "SLOT${S}_REMOTE_PORT=\"$(get_sv $S REMOTE_PORT)\""
            echo "SLOT${S}_SNI_HOST=\"$(get_sv $S SNI_HOST)\""
            echo "SLOT${S}_DEBUG_LEVEL=$(get_sv $S DEBUG_LEVEL)"
            echo "SLOT${S}_TCP_NODELAY=$(get_sv $S TCP_NODELAY)"
            echo "SLOT${S}_VERIFY=$(get_sv $S VERIFY)"
            echo "SLOT${S}_TIMEOUTCLOSE=$(get_sv $S TIMEOUTCLOSE)"

        done
    } > "$STUNMON_CFG"
}

# Load stunmon.cfg into globals; set defaults for any missing value
load_config () {
    if [ -f "$STUNMON_CFG" ]; then
        # shellcheck disable=SC1090
        . "$STUNMON_CFG"
    fi
    # Apply defaults for any unset globals
    STUNMON_MANAGED_SLOTS="${STUNMON_MANAGED_SLOTS:-}"
    STUNMON_LOGRETENTION="${STUNMON_LOGRETENTION:-2500}"
    STUNMON_HEALTHINTERVAL="${STUNMON_HEALTHINTERVAL:-30}"
    STUNMON_DISPLAY_REFRESH="${STUNMON_DISPLAY_REFRESH:-30}"
    # Apply per-slot defaults for each managed slot
    for S in $STUNMON_MANAGED_SLOTS; do
        [ -z "$(get_sv $S ENABLED)"        ] && set_sv $S ENABLED        1
        [ -z "$(get_sv $S PROVIDER)"       ] && set_sv $S PROVIDER        "Unknown"
        [ -z "$(get_sv $S SSL_CONF)"       ] && set_sv $S SSL_CONF        ""
        [ -z "$(get_sv $S CERT)"           ] && set_sv $S CERT            ""
        [ -z "$(get_sv $S LOCAL_HOST)"     ] && set_sv $S LOCAL_HOST      "127.0.0.1"
        [ -z "$(get_sv $S LOCAL_PORT)"     ] && set_sv $S LOCAL_PORT      "1413"
        [ -z "$(get_sv $S REMOTE_HOST)"    ] && set_sv $S REMOTE_HOST     ""
        [ -z "$(get_sv $S REMOTE_PORT)"    ] && set_sv $S REMOTE_PORT     "443"
        [ -z "$(get_sv $S SNI_HOST)"       ] && set_sv $S SNI_HOST        ""
        [ -z "$(get_sv $S DEBUG_LEVEL)"    ] && set_sv $S DEBUG_LEVEL     0
        [ -z "$(get_sv $S TCP_NODELAY)"    ] && set_sv $S TCP_NODELAY     1
        [ -z "$(get_sv $S VERIFY)"         ] && set_sv $S VERIFY          3
        [ -z "$(get_sv $S TIMEOUTCLOSE)"   ] && set_sv $S TIMEOUTCLOSE    0
        [ -z "$(get_sv $S EP_SOURCE)"      ] && set_sv $S EP_SOURCE       "ssl_file"
        [ -z "$(get_sv $S EP_API_URL)"     ] && set_sv $S EP_API_URL      ""
        [ -z "$(get_sv $S EP_AUTOUPDATE)"  ] && set_sv $S EP_AUTOUPDATE   0
        [ -z "$(get_sv $S EP_UPDATEHOUR)"  ] && set_sv $S EP_UPDATEHOUR   3
        [ -z "$(get_sv $S MAX_RETRIES)"    ] && set_sv $S MAX_RETRIES     3
        [ -z "$(get_sv $S FAIL_COUNT)"     ] && set_sv $S FAIL_COUNT      0
    done
}

# ============================================================================================================================
# Section 2 -- Logging
# ============================================================================================================================

# log LEVEL MESSAGE  -- write to stunmon.log and optionally stdout
# LEVEL: INFO WARN ERROR
slog () {
    local LEVEL="$1"; shift
    local MSG="$*"
    local LINE
    LINE="$(ts) [${LEVEL}] ${MSG}"
    echo "$LINE" >> "$STUNMON_LOG" 2>/dev/null
}

slog_info  () { slog "INFO " "$@"; }
slog_warn  () { slog "WARN " "$@"; }
slog_error () { slog "ERROR" "$@"; }

# -------------------------------------------------------------------------------------------------------------------------
# trimlogs will cut down log size (in rows) based on custom value

trimlogs () {

  if [ -f "$STUNMON_LOG" ]
  then
      currlogsize="$(wc -l "$STUNMON_LOG" | awk '{ print $1 }')" # Determine the number of rows in the log

      if [ "$currlogsize" -gt "$STUNMON_LOGRETENTION" ] # If it's bigger than the max allowed, tail/trim it!
      then
          tail -"$STUNMON_LOGRETENTION" "$STUNMON_LOG" > "${STUNMON_LOG}.tmp"
          mv "${STUNMON_LOG}.tmp" "$STUNMON_LOG"
      fi
  fi
}

# -------------------------------------------------------------------------------------------------------------------------
# vlogs is a function that calls the nano text editor to view the BACKUPMON log file

display_full_log () {

export TERM=linux
nano +999999 --linenumbers $STUNMON_LOG

}

# ============================================================================================================================
# Section 3 -- Binary detection
# ============================================================================================================================

find_binaries () {
    STUNNEL_BIN=""
    for p in /opt/bin/stunnel /usr/bin/stunnel /usr/local/bin/stunnel; do
        [ -x "$p" ] && STUNNEL_BIN="$p" && break
    done

    OPENSSL_BIN=""
    if which openssl >/dev/null 2>&1; then
        OPENSSL_BIN=$(which openssl)
    elif [ -x /opt/bin/openssl ]; then OPENSSL_BIN="/opt/bin/openssl"
    elif [ -x /usr/sbin/openssl ]; then OPENSSL_BIN="/usr/sbin/openssl"
    elif [ -x /usr/bin/openssl ];  then OPENSSL_BIN="/usr/bin/openssl"
    fi
}

# ============================================================================================================================
# Section 4 -- stunnel lifecycle
# ============================================================================================================================

# Is the stunnel process for slot N alive?
stunmon_alive () {
    local SLOT="$1"
    local PF; PF=$(slot_pidfile "$SLOT")
    [ ! -f "$PF" ] && return 1
    local PID; PID=$(cat "$PF" 2>/dev/null)
    [ -z "$PID" ] && return 1
    kill -0 "$PID" 2>/dev/null
}

# Return PID for slot N (empty if not running)
stunmon_pid () {
    local SLOT="$1"
    local PF; PF=$(slot_pidfile "$SLOT")
    [ -f "$PF" ] && cat "$PF" 2>/dev/null || echo ""
}

# Start stunnel for slot N -- launches in foreground mode with &
stunmon_start () {
    local SLOT="$1"
    local RD; RD=$(slot_rundir "$SLOT")
    local PF; PF=$(slot_pidfile "$SLOT")
    local CF; CF=$(slot_conf "$SLOT")
    local LF; LF=$(slot_stlog "$SLOT")

    if stunmon_alive "$SLOT"; then
        slog_warn "stunmon_start slot${SLOT}: already running (PID: $(stunmon_pid $SLOT))"
        return 0
    fi

    if [ ! -f "$CF" ]; then
        slog_error "stunmon_start slot${SLOT}: config file not found: ${CF}"
        return 1
    fi
    if [ -z "$STUNNEL_BIN" ]; then
        slog_error "stunmon_start slot${SLOT}: stunnel binary not found"
        return 1
    fi

    mkdir -p "$RD" 2>/dev/null

    # Launch stunnel in foreground mode as background job.
    # foreground=yes means it doesn't daemonise; & returns control to script.
    # stdout+stderr go to the stunnel log file.
    "$STUNNEL_BIN" "$CF" >> "$LF" 2>&1 &
    local BG_PID=$!

    # Write PID immediately as a bootstrap; stunnel's own pid= directive
    # will confirm/overwrite once it initialises.
    echo "$BG_PID" > "$PF"

    # Wait for stunnel to bind its local port (up to 8 seconds)
    local WAIT=0
    local LP; LP=$(get_sv "$SLOT" LOCAL_PORT)
    while [ "$WAIT" -lt 8 ]; do
        sleep 1; WAIT=$((WAIT+1))
        if stunmon_alive "$SLOT" && netstat -tln 2>/dev/null | grep -q ":${LP} "; then
            break
        fi
    done

    if stunmon_alive "$SLOT"; then
        slog_info "stunmon_start slot${SLOT}: started (PID: $BG_PID, port: ${LP})"
        # Probe TLS session info in the background so get_tls_info can read
        # it without blocking the display loop. Existing cache is preserved so
        # the display shows the last known TLS version rather than "?" during
        # the probe window. The probe overwrites the cache when it completes.
        probe_tls_info "$SLOT" &
        update_status_file
        return 0
    else
        slog_error "stunmon_start slot${SLOT}: process died during startup -- check $(slot_stlog $SLOT)"
        rm -f "$PF"
        return 1
    fi
    trimlogs
}

# Stop stunnel for slot N gracefully (SIGTERM, then SIGKILL)
stunmon_stop () {
    local SLOT="$1"
    local PF; PF=$(slot_pidfile "$SLOT")

    if ! stunmon_alive "$SLOT"; then
        slog_info "stunmon_stop slot${SLOT}: already stopped"
        rm -f "$PF"
        return 0
    fi

    local PID; PID=$(stunmon_pid "$SLOT")
    slog_info "stunmon_stop slot${SLOT}: sending SIGTERM to PID ${PID}"
    kill -TERM "$PID" 2>/dev/null
    sleep 2

    if stunmon_alive "$SLOT"; then
        slog_warn "stunmon_stop slot${SLOT}: SIGTERM ignored, sending SIGKILL"
        kill -9 "$PID" 2>/dev/null
        sleep 1
    fi

    rm -f "$PF"
    # tls_cache preserved intentionally -- TLS parameters survive a restart
    # and the display should show the last known value rather than "?"
    # Cache is only invalidated by generate_stunnel_conf when endpoint changes
    slog_info "stunmon_stop slot${SLOT}: stopped"
    update_status_file
    trimlogs
    return 0
}

# Restart stunnel for slot N
stunmon_restart () {
    local SLOT="$1"
    slog_info "stunmon_restart slot${SLOT}: restarting"
    stunmon_stop "$SLOT"
    sleep 1
    generate_stunnel_conf "$SLOT" && record_start_time "$SLOT" && stunmon_start "$SLOT"
    trimlogs
}

# Print status for slot N; return 0=running 1=stopped
stunmon_status () {
    local SLOT="$1"
    if stunmon_alive "$SLOT"; then
        local PID; PID=$(stunmon_pid "$SLOT")
        local LP; LP=$(get_sv "$SLOT" LOCAL_PORT)
        local RH; RH=$(get_sv "$SLOT" REMOTE_HOST)
        local RP; RP=$(get_sv "$SLOT" REMOTE_PORT)
        echo "slot${SLOT}: RUNNING  PID=${PID}  ${LP} -> ${RH}:${RP}"
        return 0
    else
        echo "slot${SLOT}: STOPPED"
        return 1
    fi
}

# ============================================================================================================================
# Section 5 -- Config file parsing and generation
# ============================================================================================================================

# Parse a provider .ssl file to extract connection parameters for slot N
parse_ssl_conf () {
    local SLOT="$1"
    local SSL_CONF; SSL_CONF=$(get_sv "$SLOT" SSL_CONF)

    [ -z "$SSL_CONF" ] && return 1
    [ ! -f "$SSL_CONF" ] && return 1

    local ACCEPT_LINE CONNECT_LINE
    ACCEPT_LINE=$(grep -i '^ *accept'  "$SSL_CONF" | head -1 | sed 's/.*= *//')
    CONNECT_LINE=$(grep -i '^ *connect' "$SSL_CONF" | head -1 | sed 's/.*= *//')

    local LH LP RH RP
    LH=$(echo "$ACCEPT_LINE"  | cut -d: -f1)
    LP=$(echo "$ACCEPT_LINE"  | cut -d: -f2)
    RH=$(echo "$CONNECT_LINE" | cut -d: -f1)
    RP=$(echo "$CONNECT_LINE" | cut -d: -f2)

    set_sv "$SLOT" LOCAL_HOST  "${LH:-127.0.0.1}"
    set_sv "$SLOT" LOCAL_PORT  "${LP:-1413}"
    [ -n "$RH" ] && set_sv "$SLOT" REMOTE_HOST "$RH"
    [ -n "$RP" ] && set_sv "$SLOT" REMOTE_PORT "$RP"

    return 0
}

# Generate the stunnel config for slot N into CONFIGS_DIR/slotN.conf
generate_stunnel_conf () {
    local SLOT="$1"
    create_dirs
    mkdir -p "$CONFIGS_DIR" 2>/dev/null

    local CF; CF=$(slot_conf "$SLOT")
    local CERTF; CERTF=$(slot_cert "$SLOT")
    local PF; PF=$(slot_pidfile "$SLOT")
    local LF; LF=$(slot_stlog "$SLOT")
    local RD; RD=$(slot_rundir "$SLOT")

    mkdir -p "$RD" 2>/dev/null

    # Copy CA cert to working location
    local CERT_SRC; CERT_SRC=$(get_sv "$SLOT" CERT)
    if [ -n "$CERT_SRC" ] && [ -f "$CERT_SRC" ]; then
        cp "$CERT_SRC" "$CERTF" 2>/dev/null
    elif [ ! -f "$CERTF" ]; then
        slog_error "generate_conf slot${SLOT}: CA cert not found: ${CERT_SRC}"
        return 1
    fi

    local LH; LH=$(get_sv "$SLOT" LOCAL_HOST)
    local LP; LP=$(get_sv "$SLOT" LOCAL_PORT)
    local RH; RH=$(get_sv "$SLOT" REMOTE_HOST)
    local RP; RP=$(get_sv "$SLOT" REMOTE_PORT)
    local SNI; SNI=$(get_sv "$SLOT" SNI_HOST)
    local DBG; DBG=$(get_sv "$SLOT" DEBUG_LEVEL)
    local NDLY; NDLY=$(get_sv "$SLOT" TCP_NODELAY)
    local VFY; VFY=$(get_sv "$SLOT" VERIFY)
    local TCO; TCO=$(get_sv "$SLOT" TIMEOUTCLOSE)

    DBG=${DBG:-0}
    NDLY=${NDLY:-1}
    VFY=${VFY:-3}
    TCO=${TCO:-0}

    # Endpoint comes directly from REMOTE_HOST / REMOTE_PORT (single endpoint, no list)

    cat > "$CF" << EOF
# stunmon generated stunnel config -- slot ${SLOT}
# Provider : $(get_sv $SLOT PROVIDER)
# Generated: $(ts)
# Do not edit manually -- regenerated by stunmon on each start/restart.

; Process management
pid    = ${PF}
output = ${LF}

; Connection mode
foreground = yes
client     = yes
; debug = 0 (silent/production). Use stunmon -setup to change.
debug      = ${DBG}

[vpn-slot${SLOT}]
accept       = ${LH}:${LP}
connect      = ${RH}:${RP}
TIMEOUTclose = ${TCO}
verify       = ${VFY}
CAfile       = ${CERTF}
EOF

    # TCP_NODELAY -- disables Nagle on both sockets, critical for TCP-over-TCP
    if [ "$NDLY" = "1" ]; then
        echo "socket       = l:TCP_NODELAY=1" >> "$CF"
        echo "socket       = r:TCP_NODELAY=1" >> "$CF"
    fi

    # SNI hostname obfuscation
    if [ -n "$SNI" ]; then
        echo "sni          = ${SNI}" >> "$CF"
    fi

    # Invalidate TLS cache when a new config is generated -- the endpoint
    # may have changed (e.g. after rotate_endpoint), so a fresh probe is needed
    rm -f "$(slot_rundir $SLOT)/tls_cache" 2>/dev/null
    slog_info "generate_conf slot${SLOT}: wrote ${CF} (endpoint: ${RH}:${RP})"
    return 0
}

# ============================================================================================================================
# Section 6 -- Endpoint list management
# ============================================================================================================================

# Return the current endpoint for slot N (host:port or empty)
get_current_endpoint () {
    local SLOT="$1"
    local RH; RH=$(get_sv "$SLOT" REMOTE_HOST)
    local RP; RP=$(get_sv "$SLOT" REMOTE_PORT)
    [ -z "$RH" ] && return 0
    echo "${RH}:${RP}"
}

# ============================================================================================================================
# Section 7 -- Health check and VPNMON-R3 status file
# ============================================================================================================================

# Probe SSL connectivity through the VPN tunnel interface for slot N
probe_ssl_via_tun () {
    local SLOT="$1"
    local TUNIF="tun1${SLOT}"
    local TUN_IP
    TUN_IP=$(ip addr show "$TUNIF" 2>/dev/null | grep 'inet ' | awk '{print $2}' | cut -d/ -f1)
    [ -z "$TUN_IP" ] && return 1

    local CODE
    CODE=$(curl -s --max-time 8 --connect-timeout 5 \
        --interface "$TUNIF" -o /dev/null -w "%{http_code}" \
        "https://www.google.com/" 2>/dev/null)
    [ -n "$CODE" ] && [ "$CODE" != "000" ] && return 0
    return 1
}

# Get OpenVPN state for slot N from nvram
get_vpn_state () {
    local SLOT="$1"
    nvram get "vpn_client${SLOT}_state" 2>/dev/null
}

# Read cached TLS session info for slot N.
# The cache is written by probe_tls_info (called from stunmon_start).
# Returns: TLS_VERSION|CIPHER_SUITE  or  "?|?" if not yet available.
# NEVER does blocking network I/O.
get_tls_info () {
    local SLOT="$1"
    local CACHEF; CACHEF="$(slot_rundir $SLOT)/tls_cache"
    local LF;     LF=$(slot_stlog "$SLOT")

    # 1. Cache file (written by background probe or from stunnel log)
    if [ -f "$CACHEF" ]; then
        cat "$CACHEF" 2>/dev/null
        return
    fi

    # 2. stunnel log -- only has data when debug >= 5; never available at debug=0
    if [ -f "$LF" ]; then
        local TLS CIPHER
        TLS=$(grep "TLSv1\." "$LF" 2>/dev/null | tail -1 | sed "s/.*\(TLSv1\.[0-9]\).*/\1/" | grep "^TLSv")
        CIPHER=$(grep "ciphersuite:" "$LF" 2>/dev/null | tail -1 | sed "s/.*ciphersuite: //" | cut -d" " -f1)
        if [ -n "$TLS" ] && [ -n "$CIPHER" ]; then
            echo "${TLS}|${CIPHER}" > "$CACHEF" 2>/dev/null
            echo "${TLS}|${CIPHER}"
            return
        fi
    fi

    echo "?|?"
}

# Probe the remote stunnel server with openssl s_client and cache the TLS result.
# Designed to be called as a BACKGROUND job from stunmon_start so it never
# blocks the display loop. Writes to /tmp/stunmon/slotN/tls_cache on success.
probe_tls_info () {
    local SLOT="$1"
    local RH; RH=$(get_sv "$SLOT" REMOTE_HOST)
    local RP; RP=$(get_sv "$SLOT" REMOTE_PORT)
    local CACHEF; CACHEF="$(slot_rundir $SLOT)/tls_cache"
    local TMPF;   TMPF="$(slot_rundir $SLOT)/tls_probe.tmp"

    [ -z "$OPENSSL_BIN" ] && return 1
    [ -z "$RH" ]          && return 1

    # Short wait for stunnel to fully bind before we probe
    sleep 2

    # Write to a temp file to avoid BusyBox pipe-in-$() buffering issues where
    # the subshell may not receive all bytes before the pipe closes.
    rm -f "$TMPF" 2>/dev/null
    local CERTF; CERTF=$(slot_cert "$SLOT")
    local CAOPT=""
    [ -f "$CERTF" ] && CAOPT="-CAfile ${CERTF}"
    # shellcheck disable=SC2086
    sleep 3 | "$OPENSSL_BIN" s_client \
        -connect "${RH}:${RP}" ${CAOPT} > "$TMPF" 2>&1

    local SSL_OUT
    SSL_OUT=$(cat "$TMPF" 2>/dev/null)
    rm -f "$TMPF" 2>/dev/null

    local TLS="" CIPHER=""

    # Format A (most reliable in OpenSSL 1.1.1):
    # "New, TLSv1.2, Cipher is ECDHE-RSA-AES256-GCM-SHA384"
    # This line appears right after the handshake completes.
    local NEW_LINE
    NEW_LINE=$(echo "$SSL_OUT" | grep "^New,")
    if [ -n "$NEW_LINE" ]; then
        TLS=$(echo    "$NEW_LINE" | sed "s/New, //" | cut -d, -f1 | tr -d " 
")
        CIPHER=$(echo "$NEW_LINE" | sed "s/.*Cipher is //"          | tr -d " 
")
    fi

    # Format B: SSL-Session block
    #   "    Protocol  : TLSv1.2"
    #   "    Cipher    : ECDHE-RSA-AES256-GCM-SHA384"
    if [ -z "$TLS" ]; then
        TLS=$(echo "$SSL_OUT" | grep "Protocol" | grep "TLSv" |               sed "s/.*: *//" | tr -d " 
" | sed -n '2p')
    fi
    if [ -z "$CIPHER" ]; then
        CIPHER=$(echo "$SSL_OUT" | grep "Cipher" | grep -v "Protocol\|Cipher Suite\|Ciphers\|NONE" |                  sed "s/.*: *//" | tr -d " 
" | grep "^[A-Z]" | sed -n '2p')
    fi

    # Format C: "TLSv" anywhere in the output as a last resort
    if [ -z "$TLS" ]; then
        TLS=$(echo "$SSL_OUT" | grep -o "TLSv[0-9][.][0-9][0-9]*" | sed -n '2p')
    fi

    if [ -n "$TLS" ]; then
        local RESULT="${TLS}|${CIPHER:-n/a}"
        echo "$RESULT" > "$CACHEF"
        slog_info "probe_tls slot${SLOT}: ${TLS} ${CIPHER}"
    else
        # Log first 5 lines of actual openssl output to aid diagnosis
        local DBGLINES
        DBGLINES=$(echo "$SSL_OUT" | head -5 | tr '
' '|')
        slog_warn "probe_tls slot${SLOT}: TLS version not found in output: ${DBGLINES}"
    fi
}


# Get bytes transferred through the VPN tunnel interface for slot N.
# Reads from the kernel tun interface statistics -- the same source Merlin uses
# in its UI. Falls back to zero if the interface is not up.
# Returns: TX_BYTES|RX_BYTES  (as raw integers)
get_tunnel_bytes () {
    local SLOT="$1"
    local TUNIF="tun1${SLOT}"
    local STATS="/sys/class/net/${TUNIF}/statistics"

    local TX=0 RX=0
    if [ -f "${STATS}/tx_bytes" ]; then
        TX=$(cat "${STATS}/tx_bytes" 2>/dev/null); TX=${TX:-0}
        RX=$(cat "${STATS}/rx_bytes" 2>/dev/null); RX=${RX:-0}
    else
        # Fallback: parse ifconfig output (works if /sys is unavailable)
        local IFOUT; IFOUT=$(ifconfig "$TUNIF" 2>/dev/null)
        if [ -n "$IFOUT" ]; then
            TX=$(echo "$IFOUT" | grep -i "tx bytes\|bytes:" |                 grep -oE "TX bytes:[0-9]+" | cut -d: -f2 ||                 echo "$IFOUT" | awk "/TX/{print \$6}" 2>/dev/null)
            RX=$(echo "$IFOUT" | grep -i "rx bytes\|bytes:" |                 grep -oE "RX bytes:[0-9]+" | cut -d: -f2 ||                 echo "$IFOUT" | awk "/RX/{print \$2}" 2>/dev/null)
        fi
    fi
    echo "${TX:-0}|${RX:-0}"
}

# Format bytes as human-readable string
format_bytes () {
    local B="$1"
    if [ "${B:-0}" -ge 1073741824 ]; then
        awk "BEGIN {printf \"%.1fGB\", $B/1073741824}"
    elif [ "${B:-0}" -ge 1048576 ]; then
        awk "BEGIN {printf \"%.1fMB\", $B/1048576}"
    elif [ "${B:-0}" -ge 1024 ]; then
        awk "BEGIN {printf \"%.1fKB\", $B/1024}"
    else
        echo "${B}B"
    fi
}

# Compute uptime string from start timestamp stored in runtime dir
get_uptime () {
    local SLOT="$1"
    local STARTF; STARTF="$(slot_rundir $SLOT)/start_epoch"
    [ ! -f "$STARTF" ] && printf "--:--" && return
    local START; START=$(cat "$STARTF" 2>/dev/null)
    [ -z "$START" ] && printf "--:--" && return
    local NOW; NOW=$(date +%s)
    local SECS=$(( NOW - START ))
    local D=$(( SECS / 86400 ))
    local H=$(( (SECS % 86400) / 3600 ))
    local M=$(( (SECS % 3600) / 60 ))
    printf "%dd %02dh:%02dm" "$D" "$H" "$M"
}

# Record start time for a slot
record_start_time () {
    local SLOT="$1"
    date +%s > "$(slot_rundir $SLOT)/start_epoch" 2>/dev/null
}

# Write VPNMON-R3-compatible status file
update_status_file () {
    create_dirs
    {
        echo "# stunmon.status -- written by stunmon.sh v${Version}"
        echo "# Updated: $(ts)"
        echo "# Source this file in VPNMON-R3 to detect stunnel-managed slots."
        echo ""
        echo "STUNMON_MANAGED_SLOTS=\"${STUNMON_MANAGED_SLOTS}\""
        echo ""
        for S in $STUNMON_MANAGED_SLOTS; do
            local STATE="STOPPED"
            stunmon_alive "$S" && STATE="RUNNING"
            local PID; PID=$(stunmon_pid "$S")
            local TLS_INFO; TLS_INFO=$(get_tls_info "$S")
            local TLS; TLS=$(echo "$TLS_INFO" | cut -d'|' -f1)
            local CIPHER; CIPHER=$(echo "$TLS_INFO" | cut -d'|' -f2)
            local SNI; SNI=$(get_sv "$S" SNI_HOST)
            local UPTIME; UPTIME=$(get_uptime "$S")
            local EP; EP=$(get_current_endpoint "$S")
            [ -z "$EP" ] && EP="$(get_sv $S REMOTE_HOST):$(get_sv $S REMOTE_PORT)"
            local VPN_STATE; VPN_STATE=$(get_vpn_state "$S")
            local BYTES; BYTES=$(get_tunnel_bytes "$S")
            local BSENT; BSENT=$(echo "$BYTES" | cut -d'|' -f1)
            local BRECV; BRECV=$(echo "$BYTES" | cut -d'|' -f2)
            echo "STUNMON_SLOT${S}_STATE=\"${STATE}\""
            echo "STUNMON_SLOT${S}_PID=\"${PID:-}\""
            echo "STUNMON_SLOT${S}_TLS=\"${TLS:-?}\""
            echo "STUNMON_SLOT${S}_CIPHER=\"${CIPHER:-?}\""
            echo "STUNMON_SLOT${S}_SNI=\"${SNI:-}\""
            echo "STUNMON_SLOT${S}_UPTIME=\"${UPTIME}\""
            echo "STUNMON_SLOT${S}_ENDPOINT=\"${EP}\""
            echo "STUNMON_SLOT${S}_VPN_STATE=\"${VPN_STATE:-?}\""
            echo "STUNMON_SLOT${S}_BYTES_SENT=\"$(format_bytes $BSENT)\""
            echo "STUNMON_SLOT${S}_BYTES_RECV=\"$(format_bytes $BRECV)\""
            echo "STUNMON_SLOT${S}_PROVIDER=\"$(get_sv $S PROVIDER)\""
            echo ""
        done
    } > "$STUNMON_STATUS"
}

# ── City name lookup (cached by egress IP) ────────────────────────────────────
# Cache file: /tmp/stunmon/slotN/city_cache  format: EGRESS_IP|CITY_NAME
# update_slot_city: get current egress IP via tun, compare to cache.
# If egress IP changed (or cache missing), query ip-api.com for the city.
# Designed to be called in the background (&) so it never blocks the display.
update_slot_city () {
    local SLOT="$1"
    local TUNIF="tun1${SLOT}"
    local RUNDIR_S; RUNDIR_S=$(slot_rundir "$SLOT")
    local CACHEF; CACHEF="${RUNDIR_S}/city_cache"

    # Ensure the slot runtime directory exists before writing cache
    mkdir -p "$RUNDIR_S" 2>/dev/null

    # Only proceed when VPN is actually connected
    local VPN_ST; VPN_ST=$(get_vpn_state "$SLOT")
    if [ "$VPN_ST" != "2" ]; then
        slog_info "city_lookup slot${SLOT}: VPN state=${VPN_ST} (not connected), skipping"
        return 1
    fi

    # Verify the tun interface is up and has an IP
    local TUN_IP
    TUN_IP=$(ip addr show "$TUNIF" 2>/dev/null | grep 'inet ' | awk '{print $2}' | cut -d/ -f1)
    if [ -z "$TUN_IP" ]; then
        slog_info "city_lookup slot${SLOT}: ${TUNIF} has no IP, skipping"
        return 1
    fi

    # Try multiple services to get the public egress IP via the VPN tunnel.
    # Falls back to the configured endpoint IP if all external lookups fail.
    local EGRESS=""
    EGRESS=$(curl -s --max-time 6 --connect-timeout 4 \
        --interface "$TUNIF" "https://api.ipify.org" 2>/dev/null | tr -d ' \n\r')
    if [ -z "$EGRESS" ]; then
        EGRESS=$(curl -s --max-time 6 --connect-timeout 4 \
            --interface "$TUNIF" "https://icanhazip.com" 2>/dev/null | tr -d ' \n\r')
    fi
    if [ -z "$EGRESS" ]; then
        # Last resort: use the configured stunnel endpoint IP for city lookup
        EGRESS=$(get_sv "$SLOT" REMOTE_HOST)
        [ -n "$EGRESS" ] && slog_info "city_lookup slot${SLOT}: egress lookup failed, using endpoint IP ${EGRESS}"
    fi
    if [ -z "$EGRESS" ]; then
        slog_warn "city_lookup slot${SLOT}: could not determine egress IP, giving up"
        return 1
    fi

    # Read cached values
    local CACHED_EGRESS="" CACHED_CITY=""
    if [ -f "$CACHEF" ]; then
        CACHED_EGRESS=$(cut -d'|' -f1 "$CACHEF" 2>/dev/null)
        CACHED_CITY=$(cut -d'|' -f2 "$CACHEF" 2>/dev/null)
    fi

    # Cache hit: egress IP unchanged and city is known -- no lookup needed
    if [ "$EGRESS" = "$CACHED_EGRESS" ] && [ -n "$CACHED_CITY" ]; then
        return 0
    fi

    # New egress IP (or first run) -- query ip-api.com for city name
    slog_info "city_lookup slot${SLOT}: querying city for ${EGRESS}"
    local CITY="" API_RESP
    API_RESP=$(curl --silent --fail --max-time 10 --retry 2 --retry-delay 2 \
        "http://ip-api.com/json/${EGRESS}?fields=city" 2>/dev/null)

    if [ -n "$API_RESP" ]; then
        if which jq >/dev/null 2>&1; then
            CITY=$(echo "$API_RESP" | jq -r '.city // empty' 2>/dev/null)
        fi
        if [ -z "$CITY" ] || [ "$CITY" = "null" ]; then
            CITY=$(echo "$API_RESP" | sed 's/.*"city":"\([^"]*\)".*/\1/' 2>/dev/null)
        fi
    fi
    [ -z "$CITY" ] || [ "$CITY" = "null" ] && CITY="Unknown"

    # Persist result to cache file
    echo "${EGRESS}|${CITY}" > "$CACHEF"
    slog_info "city_lookup slot${SLOT}: ${EGRESS} -> ${CITY}"
    return 0
}

# Read the cached city name for a slot (returns empty string if not yet cached)
get_cached_city () {
    local SLOT="$1"
    local CACHEF; CACHEF="$(slot_rundir $SLOT)/city_cache"
    [ ! -f "$CACHEF" ] && return
    cut -d'|' -f2 "$CACHEF" 2>/dev/null
}

# Run one health check cycle for all managed slots
health_check_all () {
    for S in $STUNMON_MANAGED_SLOTS; do
        [ "$(get_sv $S ENABLED)" = "0" ] && continue
        health_check_slot "$S"
    done
    update_status_file
    # Refresh city/egress cache in the background -- non-blocking
    for S in $STUNMON_MANAGED_SLOTS; do
        [ "$(get_sv $S ENABLED)" = "0" ] && continue
        update_slot_city "$S" &
    done
}

# Health check logic for one slot.
#
# Three independent checks are run each cycle:
#   A -- stunnel process alive (kill -0 on PID file)
#   B -- OpenVPN client state = 2 (nvram vpn_clientN_state)
#   C -- SSL probe through the tun interface (curl via tun1N)
#
# Recovery matrix:
#   A=1 B=1 C=1  Healthy -- no action
#   A=0 B=1      stunnel died while VPN thinks it's up -- restart both
#   A=1 B=0      VPN dropped (manual stop, crash, timeout) -- restart VPN
#   A=1 B=1 C=0  Both up but no traffic -- full restart
#   else         Full failure -- restart both, give up after MAX_R attempts
#
# This function is called automatically every STUNMON_DISPLAY_REFRESH seconds
# by the display loop timeout, and also on-demand via the -check cron mode.
health_check_slot () {
    local SLOT="$1"
    local A=0 B=0 C=0

    # Capture actual state values for use in log messages
    local VPN_ST; VPN_ST=$(get_vpn_state "$SLOT")
    local PID;    PID=$(stunmon_pid "$SLOT")

    stunmon_alive "$SLOT"                && A=1
    [ "$VPN_ST" = "2" ]                 && B=1
    probe_ssl_via_tun "$SLOT"            && C=1

    local FC=0 MAX_R=3

    if [ "$A" = "1" ] && [ "$B" = "1" ] && [ "$C" = "1" ]; then
        # Fully healthy -- reset consecutive-failure counter and return
        slog_info "health_check slot${SLOT}: PASS -- stunnel=UP(${PID}) vpn=${VPN_ST} ssl=OK"
        set_sv "$SLOT" FAIL_COUNT 0
        return 0
    fi

    # ── Failure detected -- log it and take recovery action ──────────────────

    if [ "$A" = "0" ] && [ "$B" = "1" ]; then
        # stunnel process died while OpenVPN still reports connected.
        # Restart stunnel first, then cycle OpenVPN so it reconnects through it.
        FC=$((FC+1)); set_sv "$SLOT" FAIL_COUNT "$FC"
        slog_warn "health_check slot${SLOT}: FAIL -- stunnel=DOWN vpn=${VPN_ST} (attempt ${FC}/${MAX_R})"
        slog_warn "health_check slot${SLOT}: RECOVERY -- restarting stunnel then stopping/starting OpenVPN"
        stunmon_stop "$SLOT"
        service "stop_vpnclient${SLOT}" >/dev/null 2>&1; sleep 2
        generate_stunnel_conf "$SLOT" && record_start_time "$SLOT" && stunmon_start "$SLOT"
        service "start_vpnclient${SLOT}" >/dev/null 2>&1
        slog_info "health_check slot${SLOT}: RECOVERY complete -- stunnel restarted, OpenVPN restart issued"

    elif [ "$A" = "1" ] && [ "$B" = "0" ]; then
        # OpenVPN dropped (manual stop, keepalive timeout, or crash).
        # stunnel is still healthy so we only need to restart OpenVPN.
        FC=$((FC+1)); set_sv "$SLOT" FAIL_COUNT "$FC"
        slog_warn "health_check slot${SLOT}: FAIL -- vpn=DOWN(state=${VPN_ST}) stunnel=UP (attempt ${FC}/${MAX_R})"
        slog_warn "health_check slot${SLOT}: RECOVERY -- stopping then starting vpnclient${SLOT}"
        service "stop_vpnclient${SLOT}" >/dev/null 2>&1; sleep 2
        service "start_vpnclient${SLOT}" >/dev/null 2>&1
        slog_info "health_check slot${SLOT}: RECOVERY complete -- OpenVPN restart issued, awaiting state=2"

    elif [ "$A" = "1" ] && [ "$B" = "1" ] && [ "$C" = "0" ]; then
        # Both stunnel and OpenVPN report up but traffic test fails.
        # Full restart: the tunnel is stale or the route is broken.
        FC=$((FC+1)); set_sv "$SLOT" FAIL_COUNT "$FC"
        slog_warn "health_check slot${SLOT}: FAIL -- stunnel=UP vpn=${VPN_ST} ssl=FAIL (attempt ${FC}/${MAX_R})"
        slog_warn "health_check slot${SLOT}: RECOVERY -- full restart (stunnel + OpenVPN)"
        stunmon_stop "$SLOT"; sleep 1
        service "stop_vpnclient${SLOT}" >/dev/null 2>&1; sleep 2
        generate_stunnel_conf "$SLOT" && record_start_time "$SLOT" && stunmon_start "$SLOT"
        service "start_vpnclient${SLOT}" >/dev/null 2>&1
        slog_info "health_check slot${SLOT}: RECOVERY complete -- full restart issued"

    else
        # Both stunnel and OpenVPN are down simultaneously.
        FC=$((FC+1)); set_sv "$SLOT" FAIL_COUNT "$FC"
        slog_error "health_check slot${SLOT}: FAIL -- stunnel=DOWN vpn=${VPN_ST} ssl=FAIL (attempt ${FC}/${MAX_R})"
        if [ "$FC" -ge "$MAX_R" ]; then
            slog_error "health_check slot${SLOT}: GIVING UP -- ${FC} consecutive failures, manual intervention required"
            return 1
        fi
        slog_warn "health_check slot${SLOT}: RECOVERY -- full restart (stunnel + OpenVPN)"
        service "stop_vpnclient${SLOT}" >/dev/null 2>&1; sleep 2
        generate_stunnel_conf "$SLOT" && record_start_time "$SLOT" && stunmon_start "$SLOT"
        service "start_vpnclient${SLOT}" >/dev/null 2>&1
        slog_info "health_check slot${SLOT}: RECOVERY complete -- full restart issued"
    fi

    return 1
}

# ============================================================================================================================
# Section 9 -- Display helper functions
# ============================================================================================================================

# Spinner is a script that provides a small indicator on the screen to show script activity

spinner()
{
  spins=$1

  spin=0
  charspin=0
  totalspins=$((spins / 4))
  while [ $spin -le $totalspins ]; do
    for spinchar in / - \\ \|; do
      printf "\r$spinchar ${CGreen}[${CWhite}$charspin${CGreen}]"
      charspin=$((charspin + 1))
      sleep 1
    done
    spin=$((spin+1))
  done

  printf "\r"
}

# Draw a horizontal rule
hrule () {
    local CHAR="${1:--}"
    printf "%78s\n" "" | tr " " "$CHAR"
}

# Right-pad a string to a given width (for table alignment)
rpad () {
    local STR="$1" WIDTH="$2"
    printf "%-${WIDTH}s" "$STR"
}

# Status badge -- RUNNING in green, STOPPED in yellow, FAILED in red
state_badge () {
    local STATE="$1"
    case "$STATE" in
        RUNNING) echo -e "${CGreen}RUNNING ${CClear}" ;;
        STOPPED) echo -e "${CYellow}STOPPED ${CClear}" ;;
        FAILED)  echo -e "${CRed}FAILED  ${CClear}" ;;
        *)       echo -e "${CDkGray}UNKNOWN ${CClear}" ;;
    esac
}

# Reset slot: stop VPN + restart stunnel + start VPN
reset_slot_connection () {
    local SLOT="$1"
    echo " $STUNMON_MANAGED_SLOTS " | grep -q " $SLOT " || return 0
    slog_info "reset_slot_connection slot${SLOT}: restarting stunnel + VPN"
    # Clear city cache so the new egress IP is looked up after reconnection
    rm -f "$(slot_rundir $SLOT)/city_cache" 2>/dev/null

    printf "${CGreen}  [ VPN${SLOT} ] Stopping VPN client...${CClear}"
    service "stop_vpnclient${SLOT}" >/dev/null 2>&1
    sleep 1

    printf "\r\033[2K${CGreen}  [ VPN${SLOT} ] Stopping stunnel service...${CClear}"
    stunmon_stop "$SLOT"
    sleep 1

    printf "\r\033[2K${CGreen}  [ VPN${SLOT} ] Generating stunnel config...${CClear}"
    generate_stunnel_conf "$SLOT"

    printf "\r\033[2K${CGreen}  [ VPN${SLOT} ] Starting stunnel service...${CClear}"
    record_start_time "$SLOT"
    stunmon_start "$SLOT"
    sleep 2

    printf "\r\033[2K${CGreen}  [ VPN${SLOT} ] Starting VPN client...${CClear}"
    service "start_vpnclient${SLOT}" >/dev/null 2>&1

    printf "\r\033[2K${CGreen}  [ VPN${SLOT} ] Reset complete -- resuming monitor...${CClear}\n"
    sleep 1

    update_status_file
    # Trigger city lookup in background (will populate once VPN reconnects)
    update_slot_city "$SLOT" &
}

# Read a single keypress immediately in the main display loop
read_key_nowait () {
    local TIMEOUT="${1:-30}" KEY="" I=0
    local STTY_SAVE; STTY_SAVE=$(stty -g 2>/dev/null)
    stty -echo -icanon min 0 time 0 2>/dev/null
    while [ "$I" -lt "$TIMEOUT" ]; do
        KEY=$(dd if=/dev/tty bs=1 count=1 2>/dev/null | tr -d "\000")
        [ -n "$KEY" ] && break
        sleep 1
        I=$((I+1))
    done
    stty "$STTY_SAVE" 2>/dev/null
    echo "$KEY"
}

_SEP="-------|-------------|-----------|------------------------|---------|------|----------------------------------"

draw_table_header () {
    echo -e "${CClear}  ${CWhite}Slot${CClear} | ${CWhite}Provider    ${CClear}| ${CWhite}STUN SVC ${CClear} | ${CWhite}Endpoint               ${CClear}| ${CWhite}TLS     ${CClear}| ${CWhite}VPN  ${CClear}| ${CWhite}City Exit / Uptime    ${CClear}"
    echo -e "${CClear}${_SEP}${CClear}"
}
draw_table_footer () {
    echo -e "${CClear}${_SEP}${CClear}"
}

draw_slot_row () {
    local SLOT="$1"
    local STATE="STOPPED"; stunmon_alive "$SLOT" && STATE="RUNNING"
    local PROVIDER; PROVIDER=$(get_sv "$SLOT" PROVIDER)
    local EP; EP=$(get_current_endpoint "$SLOT")
    [ -z "$EP" ] && EP="$(get_sv $SLOT REMOTE_HOST):$(get_sv $SLOT REMOTE_PORT)"
    local TLS_INFO; TLS_INFO=$(get_tls_info "$SLOT")
    local TLS; TLS=$(echo "$TLS_INFO" | cut -d'|' -f1)
    local VPN_STATE; VPN_STATE=$(get_vpn_state "$SLOT")

    # Build city+uptime cell: "City: Xd XXh:XXm" or "[n/a]" when VPN is down
    local UPTIME; UPTIME=$(get_uptime "$SLOT")
    local CITY;   CITY=$(get_cached_city "$SLOT")
    local CITY_UPTIME
    if [ "$VPN_STATE" = "2" ]; then
        if [ -n "$CITY" ]; then
            CITY_UPTIME="${CITY}: ${UPTIME}"
        else
            CITY_UPTIME="${UPTIME}"
        fi
    else
        CITY_UPTIME="[n/a]"
    fi

    # Pre-pad all fields to exact visible widths BEFORE adding color codes
    local SL; SL=$(printf "%-4.4s"  "VPN${SLOT}")
    local PR; PR=$(printf "%-11.11s" "$PROVIDER")
    local ST; ST=$(printf "%-9.9s"   "$STATE")
    local EF; EF=$(printf "%-22.22s" "$EP")
    local TF; TF=$(printf "%-7.7s"   "${TLS:-?}")
    local CF; CF=$(printf "%-22.22s" "$CITY_UPTIME")
    local SC; case "$STATE" in RUNNING) SC="$CGreen" ;; FAILED) SC="$CRed" ;; *) SC="$CYellow" ;; esac
    local VT VC
    case "$VPN_STATE" in 2) VT="UP  "; VC="$CGreen" ;; 1) VT="UP^ "; VC="$CYellow" ;; *) VT="DOWN"; VC="$CRed" ;; esac
    echo -e "${InvGreen} ${InvDkGray}${CWhite} ${SL}${CClear} | ${PR} | ${SC}${ST}${CClear} | ${EF} | ${TF} | ${VC}${VT}${CClear} | ${CF}"
}

# Draw the detail panel for one slot
draw_slot_detail () {
    local SLOT="$1"

    local LH; LH=$(get_sv "$SLOT" LOCAL_HOST)
    local LP; LP=$(get_sv "$SLOT" LOCAL_PORT)
    local RH; RH=$(get_sv "$SLOT" REMOTE_HOST)
    local RP; RP=$(get_sv "$SLOT" REMOTE_PORT)
    local EP; EP=$(get_current_endpoint "$SLOT")
    if [ -n "$EP" ]; then
        RH=$(echo "$EP" | cut -d: -f1)
        RP=$(echo "$EP" | cut -d: -f2)
    fi
    local SNI; SNI=$(get_sv "$SLOT" SNI_HOST)
    local PID; PID=$(stunmon_pid "$SLOT")
    local DBG; DBG=$(get_sv "$SLOT" DEBUG_LEVEL)
    local NDLY; NDLY=$(get_sv "$SLOT" TCP_NODELAY)
    local VFY; VFY=$(get_sv "$SLOT" VERIFY)

    local TLS_INFO; TLS_INFO=$(get_tls_info "$SLOT")
    local TLS; TLS=$(echo "$TLS_INFO" | cut -d'|' -f1)
    local CIPHER; CIPHER=$(echo "$TLS_INFO" | cut -d'|' -f2)

    # Cert subject from working cert file
    local CERTF; CERTF=$(slot_cert "$SLOT")
    local CERT_SUBJ=""
    [ -n "$OPENSSL_BIN" ] && [ -f "$CERTF" ] && \
        CERT_SUBJ=$("$OPENSSL_BIN" x509 -in "$CERTF" -noout -subject 2>/dev/null | \
        sed 's/.*CN = //' | cut -d, -f1)

    # VPN interface info
    local TUNIF="tun1${SLOT}"
    local TUN_IP
    TUN_IP=$(ip addr show "$TUNIF" 2>/dev/null | grep 'inet ' | awk '{print $2}' | cut -d/ -f1)
    local VPN_STATE; VPN_STATE=$(get_vpn_state "$SLOT")

    # Egress IP
    local EGRESS=""
    if [ -n "$TUN_IP" ]; then
        EGRESS=$(curl -s --max-time 5 --interface "$TUNIF" "https://api.ipify.org" 2>/dev/null)
    fi

    # Bytes
    local BYTES; BYTES=$(get_tunnel_bytes "$SLOT")
    local BSENT; BSENT=$(echo "$BYTES" | cut -d'|' -f1)
    local BRECV; BRECV=$(echo "$BYTES" | cut -d'|' -f2)

    # Endpoint list info
    echo ""
    echo -e "${InvGreen} ${CClear}${CWhite} VPN${SLOT} Detail${CClear}"
    echo -e "${InvGreen} ${CClear}-------------------------------------------------------------------------------------------------------------"
    
    # Show actual TLS version in chain label when cached; "stunnel" otherwise
    local CHAIN_TLS
    if [ -n "$TLS" ] && [ "$TLS" != "?" ]; then
        CHAIN_TLS="${TLS}"
    else
        CHAIN_TLS="stunnel TLS"
    fi
    echo -e "  ${CWhite}Chain      :${CClear} ${LH}:${LP} -> [${CHAIN_TLS}] -> ${RH}:${RP}"
    [ -n "$SNI"       ] && echo -e "  ${CWhite}SNI        :${CClear} ${CYellow}${SNI}${CClear}  (TLS ClientHello advertises this hostname)"
    [ -n "$TLS"       ] && echo -e "  ${CWhite}TLS        :${CClear} ${TLS}  ${CIPHER}"
    [ -n "$CERT_SUBJ" ] && echo -e "  ${CWhite}Cert       :${CClear} ${CERT_SUBJ}  ${CGreen}OK${CClear}"
    [ -n "$PID"       ] && echo -e "  ${CWhite}PID        :${CClear} ${PID}  uptime: $(get_uptime $SLOT)"
    echo -e "  ${CWhite}Settings   :${CClear} debug=${DBG}  TCP_NODELAY=$([ "$NDLY" = "1" ] && echo enabled || echo disabled)"
    echo ""
    echo -e "  ${CWhite}OpenVPN    :${CClear} ${TUNIF}  IP=${TUN_IP:-n/a}  state=${VPN_STATE:-?}"
    [ -n "$EGRESS"    ] && echo -e "  ${CWhite}Egress     :${CClear} ${EGRESS}  (via AirVPN exit node)"
    echo -e "  ${CWhite}Bytes      :${CClear} $(format_bytes $BSENT) sent  /  $(format_bytes $BRECV) recv"
    echo ""
    echo -e "  ${CWhite}Endpoint   :${CClear} ${EP:-$(get_sv $SLOT REMOTE_HOST):$(get_sv $SLOT REMOTE_PORT)}"

    echo -e "${CClear}--------------------------------------------------------------------------------------------------------------"
}

# Draw last N lines of the stunmon application log
draw_log_tail () {
    local LINES="${1:-8}"
    echo ""
    echo -e "${InvGreen} ${CClear}${InvDkGray}${CWhite} Recent Events                                                                                               ${CClear}"
    if [ -f "$STUNMON_LOG" ]; then
        tail -n "$LINES" "$STUNMON_LOG" | while IFS= read -r line; do
            echo -e "  ${CDkGray}${line}${CClear}"
        done
    else
        echo -e "  ${CDkGray}  (no log entries yet)${CClear}"
    fi
    echo -e "${CClear}--------------------------------------------------------------------------------------------------------------"
    echo ""
}

# ============================================================================================================================
# Section 10 -- Main monitoring display
# ============================================================================================================================

display_main () {
    local DETAIL_SLOT=""
    local SHOW_OPS=0
    local SLOT_COUNT; SLOT_COUNT=$(echo "$STUNMON_MANAGED_SLOTS" | wc -w)
    [ "$SLOT_COUNT" = "1" ] && DETAIL_SLOT="$STUNMON_MANAGED_SLOTS"

    # Kick off immediate city lookups so the column is populated on first render.
    for _INIT_S in $STUNMON_MANAGED_SLOTS; do
        [ "$(get_sv $_INIT_S ENABLED)" = "0" ] && continue
        update_slot_city "$_INIT_S" &
    done

    while true; do
        stty_normal
        clear

        # Operations menu at TOP (when shown)
        if [ "$SHOW_OPS" = "1" ]; then
            echo -e "${InvGreen} ${InvDkGray} ${CWhite}Operations Menu                                                                                             ${CClear}"
            printf "${InvGreen} ${CClear} Select Slot Detail:       1:${CGreen}(1)${CClear} 2:${CGreen}(2)${CClear} 3:${CGreen}(3)${CClear} 4:${CGreen}(4)${CClear} 5:${CGreen}(5)${CClear} ${InvGreen} ${CClear} ${CGreen}(C)${CClear}onfiguration / Main Setup Menu\n"
            printf "${InvGreen} ${CClear} Reset stunnel/OPVN Slot:  1:${CGreen}(!)${CClear} 2:${CGreen}(@)${CClear} 3:${CGreen}(#)${CClear} 4:${CGreen}(\$)${CClear} 5:${CGreen}(%%)${CClear} ${InvGreen} ${CClear} ${CDkGray}A(M)TM Email Notifications: Success, Failure\n"
            printf "${InvGreen} ${CClear} ${CGreen}(R)${CClear}efresh Display Stats                                 ${InvGreen} ${CClear} ${CDkGray}(A)utostart STUNMON on Reboot: Enabled\n"
            printf "${InvGreen} ${CClear} ${CGreen}(L)${CClear}og Viewer                                            ${InvGreen} ${CClear} ${CGreen}(Q)${CClear}uit STUNMON\n"
            echo -e "${InvGreen} ${CClear}${CDkGray}-------------------------------------------------------------------------------------------------------------${CClear}"
            echo ""
        fi

        tzone="$(date +%Z)"
        tzonechars="${#tzone}"

        if   [ "$tzonechars" = "1" ]; then tzspaces="        ";
        elif [ "$tzonechars" = "2" ]; then tzspaces="       ";
        elif [ "$tzonechars" = "3" ]; then tzspaces="      ";
        elif [ "$tzonechars" = "4" ]; then tzspaces="     ";
        elif [ "$tzonechars" = "5" ]; then tzspaces="    "; fi

        # Status bar (always visible)
        local OPS_LABEL
        [ "$SHOW_OPS" = "1" ] && OPS_LABEL="(H)ide Operations Menu" || OPS_LABEL="(S)how Operations Menu"
        echo -en "${InvGreen} ${InvDkGray}${CWhite} STUNMON v"
        printf "%-8s" ${Version}
        printf "%*s" 15 "" 
        echo -en "${OPS_LABEL}"
        printf "%*s" 12 ""
        echo -e "$tzspaces$(date +"%a %b %d, %Y %H:%M:%S %Z %z") ${CClear}"
        echo ""

        # Slot summary table
        if [ -z "$STUNMON_MANAGED_SLOTS" ]; then
            echo -e "${InvGreen} ${CClear}  ${CYellow}No slots configured. Press (C) to enter setup.${CClear}"
            echo -e "${InvGreen} ${CClear}"
        else
            draw_table_header
            for S in $STUNMON_MANAGED_SLOTS; do
                [ "$(get_sv $S ENABLED)" = "0" ] && continue
                draw_slot_row "$S"
            done
            draw_table_footer
        fi

        # Detail panel
        if [ -n "$DETAIL_SLOT" ] && [ -n "$STUNMON_MANAGED_SLOTS" ]; then
            draw_slot_detail "$DETAIL_SLOT"
        fi

        # Log tail
        draw_log_tail 5

        # Countdown counter + inline keypress polling
        local KEY="" _CT=1 _FIRST_CTR=1
        local _SAVE_TTY; _SAVE_TTY=$(stty -g 2>/dev/null)
        stty -echo -icanon min 0 time 0 2>/dev/null
        while [ "$_CT" -le "$STUNMON_DISPLAY_REFRESH" ]; do
            local _PCT; _PCT=$(awk -v ct="$_CT" -v tot="$STUNMON_DISPLAY_REFRESH" 'BEGIN{printf "%.1f", ct * 100.0 / tot}')
            # On all iterations after the first: move cursor up one line and clear it
            [ "$_FIRST_CTR" = "0" ] && printf "\033[1A\033[2K"
            printf "${InvGreen} ${CClear} ${InvDkGray}${CWhite}%3ds /%5s%%${CClear} [${CGreen}e${CClear}=Exit] [Selection? ${InvGreen} ${CClear}]\n" "$_CT" "$_PCT"
            _FIRST_CTR=0
            KEY=$(dd if=/dev/tty bs=1 count=1 2>/dev/null | tr -d "\000")
            [ -n "$KEY" ] && break
            sleep 1
            _CT=$((_CT + 1))
        done
        printf "\033[1A\033[2K"   # clear the counter line before next screen draw
        stty "$_SAVE_TTY" 2>/dev/null

        case "$KEY" in
            s|S) SHOW_OPS=1 ;;
            h|H) SHOW_OPS=0 ;;
            c|C) stty_normal; setup_menu; load_config ;;
            r|R) health_check_all; update_status_file ;;
            l|L) display_full_log ;;
            e|E|q|Q) break ;;   # e=Exit and q=Quit both terminate the display loop
            '!') reset_slot_connection 1 ;;
            '@') reset_slot_connection 2 ;;
            '#') reset_slot_connection 3 ;;
            '$') reset_slot_connection 4 ;;
            '%') reset_slot_connection 5 ;;
            [1-5])
                if echo "$STUNMON_MANAGED_SLOTS" | grep -qw "$KEY"; then
                    [ "$DETAIL_SLOT" = "$KEY" ] && DETAIL_SLOT="" || DETAIL_SLOT="$KEY"
                fi ;;
            '')
                # Timeout: run automatic health check (primary resilience mechanism)
                health_check_all ;;
        esac
    done
}

# ============================================================================================================================
# Section 11 -- Setup menu
# ============================================================================================================================

# Global variable used by pick_file to return a path without stdout capture
PICKED_FILE=""

# File picker: scans standard locations for files matching PATTERN,
# presents a numbered list, and sets PICKED_FILE.  No timeout, no cursor drop.
# Usage: pick_file "*.ssl" "stunnel .ssl config"; use "$PICKED_FILE"
pick_file () {
    local PATTERN="$1" LABEL="$2"
    PICKED_FILE=""

    # Write all matches to a temp file (avoids pipe subshell so N increments correctly)
    local _PF_TMP; _PF_TMP="/tmp/stunmon_pf_$$.txt"
    > "$_PF_TMP"

    # Search each standard location for each space-separated sub-pattern.
    # Use 'find' instead of shell glob expansion
    local _DIR _P
    for _DIR in /jffs/scripts \
                /jffs/addons/stunmon.d \
                /jffs/addons/stunmon.d/configs \
                /tmp; do
        [ -d "$_DIR" ] || continue
        for _P in $PATTERN; do          # unquoted: splits "*.crt *.pem" into two words
            find "$_DIR" -maxdepth 1 -name "$_P" -type f 2>/dev/null >> "$_PF_TMP"
        done
    done
    # Sort and deduplicate in-place
    sort -u "$_PF_TMP" -o "$_PF_TMP" 2>/dev/null

    local _TOTAL; _TOTAL=$(grep -c '' "$_PF_TMP" 2>/dev/null || echo 0)

    echo ""
    echo -e "${CClear} Looking for ${LABEL} files in standard locations...${CClear}"
    echo -e "${CClear}"

    if [ "$_TOTAL" -gt 0 ]; then
        # Display numbered list -- loop reads from FILE not a pipe, so N increments
        local N=1
        while IFS= read -r _F; do
            echo -e "${CClear}   (${N}) ${CGreen}${_F}${CClear}"
            N=$((N+1))
        done < "$_PF_TMP"
        echo -e "${CClear}   (c) Enter a custom path"
        echo -e "${CClear}   (e) Skip"
        echo -e "${CClear}"
        echo -e "${CClear}${CDkGray}  -----------------------------------------------------------------------${CClear}"
        echo ""
        while true; do
            printf " Select [1-%s/c/e]: " "$_TOTAL"
            local _PICK; _PICK=$(getkey); printf "%s\n" "$_PICK"
            case "$_PICK" in
                [Ee]) PICKED_FILE=""; rm -f "$_PF_TMP"; return 1 ;;
                [Cc]) stty_normal; printf " Enter full path: "; read -r PICKED_FILE
                      rm -f "$_PF_TMP"; return 0 ;;
                ''|*[!0-9]*)
                    echo ""; echo -e "  ${CRed}Enter a number (1-${_TOTAL}), 'c' for custom path, or 'e' to skip.${CClear}" ;;
                *)
                    local _CHOSEN; _CHOSEN=$(awk "NR==${_PICK}" "$_PF_TMP")
                    if [ -n "$_CHOSEN" ]; then
                        PICKED_FILE="$_CHOSEN"
                        rm -f "$_PF_TMP"; return 0
                    else
                        echo ""; echo -e "  ${CRed}Selection ${_PICK} is out of range (1-${_TOTAL}).${CClear}"
                    fi ;;
            esac
        done
    else
        rm -f "$_PF_TMP"
        echo -e "${CClear}   ${CYellow}No ${LABEL} files found in standard locations.${CClear}"
        echo -e "${CClear}   Copy the file to /jffs/scripts/ then press ENTER to retry,${CClear}"
        echo -e "${CClear}   or type the full path manually.  Press 'e' to skip.${CClear}"
        echo -e "${CClear}"
        echo -e "${CClear}${CDkGray}  -----------------------------------------------------------------------${CClear}"
        echo ""
        while true; do
            stty_normal
            printf " Full path, ENTER to re-scan, or 'e' to skip: "
            read -r PICKED_FILE
            [ "$(echo "$PICKED_FILE" | tr '[:upper:]' '[:lower:]')" = "e" ] && PICKED_FILE="" && return 1
            if [ -z "$PICKED_FILE" ]; then
                pick_file "$PATTERN" "$LABEL"; return $?
            fi
            [ -f "$PICKED_FILE" ] && return 0
            echo ""; echo -e "  ${CRed}File not found: ${PICKED_FILE}${CClear}"
        done
    fi
}

# Yes/No prompt -- returns 1 (yes) or 0 (no)
# getkey: read exactly one character immediately -- no Enter needed, no echo.
# Used for all single-character menu selections throughout setup menus.
# Text fields (IP addresses, paths) still use inp() with regular read.
getkey () {
    local _K=""
    local _SAVE; _SAVE=$(stty -g 2>/dev/null)
    stty -echo -icanon min 1 time 0 2>/dev/null
    _K=$(dd if=/dev/tty bs=1 count=1 2>/dev/null | tr -d "\000")
    stty "$_SAVE" 2>/dev/null
    printf '%s' "$_K"
}

# stty_normal: restore terminal to canonical+echo mode before text input.
stty_normal () {
    stty echo icanon 2>/dev/null
}

# yesno: single-keypress y/n -- no Enter required. Echoes key back.
yesno () {
    local CURRENT="$1"
    local DISPLAY; [ "$CURRENT" = "1" ] && DISPLAY="Yes" || DISPLAY="No"
    printf " [%s] (y/n): " "$DISPLAY" >&2
    local _YN; _YN=$(getkey)
    printf "%s\n" "$_YN" >&2
    case "$(echo "$_YN" | tr '[:upper:]' '[:lower:]')" in
        y) echo 1 ;;
        n) echo 0 ;;
        *) echo "$CURRENT" ;;
    esac
}

# inp: text prompt -- returns typed value or current on Enter.
# Prompt goes to stderr so the captured return value from $() is clean.
inp () {
    local LABEL="$1" CURRENT="$2"
    stty_normal
    printf " %s [%s]: " "$LABEL" "$CURRENT" >&2
    local _INP=""
    read -r _INP
    [ -z "$_INP" ] && printf '%s' "$CURRENT" || printf '%s' "$_INP"
}

# ============================================================================================================================
# Section 11a -- Per-slot setup screen
# ============================================================================================================================

setup_slot () {
    local SLOT="$1"

    while true; do
        stty_normal
        clear
        echo -en "${InvGreen} ${InvDkGray}${CWhite} STUNMON v"
        printf "%-8s" ${Version} 
        echo -e "|  Slot ${SLOT} Configuration                                        ${CClear}"
        echo -e "${InvGreen} ${CClear}"
        local ST_BADGE
        if stunmon_alive "$SLOT"; then
            ST_BADGE="${CGreen}RUNNING (PID: $(stunmon_pid $SLOT))${CClear}"
        else
            ST_BADGE="${CYellow}STOPPED${CClear}"
        fi
        echo -e "${InvGreen} ${CClear} Status : ${ST_BADGE}"
        echo -e "${InvGreen} ${CClear}"
        echo -e "${InvGreen} ${CClear} ${CWhite}-- Identity --------------------------------------------------------------------${CClear}"
        echo -e "${InvGreen} ${CClear}"
        local EN_BADGE; [ "$(get_sv $SLOT ENABLED)" = "1" ] && EN_BADGE="${CGreen}Yes${CClear}" || EN_BADGE="${CRed}No${CClear}"
        echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(1)${CClear}  Enabled            : ${EN_BADGE}"
        echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(2)${CClear}  Provider Name      : ${CWhite}$(get_sv $SLOT PROVIDER)${CClear}"
        echo -e "${InvGreen} ${CClear}"
        echo -e "${InvGreen} ${CClear} ${CWhite}-- Connection ------------------------------------------------------------------${CClear}"
        echo -e "${InvGreen} ${CClear}"
        local SSL_PATH; SSL_PATH=$(get_sv $SLOT SSL_CONF)
        [ -z "$SSL_PATH" ] && SSL_PATH="${CYellow}(not set)${CClear}" || SSL_PATH="${CGreen}${SSL_PATH}${CClear}"
        echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(3)${CClear}  SSL Config File    : ${SSL_PATH}"
        local CERT_PATH; CERT_PATH=$(get_sv $SLOT CERT)
        local CERT_SUBJ="(not set)"
        if [ -n "$CERT_PATH" ] && [ -f "$CERT_PATH" ] && [ -n "$OPENSSL_BIN" ]; then
            CERT_SUBJ=$("$OPENSSL_BIN" x509 -in "$CERT_PATH" -noout -subject 2>/dev/null | \
                sed 's/.*CN *= */CN=/' | cut -d, -f1 | cut -d/ -f1)
        fi
        local CERT_DISP; [ -z "$(get_sv $SLOT CERT)" ] && CERT_DISP="${CYellow}(not set)${CClear}" || CERT_DISP="${CGreen}$(get_sv $SLOT CERT)${CClear}"
        echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(4)${CClear}  CA Certificate     : ${CERT_DISP}"
        echo -e "${InvGreen} ${CClear}      Subject            : ${CDkGray}${CERT_SUBJ}${CClear}"
        echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(5)${CClear}  Local Port         : ${CWhite}$(get_sv $SLOT LOCAL_PORT)${CClear}"
        echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(6)${CClear}  Remote Host        : ${CWhite}$(get_sv $SLOT REMOTE_HOST)${CClear}"
        echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(7)${CClear}  Remote Port        : ${CWhite}$(get_sv $SLOT REMOTE_PORT)${CClear}"
        echo -e "${InvGreen} ${CClear}"
        echo -e "${InvGreen} ${CClear} ${CWhite}-- Obfuscation -----------------------------------------------------------------${CClear}"
        echo -e "${InvGreen} ${CClear}"
        local SNI_DISP; SNI_DISP=$(get_sv $SLOT SNI_HOST)
        [ -z "$SNI_DISP" ] && SNI_DISP="${CDkGray}(not set)${CClear}" || SNI_DISP="${CGreen}${SNI_DISP}${CClear}"
        echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(8)${CClear}  SNI Hostname       : ${SNI_DISP}"
        echo -e "${InvGreen} ${CClear}"
        echo -e "${InvGreen} ${CClear} ${CWhite}-- Performance -----------------------------------------------------------------${CClear}"
        echo -e "${InvGreen} ${CClear}"
        local DBG; DBG=$(get_sv $SLOT DEBUG_LEVEL)
        echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(9)${CClear}  Debug Level        : ${CWhite}${DBG}${CClear}  ${CDkGray}(0=silent  3=errors  6=verbose)${CClear}"
        local NDLY_BADGE; [ "$(get_sv $SLOT TCP_NODELAY)" = "1" ] && NDLY_BADGE="${CGreen}enabled${CClear}" || NDLY_BADGE="${CYellow}disabled${CClear}"
        echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(t)${CClear}  TCP_NODELAY        : ${NDLY_BADGE}"
        echo -e "${InvGreen} ${CClear}"
        echo -e "${InvGreen} ${CClear}${CDkGray}---------------------------------------------------------------------------------${CClear}"
        echo ""
        printf " Option [1-9/t], (p)arse .ssl, (v)alidate, (s)ave+apply, (e)xit: "
        local OPT; OPT=$(getkey); printf "%s\n" "$OPT"

        case "$OPT" in
            1) echo ""; set_sv "$SLOT" ENABLED "$(yesno $(get_sv $SLOT ENABLED))" ;;
            2) echo ""; set_sv "$SLOT" PROVIDER "$(inp 'Provider name' $(get_sv $SLOT PROVIDER))" ;;
            3) echo ""
               echo -e "${CClear} Select the stunnel .ssl config file from your VPN provider.${CClear}"
               echo -e "${CClear}${CYellow} Example: AirVPN_US-Atlanta-Georgia_Musca_SSL-443.ssl${CClear}"
               pick_file "*.ssl" "stunnel .ssl config"
               if [ -n "$PICKED_FILE" ] && [ -f "$PICKED_FILE" ]; then
                   set_sv "$SLOT" SSL_CONF "$PICKED_FILE"
                   echo ""; echo -e "  ${CGreen}SSL config set: ${PICKED_FILE}${CClear}"; sleep 1
               fi ;;
            4) echo ""
               echo -e "${CClear} Select the CA certificate file from your VPN provider.${CClear}"
               pick_file "*.crt *.pem" "CA certificate"
               if [ -n "$PICKED_FILE" ] && [ -f "$PICKED_FILE" ]; then
                   if grep -q 'BEGIN CERTIFICATE' "$PICKED_FILE" 2>/dev/null; then
                       set_sv "$SLOT" CERT "$PICKED_FILE"
                       echo ""; echo -e "  ${CGreen}CA cert set: ${PICKED_FILE}${CClear}"; sleep 1
                   else
                       echo ""; echo -e "  ${CRed}Not a valid PEM certificate.${CClear}"; sleep 2
                   fi
               fi ;;
            5) echo ""; set_sv "$SLOT" LOCAL_PORT "$(inp 'Local listener port' $(get_sv $SLOT LOCAL_PORT))" ;;
            6) echo ""; set_sv "$SLOT" REMOTE_HOST "$(inp 'Remote stunnel server host/IP' $(get_sv $SLOT REMOTE_HOST))" ;;
            7) echo ""; set_sv "$SLOT" REMOTE_PORT "$(inp 'Remote stunnel server port' $(get_sv $SLOT REMOTE_PORT))" ;;
            8) echo ""; stty_normal
               printf " SNI hostname (ENTER to clear): "
               local _SNI=""; read -r _SNI
               set_sv "$SLOT" SNI_HOST "$_SNI" ;;
            9) echo ""; set_sv "$SLOT" DEBUG_LEVEL "$(inp 'Debug level (0/3/6)' $(get_sv $SLOT DEBUG_LEVEL))" ;;
            t|T) echo ""; set_sv "$SLOT" TCP_NODELAY "$(yesno $(get_sv $SLOT TCP_NODELAY))" ;;
            p|P) echo ""; echo -e "  ${CWhite}Parsing .ssl file...${CClear}"
               if parse_ssl_conf "$SLOT"; then
                   echo -e "  ${CGreen}local=$(get_sv $SLOT LOCAL_HOST):$(get_sv $SLOT LOCAL_PORT)  remote=$(get_sv $SLOT REMOTE_HOST):$(get_sv $SLOT REMOTE_PORT)${CClear}"
               else
                   echo -e "  ${CRed}Could not parse. Check SSL config file (option 3).${CClear}"
               fi
               sleep 2 ;;
            v|V) echo ""; setup_validate "$SLOT" ;;
            s|S) save_config
               echo ""
               echo -e "  ${CWhite}Generating stunnel config...${CClear}"
               if generate_stunnel_conf "$SLOT"; then
                   stunmon_restart "$SLOT"
                   echo -e "  ${CGreen}Saved. Slot ${SLOT} restarted.${CClear}"
               else
                   echo -e "  ${CRed}Config generation failed. Check SSL file (3) and cert (4).${CClear}"
               fi
               sleep 2 ;;
            e|E|q|Q) save_config; break ;;
        esac
    done
}


# ============================================================================================================================
# Section 11b -- Validate slot
# ============================================================================================================================

setup_validate () {
    local SLOT="$1"
    local OK=1

    clear
    echo -e "${InvGreen} ${InvDkGray}${CWhite} stunmon v${Version} -- Slot ${SLOT} Validation                                               ${CClear}"
    echo -e "${InvGreen} ${CClear}"

    # stunnel binary
    if [ -n "$STUNNEL_BIN" ]; then
        local _SVER; _SVER=$("$STUNNEL_BIN" -version 2>&1 | sed -n '2p')
        echo -e "${InvGreen} ${CClear}   ${CGreen}[OK]${CClear}  stunnel binary : ${STUNNEL_BIN} -- ${_SVER}"
    else
        echo -e "${InvGreen} ${CClear}   ${CRed}[!!]${CClear}  stunnel not found. Install via: opkg install stunnel"
        OK=0
    fi

    # SSL config file
    local SSLF; SSLF=$(get_sv "$SLOT" SSL_CONF)
    if [ -f "$SSLF" ]; then
        echo -e "${InvGreen} ${CClear}   ${CGreen}[OK]${CClear}  SSL config     : ${SSLF}"
    else
        echo -e "${InvGreen} ${CClear}   ${CRed}[!!]${CClear}  SSL config not found: ${SSLF:-"(not set -- use option 3)"}"
        OK=0
    fi

    # CA certificate
    local CERTF; CERTF=$(get_sv "$SLOT" CERT)
    if [ -f "$CERTF" ] && grep -q 'BEGIN CERTIFICATE' "$CERTF" 2>/dev/null; then
        local _SUBJ
        [ -n "$OPENSSL_BIN" ] && \
            _SUBJ=$("$OPENSSL_BIN" x509 -in "$CERTF" -noout -subject 2>/dev/null | \
                sed 's/.*CN *= */CN=/' | cut -d, -f1 | cut -d/ -f1)
        echo -e "${InvGreen} ${CClear}   ${CGreen}[OK]${CClear}  CA certificate : ${_SUBJ:-${CERTF}}"
    else
        echo -e "${InvGreen} ${CClear}   ${CRed}[!!]${CClear}  CA certificate not found or invalid: ${CERTF:-"(not set -- use option 4)"}"
        OK=0
    fi

    # Local port availability
    local LP; LP=$(get_sv "$SLOT" LOCAL_PORT)
    if netstat -tln 2>/dev/null | grep -q ":${LP} "; then
        if stunmon_alive "$SLOT"; then
            echo -e "${InvGreen} ${CClear}   ${CGreen}[OK]${CClear}  Port ${LP} in use by stunmon (slot is running)"
        else
            echo -e "${InvGreen} ${CClear}   ${CYellow}[!!]${CClear}  Port ${LP} is in use by another process"
        fi
    else
        echo -e "${InvGreen} ${CClear}   ${CGreen}[OK]${CClear}  Port ${LP} is available"
    fi

    # Remote TCP reachability
    local RH; RH=$(get_sv "$SLOT" REMOTE_HOST)
    local RP; RP=$(get_sv "$SLOT" REMOTE_PORT)
    if [ -n "$RH" ]; then
        echo -e "${InvGreen} ${CClear}${CDkGray}          Testing TCP to ${RH}:${RP}...${CClear}"
        curl -s --max-time 6 --connect-timeout 4 -o /dev/null "http://${RH}:${RP}/" 2>/dev/null
        if [ $? -ne 7 ]; then
            echo -e "${InvGreen} ${CClear}   ${CGreen}[OK]${CClear}  Remote ${RH}:${RP} is reachable"
        else
            echo -e "${InvGreen} ${CClear}   ${CRed}[!!]${CClear}  Remote ${RH}:${RP} is not reachable"
            OK=0
        fi
    else
        echo -e "${InvGreen} ${CClear}   ${CYellow}[??]${CClear}  Remote host not configured (use option 6)"
        OK=0
    fi

    echo -e "${InvGreen} ${CClear}"
    echo -e "${InvGreen} ${CClear}${CDkGray}  -----------------------------------------------------------------------${CClear}"
    echo -e "${InvGreen} ${CClear}"
    if [ "$OK" = "1" ]; then
        echo -e "${InvGreen} ${CClear}   ${CGreen}All Slot ${SLOT} checks passed.${CClear}"
    else
        echo -e "${InvGreen} ${CClear}   ${CYellow}Some checks failed. Resolve issues above before starting.${CClear}"
    fi
    echo -e "${InvGreen} ${CClear}"
    echo ""
    printf " Press any key to continue..."
    getkey > /dev/null
}

# ============================================================================================================================
# Section 11c -- Main setup menu
# ============================================================================================================================

setup_menu () {
    while true; do
        clear
        echo -e "${InvGreen} ${InvDkGray}${CWhite} STUNMON  |  Setup & Configuration                                                    ${CClear}"
        echo -e "${InvGreen} ${CClear}"
        echo -e "${InvGreen} ${CClear} Configure and manage stunnel connections for your OpenVPN slots."
        echo -e "${InvGreen} ${CClear}"
        echo -e "${InvGreen} ${CClear} ${CYellow}stunnel${CClear} wraps OpenVPN TCP traffic inside a genuine TLS session, making it appear as${CClear}"
        echo -e "${InvGreen} ${CClear} standard HTTPS to deep packet inspection systems.${CClear}"
        echo -e "${InvGreen} ${CClear}"
        echo -e "${InvGreen} ${CClear}${CDkGray}--------------------------------------------------------------------------------------${CClear}"
        echo -e "${InvGreen} ${CClear}"

        # Show configured slots summary
        if [ -n "$STUNMON_MANAGED_SLOTS" ]; then
            echo -e "${InvGreen} ${CClear} ${CWhite}Configured slots:${CClear}"
            echo -e "${InvGreen} ${CClear}"
            for S in $STUNMON_MANAGED_SLOTS; do
                local _ST="STOPPED"
                stunmon_alive "$S" && _ST="${CGreen}RUNNING${CClear}" || _ST="${CYellow}STOPPED${CClear}"
                local _EP; _EP=$(get_current_endpoint "$S")
                [ -z "$_EP" ] && _EP="$(get_sv $S REMOTE_HOST):$(get_sv $S REMOTE_PORT)"
                printf "${InvGreen} ${CClear} ${InvDkGray}${CWhite}( ${S})${CClear}  VPN%-1s      %-12s  " "$S" "$(get_sv $S PROVIDER)"
                echo -e "${_ST}      ${_EP}${CClear}"
            done
        else
            echo -e "${InvGreen} ${CClear} ${CYellow}No slots configured yet. Use (a) to add your first slot.${CClear}"
        fi

        echo -e "${InvGreen} ${CClear}"
        echo -e "${InvGreen} ${CClear}${CDkGray}--------------------------------------------------------------------------------------${CClear}"
        echo -e "${InvGreen} ${CClear}"
        echo -e "${InvGreen} ${CClear} ${CWhite}Slot Maintenance:${CClear}"
        echo -e "${InvGreen} ${CClear}"
        echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite}( 6)${CClear}  Add new slot"
        echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite}( 7)${CClear}  Global settings"
        echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite}( 8)${CClear}  Validate all configs"
        echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite}( 9)${CClear}  Remove a slot"
        echo -e "${InvGreen} ${CClear}"
        echo -e "${InvGreen} ${CClear}${CDkGray}--------------------------------------------------------------------------------------${CClear}"
        echo -e "${InvGreen} ${CClear}"
        echo -e "${InvGreen} ${CClear} ${CWhite}Script Maintenance:${CClear}"
        echo -e "${InvGreen} ${CClear}"
        echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(10)${CClear}  Force-reinstall Entware dependencies"
        echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(11)${CClear}  Check for STUNMON updates"
        echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite}(12)${CClear}  Uninstall STUNMON"
        echo -e "${InvGreen} ${CClear} ${InvDkGray}${CWhite}( e)${CClear}  Exit setup"
        echo -e "${InvGreen} ${CClear}"
        echo -e "${InvGreen} ${CClear}${CDkGray}--------------------------------------------------------------------------------------${CClear}"
        echo ""
        local _CHOICE;
        read -p "  Enter Slot Number [1-5] or Option [6-12, e=Exit]: " _CHOICE

        case "$_CHOICE" in
            6)  setup_new_slot ;;
            7)  setup_global ;;

            8)  for S in $STUNMON_MANAGED_SLOTS; do setup_validate "$S"; done ;;
            9)  setup_remove_slot ;;
            [Ee]) break ;;
            [1-5])
                if echo "$STUNMON_MANAGED_SLOTS" | grep -qw "$_CHOICE"; then
                    setup_slot "$_CHOICE"
                else
                    echo -e " ${CYellow}Slot ${_CHOICE} is not configured. Use (a) to add it.${CClear}"
                    sleep 2
                fi ;;
            *) echo ""; echo -e "${CRed}  Invalid Choice. Please try again. ${CClear}"; sleep 2
        esac
    done
    save_config
}

# ============================================================================================================================
# Section 11d -- Add/remove slot helpers
# ============================================================================================================================

setup_new_slot () {
    clear
    echo -e "${InvGreen} ${InvDkGray}${CWhite} STUNMON  |  Add New Slot                                                             ${CClear}"
    echo -e "${InvGreen} ${CClear}"
    echo -e "${InvGreen} ${CClear} Add a new OpenVPN slot to STUNMON management.${CClear}"
    echo -e "${InvGreen} ${CClear}"
    echo -e "${InvGreen} ${CClear} The slot must already be configured in the router's VPN client settings with the${CClear}"
    echo -e "${InvGreen} ${CClear} provider's stunnel .ovpn file loaded.${CClear}"
    echo -e "${InvGreen} ${CClear}${CDkGray}--------------------------------------------------------------------------------------${CClear}"
    echo ""
    
    local NEWSLOT
    printf " VPN slot number to add [1-5, e=Exit]: "
    local NEWSLOT; NEWSLOT=$(getkey); printf "%s
" "$NEWSLOT"
    [ "$(echo "$NEWSLOT" | tr '[:upper:]' '[:lower:]')" = "e" ] && return
    case "$NEWSLOT" in
        [1-5]) ;;
        *) echo ""; echo -e "  ${CRed}Invalid slot number. Must be 1-5.${CClear}"; sleep 2; return ;;
    esac
    if echo "$STUNMON_MANAGED_SLOTS" | grep -qw "$NEWSLOT"; then
        echo ""; echo -e "  ${CYellow}Slot ${NEWSLOT} is already configured. Select it from the menu to edit.${CClear}"
        sleep 2; return
    fi

    # Initialise slot defaults
    set_sv "$NEWSLOT" ENABLED        1
    set_sv "$NEWSLOT" PROVIDER       ""
    set_sv "$NEWSLOT" SSL_CONF       ""
    set_sv "$NEWSLOT" CERT           ""
    set_sv "$NEWSLOT" LOCAL_HOST     "127.0.0.1"
    set_sv "$NEWSLOT" LOCAL_PORT     "1413"
    set_sv "$NEWSLOT" REMOTE_HOST    ""
    set_sv "$NEWSLOT" REMOTE_PORT    "443"
    set_sv "$NEWSLOT" SNI_HOST       ""
    set_sv "$NEWSLOT" DEBUG_LEVEL    0
    set_sv "$NEWSLOT" TCP_NODELAY    1
    set_sv "$NEWSLOT" VERIFY         3
    set_sv "$NEWSLOT" TIMEOUTCLOSE   0

    STUNMON_MANAGED_SLOTS=$(printf "%s\n%s" "$STUNMON_MANAGED_SLOTS" "$NEWSLOT" | \
        tr ' ' '\n' | sort -n | uniq | tr '\n' ' ' | sed 's/^ //;s/ $//')
    save_config

    echo ""; echo -e "  ${CGreen}Slot ${NEWSLOT} added. Opening configuration...${CClear}"
    sleep 1
    setup_slot "$NEWSLOT"
}

setup_remove_slot () {
    clear
    echo -e "${InvGreen} ${InvDkGray}${CWhite} STUNMON  |  Remove Slot                                                              ${CClear}"
    echo -e "${InvGreen} ${CClear}"
    echo -e "${InvGreen} ${CClear} Remove an OpenVPN slot from STUNMON management.${CClear}"
    echo -e "${InvGreen} ${CClear}"
    echo -e "${InvGreen} ${CClear} Current slots in use: ${CWhite}${STUNMON_MANAGED_SLOTS:-none}${CClear}"
    echo -e "${InvGreen} ${CClear}"
    echo -e "${InvGreen} ${CClear}${CDkGray}--------------------------------------------------------------------------------------${CClear}"
    echo ""
    printf " Slot number to remove [1-5, e=Exit]: "
    local _SLOT; _SLOT=$(getkey); printf "%s
" "$_SLOT"
    [ "$(echo "$_SLOT" | tr '[:upper:]' '[:lower:]')" = "e" ] || [ -z "$_SLOT" ] && return
    if ! echo "$STUNMON_MANAGED_SLOTS" | grep -qw "$_SLOT"; then
        echo ""; echo -e " ${CRed}Slot ${_SLOT} is not in the managed list.${CClear}"; sleep 2; return
    fi
    echo ""
    printf " Remove slot ${_SLOT} ($(get_sv $_SLOT PROVIDER))? This stops stunnel and removes its config [y/n]: "
    local _CONF; read -r _CONF
    [ "$(echo "$_CONF" | tr '[:upper:]' '[:lower:]')" != "y" ] && return
    stunmon_stop "$_SLOT"
    service "stop_vpnclient${_SLOT}" >/dev/null 2>&1
    rm -f "$(slot_conf $_SLOT)" "$(slot_cert $_SLOT)" \
          "$(slot_eplist $_SLOT)" "$(slot_epidx $_SLOT)" 2>/dev/null
    rm -rf "$(slot_rundir $_SLOT)" 2>/dev/null
    STUNMON_MANAGED_SLOTS=$(echo "$STUNMON_MANAGED_SLOTS" | tr ' ' '\n' | \
        grep -v "^${_SLOT}$" | tr '\n' ' ' | sed 's/^ //;s/ $//')
    save_config; update_status_file
    slog_info "setup: slot ${_SLOT} removed"
    echo ""; echo -e " ${CGreen}Slot ${_SLOT} removed.${CClear}"; sleep 2
}

# Global settings
setup_global () {
    while true; do
        clear
        echo -e "${InvGreen} ${InvDkGray}${CWhite} STUNMON  |  Global Settings                                                          ${CClear}"
        echo -e "${InvGreen} ${CClear}"
        echo -e "${InvGreen} ${CClear}   (1)  Log retention      : ${CWhite}${STUNMON_LOGRETENTION}${CClear} rows"
        echo -e "${InvGreen} ${CClear}   (2)  Health interval    : ${CWhite}${STUNMON_HEALTHINTERVAL}${CClear} seconds (display mode refresh)"
        echo -e "${InvGreen} ${CClear}   (3)  Display refresh    : ${CWhite}${STUNMON_DISPLAY_REFRESH}${CClear} seconds"
        echo -e "${InvGreen} ${CClear}"
        echo -e "${InvGreen} ${CClear}${CDkGray}--------------------------------------------------------------------------------------${CClear}"
        echo ""
        printf " Option [1-3, e=Exit]: "
        local _G; _G=$(getkey); printf "%s
" "$_G"
        case "$_G" in
            1) echo ""; STUNMON_LOGRETENTION=$(inp 'Log retention (rows)' "$STUNMON_LOGRETENTION") ;;
            2) echo ""; STUNMON_HEALTHINTERVAL=$(inp 'Health check interval (secs)' "$STUNMON_HEALTHINTERVAL") ;;
            3) echo ""; STUNMON_DISPLAY_REFRESH=$(inp 'Display refresh interval (secs)' "$STUNMON_DISPLAY_REFRESH") ;;
            e|q) break ;;
        esac
    done
    save_config
    echo ""; echo -e "  ${CGreen}Global settings saved.${CClear}"; sleep 1
}

# ============================================================================================================================
# Section 12 -- First-run wizard
# ============================================================================================================================

first_run_wizard () {
    # Page 1: Welcome
    clear
    echo -e "${InvGreen} ${InvDkGray}${CWhite} STUNMON  |  First-Run Setup Wizard                                                  ${CClear}"
    echo -e "${InvGreen} ${CClear}"
    echo -e "${InvGreen} ${CClear} Welcome to STUNMON. This wizard will configure your first stunnel slot.${CClear}"
    echo -e "${InvGreen} ${CClear}"
    echo -e "${InvGreen} ${CClear} STUNMON manages stunnel, which wraps OpenVPN TCP traffic inside a genuine${CClear}"
    echo -e "${InvGreen} ${CClear} TLS session. To a deep packet inspection system the connection is identical${CClear}"
    echo -e "${InvGreen} ${CClear} to standard HTTPS browser traffic.${CClear}"
    echo -e "${InvGreen} ${CClear}"
    echo -e "${InvGreen} ${CClear} Before continuing, ensure you have the following files from your VPN provider:${CClear}"
    echo -e "${InvGreen} ${CClear}"
    echo -e "${InvGreen} ${CClear}   * An stunnel .ssl config file   ${CDkGray}(e.g. AirVPN_..._SSL-443.ssl)${CClear}"
    echo -e "${InvGreen} ${CClear}   * An stunnel CA certificate      ${CDkGray}(e.g. stunnel.crt)${CClear}"
    echo -e "${InvGreen} ${CClear}   * An stunnel .ovpn file loaded in the router's VPN client slot${CClear}"
    echo -e "${InvGreen} ${CClear}     ${CDkGray}(a specific .ovpn file that references 'remote 127.0.0.1 PORT')${CClear}"
    echo -e "${InvGreen} ${CClear}"
    echo -e "${InvGreen} ${CClear} Copy the .ssl and .crt files to /jffs/scripts/ for easy selection.${CClear}"
    echo -e "${InvGreen} ${CClear}"
    echo -e "${InvGreen} ${CClear}${CDkGray}--------------------------------------------------------------------------------------${CClear}"

    # Check stunnel binary
    echo -e "${InvGreen} ${CClear}"
    if [ -n "$STUNNEL_BIN" ]; then
        local _SVER; _SVER=$("$STUNNEL_BIN" -version 2>&1 | sed -n '2p')
        echo -e "${InvGreen} ${CClear}   stunnel Status : ${CGreen}Installed${CClear} (${STUNNEL_BIN})"
        echo -e "${InvGreen} ${CClear}   Version        : ${CGreen}${_SVER}${CClear}"
    else
        echo -e "${InvGreen} ${CClear}   stunnel Status : ${CRed}Not installed${CClear}"
        echo -e "${InvGreen} ${CClear}   Install via    : ${CWhite}opkg install stunnel${CClear}"
    fi
    echo -e "${InvGreen} ${CClear}"
    echo -e "${InvGreen} ${CClear}${CDkGray}  -----------------------------------------------------------------------${CClear}"
    echo ""
    stty_normal
    printf " Press ENTER to begin, or e to exit: "
    read -r _K
    [ "$(echo "$_K" | tr '[:upper:]' '[:lower:]')" = "e" ] && return

    if [ -z "$STUNNEL_BIN" ]; then
        stty_normal
        printf " stunnel is not installed. Install via opkg now? [y/n]: "
        read -r _INST
        if [ "$(echo "$_INST" | tr '[:upper:]' '[:lower:]')" = "y" ]; then
            echo ""
            echo -e " ${CWhite}Installing stunnel via opkg...${CClear}"
            if opkg install stunnel 2>&1; then
                find_binaries
                echo -e " ${CGreen}stunnel installed successfully.${CClear}"
            else
                echo -e " ${CRed}Installation failed. Ensure Entware is installed and router has internet access.${CClear}"
                stty_normal
                printf " Press ENTER to continue anyway, or e to exit: "
                read -r _K2
                [ "$(echo "$_K2" | tr '[:upper:]' '[:lower:]')" = "e" ] && return
            fi
        fi
    fi

    # Page 2: Slot number and provider
    clear
    echo -e "${InvGreen} ${InvDkGray}${CWhite} stunmon v${Version} -- Step 1 of 4: Slot and Provider                                      ${CClear}"
    echo -e "${InvGreen} ${CClear}"
    echo -e "${InvGreen} ${CClear} Which OVPN client slot is configured with your provider's stunnel .ovpn?${CClear}"
    echo -e "${InvGreen} ${CClear} ${CDkGray}(The specific .ovpn that references 'remote 127.0.0.1 PORT')${CClear}"
    echo -e "${InvGreen} ${CClear}"
    echo -e "${InvGreen} ${CClear}${CDkGray}  -----------------------------------------------------------------------${CClear}"
    echo ""
    local SLOT PROV
    while true; do
        stty_normal
        printf " OVPN slot number [1-5]: "
        read -r SLOT
        case "$SLOT" in [1-5]) break ;;
            *) echo -e "  ${CRed}Enter a number between 1 and 5.${CClear}" ;;
        esac
    done
    stty_normal
    printf " VPN Provider name (e.g. AirVPN): "
    read -r PROV
    PROV=${PROV:-"Unknown"}

    # Page 3: SSL config file
    clear
    echo -e "${InvGreen} ${InvDkGray}${CWhite} stunmon v${Version} -- Step 2 of 4: stunnel .ssl Config File                              ${CClear}"
    echo -e "${InvGreen} ${CClear}"
    echo -e "${InvGreen} ${CClear} Select the stunnel client config file provided by your VPN provider.${CClear}"
    echo -e "${InvGreen} ${CClear}"
    echo -e "${InvGreen} ${CClear}   This is the stunnel .ssl file (not the .ovpn file) that defines the TLS tunnel:${CClear}"
    echo -e "${InvGreen} ${CClear}   ${CYellow}accept = 127.0.0.1:1413     (local OpenVPN connects here)${CClear}"
    echo -e "${InvGreen} ${CClear}   ${CYellow}connect = 64.x.x.x:443      (your VPN provider's stunnel server)${CClear}"
    echo -e "${InvGreen} ${CClear}   ${CYellow}verify = 3                  (verify server cert against CA cert)${CClear}"
    echo -e "${InvGreen} ${CClear}"
    echo -e "${InvGreen} ${CClear}   For AirVPN this file is named: ${CDkGray}AirVPN_..._SSL-443.ssl${CClear}"
    echo -e "${InvGreen} ${CClear}   Copy it to /jffs/scripts/ before continuing.${CClear}"
    echo -e "${InvGreen} ${CClear}"
    echo -e "${InvGreen} ${CClear}${CDkGray}  -----------------------------------------------------------------------${CClear}"

    local SSLF=""
    while true; do
        pick_file "*.ssl" "stunnel .ssl config"
        SSLF="$PICKED_FILE"
        [ -z "$SSLF" ] && echo -e "  ${CYellow}No file selected. Try again or copy the file to /jffs/scripts/.${CClear}" && continue
        if [ ! -f "$SSLF" ]; then
            echo -e "  ${CRed}File not found: ${SSLF}${CClear}"; continue
        fi
        if ! grep -qi 'accept\|connect' "$SSLF" 2>/dev/null; then
            echo -e "  ${CYellow}Warning: file does not look like a stunnel config (no accept/connect lines found).${CClear}"
            stty_normal
            printf " Use it anyway? [y/n]: "
            read -r _CHK; [ "$(echo "$_CHK" | tr '[:upper:]' '[:lower:]')" = "y" ] && break
            continue
        fi
        break
    done
    echo -e "  ${CGreen}SSL config selected: ${SSLF}${CClear}"

    # Page 4: CA certificate
    clear
    echo -e "${InvGreen} ${InvDkGray}${CWhite} stunmon v${Version} -- Step 3 of 4: CA Certificate                                        ${CClear}"
    echo -e "${InvGreen} ${CClear}"
    echo -e "${InvGreen} ${CClear} Select the CA certificate file provided by your VPN provider.${CClear}"
    echo -e "${InvGreen} ${CClear}"
    echo -e "${InvGreen} ${CClear}   This .crt file proves the remote stunnel server is your VPN provider.${CClear}"
    echo -e "${InvGreen} ${CClear}   stunnel will reject any server whose certificate is not signed by this CA.${CClear}"
    echo -e "${InvGreen} ${CClear}"
    echo -e "${InvGreen} ${CClear}   For AirVPN this file is named: ${CYellow}stunnel.crt${CClear}"
    echo -e "${InvGreen} ${CClear}   Copy it to /jffs/scripts/ before continuing.${CClear}"
    echo -e "${InvGreen} ${CClear}"
    echo -e "${InvGreen} ${CClear}${CDkGray}  -----------------------------------------------------------------------${CClear}"

    local CERTF=""
    while true; do
        pick_file "*.crt *.pem" "CA certificate"
        CERTF="$PICKED_FILE"
        [ -z "$CERTF" ] && echo -e "  ${CYellow}No file selected. Try again.${CClear}" && continue
        if [ ! -f "$CERTF" ]; then
            echo -e "  ${CRed}File not found: ${CERTF}${CClear}"; continue
        fi
        if ! grep -q 'BEGIN CERTIFICATE' "$CERTF" 2>/dev/null; then
            echo -e "  ${CRed}File is not a valid PEM certificate (no BEGIN CERTIFICATE header found).${CClear}"; continue
        fi
        break
    done
    echo -e "  ${CGreen}CA certificate selected: ${CERTF}${CClear}"

    # Page 5: Optional settings
    clear
    echo -e "${InvGreen} ${InvDkGray}${CWhite} stunmon v${Version} -- Step 4 of 4: Optional Settings                                    ${CClear}"
    echo -e "${InvGreen} ${CClear}"
    echo -e "${InvGreen} ${CClear} SNI Hostname (optional -- leave blank to skip):${CClear}"
    echo -e "${InvGreen} ${CClear}"
    echo -e "${InvGreen} ${CClear}   When set, stunmon sends this hostname in the TLS ClientHello SNI field.${CClear}"
    echo -e "${InvGreen} ${CClear}   To a DPI system it looks like traffic to a legitimate service.${CClear}"
    echo -e "${InvGreen} ${CClear}   ${CYellow}Examples: onedrive.live.com  outlook.live.com  www.microsoft.com${CClear}"
    echo -e "${InvGreen} ${CClear}   ${CYellow}Note: IP-level correlation still reveals the true destination.${CClear}"
    echo -e "${InvGreen} ${CClear}"
    echo -e "${InvGreen} ${CClear}${CDkGray}  -----------------------------------------------------------------------${CClear}"
    echo ""
    local SNIHOST
    stty_normal
    printf " SNI hostname (press ENTER to skip): "
    read -r SNIHOST

    # Confirm and save
    clear
    echo -e "${InvGreen} ${InvDkGray}${CWhite} stunmon v${Version} -- Confirm Configuration                                              ${CClear}"
    echo -e "${InvGreen} ${CClear}"
    echo -e "${InvGreen} ${CClear}   Slot         : ${CWhite}${SLOT}${CClear}"
    echo -e "${InvGreen} ${CClear}   Provider     : ${CWhite}${PROV}${CClear}"
    echo -e "${InvGreen} ${CClear}   SSL config   : ${CGreen}${SSLF}${CClear}"
    echo -e "${InvGreen} ${CClear}   CA cert      : ${CGreen}${CERTF}${CClear}"
    [ -n "$SNIHOST" ] && \
    echo -e "${InvGreen} ${CClear}   SNI hostname : ${CYellow}${SNIHOST}${CClear}"
    echo -e "${InvGreen} ${CClear}   Debug level  : ${CWhite}0${CClear} (silent/production)"
    echo -e "${InvGreen} ${CClear}   TCP_NODELAY  : ${CGreen}enabled${CClear}"
    echo -e "${InvGreen} ${CClear}"
    echo -e "${InvGreen} ${CClear}${CDkGray}  -----------------------------------------------------------------------${CClear}"
    echo ""
    stty_normal
    printf " Save this configuration and start stunmon? [y/n]: "
    read -r _GO
    if [ "$(echo "$_GO" | tr '[:upper:]' '[:lower:]')" != "y" ]; then
        echo -e "  ${CYellow}Configuration not saved. Run stunmon.sh -setup to configure at any time.${CClear}"
        sleep 2; return
    fi

    # Populate and save config
    STUNMON_MANAGED_SLOTS="$SLOT"
    set_sv "$SLOT" ENABLED        1
    set_sv "$SLOT" PROVIDER       "$PROV"
    set_sv "$SLOT" SSL_CONF       "$SSLF"
    set_sv "$SLOT" CERT           "$CERTF"
    set_sv "$SLOT" SNI_HOST       "$SNIHOST"
    set_sv "$SLOT" DEBUG_LEVEL    0
    set_sv "$SLOT" TCP_NODELAY    1
    set_sv "$SLOT" VERIFY         3
    set_sv "$SLOT" TIMEOUTCLOSE   0
    set_sv "$SLOT" LOCAL_HOST     "127.0.0.1"
    set_sv "$SLOT" LOCAL_PORT     "1413"
    set_sv "$SLOT" REMOTE_HOST    ""
    set_sv "$SLOT" REMOTE_PORT    "443"

    echo -e "  ${CWhite}Parsing connection parameters from .ssl file...${CClear}"
    if parse_ssl_conf "$SLOT"; then
        echo -e "  ${CGreen}Parsed: local=$(get_sv $SLOT LOCAL_HOST):$(get_sv $SLOT LOCAL_PORT)  remote=$(get_sv $SLOT REMOTE_HOST):$(get_sv $SLOT REMOTE_PORT)${CClear}"
    else
        echo -e "  ${CYellow}Could not auto-parse .ssl file. Set remote host manually in setup (option 6).${CClear}"
    fi

    save_config

    echo -e "  ${CWhite}Generating stunnel config and starting...${CClear}"
    if generate_stunnel_conf "$SLOT"; then
        mkdir -p "$(slot_rundir $SLOT)" 2>/dev/null
        record_start_time "$SLOT"
        stunmon_start "$SLOT"
        update_status_file
        echo -e "  ${CGreen}stunmon started for slot ${SLOT}. Use stunmon.sh to monitor.${CClear}"
        slog_info "first_run: slot ${SLOT} configured and started (${PROV})"
    else
        echo -e "  ${CYellow}Config generation had issues. Use stunmon.sh -setup to review and fix.${CClear}"
        save_config
    fi
    sleep 3
}

# Section 13 -- Main dispatch
# ============================================================================================================================

main () {
		
		# Check for and add an alias for STUNMON
		if ! grep -F "sh /jffs/scripts/stunmon.sh" /jffs/configs/profile.add >/dev/null 2>/dev/null; then
		  echo "alias stunmon=\"sh /jffs/scripts/stunmon.sh\" # added by stunmon" >> /jffs/configs/profile.add
		fi

    create_dirs
    find_binaries
    load_config

    # Parse command
    local CMD="${1:-}"
    local SLOT="${2:-}"

    case "$CMD" in
        -setup|--setup)
            if [ -z "$STUNMON_MANAGED_SLOTS" ]; then
                first_run_wizard
            else
                setup_menu
            fi
            ;;

        -start|--start)
            if [ -n "$SLOT" ]; then
                echo -e "${CGreen}Starting stunnel for slot ${SLOT}...${CClear}"
                generate_stunnel_conf "$SLOT" || exit 1
                record_start_time "$SLOT"
                stunmon_start "$SLOT"
                update_status_file
                trimlogs
            else
                for S in $STUNMON_MANAGED_SLOTS; do
                    [ "$(get_sv $S ENABLED)" = "0" ] && continue
                    echo -e "${CGreen}Starting slot ${S}...${CClear}"
                    generate_stunnel_conf "$S"
                    record_start_time "$S"
                    stunmon_start "$S"
                done
                update_status_file
                trimlogs
            fi
            ;;

        -stop|--stop)
            if [ -n "$SLOT" ]; then
                echo -e "${CYellow}Stopping stunnel for slot ${SLOT}...${CClear}"
                stunmon_stop "$SLOT"
                update_status_file
                trimlogs
            else
                for S in $STUNMON_MANAGED_SLOTS; do
                    echo -e "${CYellow}Stopping slot ${S}...${CClear}"
                    stunmon_stop "$S"
                done
                update_status_file
                trimlogs
            fi
            ;;

        -restart|--restart)
            if [ -n "$SLOT" ]; then
                echo -e "${CGreen}Restarting stunnel for slot ${SLOT}...${CClear}"
                stunmon_restart "$SLOT"
                update_status_file
                trimlogs
                
            else
                for S in $STUNMON_MANAGED_SLOTS; do
                    [ "$(get_sv $S ENABLED)" = "0" ] && continue
                    echo -e "${CGreen}Restarting slot ${S}...${CClear}"
                    stunmon_restart "$S"
                done
                update_status_file
                trimlogs
            fi
            ;;

        -status|--status)
            if [ -n "$SLOT" ]; then
                stunmon_status "$SLOT"
                exit $?
            else
                for S in $STUNMON_MANAGED_SLOTS; do
                    stunmon_status "$S"
                done
            fi
            ;;

        -check|--check)
            # Single health check cycle -- intended for cron
            # Example crontab: */1 * * * * /jffs/scripts/stunmon.sh -check
            health_check_all
            trimlogs
            ;;

        -reset|--reset)
            if [ -n "$SLOT" ]; then
                echo -e "${CYellow}Resetting slot ${SLOT}...${CClear}"
                stunmon_stop "$SLOT"
                service "stop_vpnclient${SLOT}" >/dev/null 2>&1
                        rm -rf "$(slot_rundir $SLOT)" 2>/dev/null
                save_config; update_status_file; trimlogs
                echo -e "${CGreen}Slot ${SLOT} reset.${CClear}"
            else
                for S in $STUNMON_MANAGED_SLOTS; do
                    stunmon_stop "$S"
                    set_sv "$S" FAIL_COUNT 0
                    rm -rf "$(slot_rundir $S)" 2>/dev/null
                done
                save_config; update_status_file; trimlogs
            fi
            ;;

        -h|--help|-help)
            echo ""
            echo -e "${CWhite}STUNMON v${Version} -- stunnel Connection Manager${CClear}"
            echo ""
            echo "Usage:  stunmon.sh [command] [slot]"
            echo ""
            echo "  (no args)         Interactive monitoring display"
            echo "  -setup            Configuration menu (first-run wizard if unconfigured)"
            echo "  -start  [slot]    Start stunnel for slot (default: all managed slots)"
            echo "  -stop   [slot]    Stop  stunnel for slot"
            echo "  -restart[slot]    Restart stunnel for slot"
            echo "  -status [slot]    Print status; exit 0=running 1=stopped"
            echo "  -check            Run one health check cycle (use with cron)"
            echo "  -reset  [slot]    Stop, clear fail counter, remove runtime files"
            echo "  -h / --help       This help"
            echo ""
            echo "Cron example (health check every minute):"
            echo "  * * * * * /jffs/scripts/stunmon.sh -check >/dev/null 2>&1"
            echo ""
            echo "Files:"
            echo "  Config  : ${STUNMON_CFG}"
            echo "  Status  : ${STUNMON_STATUS}  (read by VPNMON-R3)"
            echo "  Log     : ${STUNMON_LOG}"
            echo ""
            ;;

        -screen)
				    /opt/sbin/screen -wipe >/dev/null 2>&1 # Kill any dead screen sessions
				    sleep 1
				    ScreenSess=$(/opt/sbin/screen -ls | grep "stunmon" | awk '{print $1}' | cut -d . -f 1)
				      if [ -z $ScreenSess ]; then
				        if [ "$SLOT" = "-now" ]; then
				          /opt/sbin/screen -dmS "stunmon" $APPPATH
				          sleep 1
				          /opt/sbin/screen -r stunmon
				        else
				          clear
				          echo -e "${CClear}Executing ${CGreen}STUNMON v$Version${CClear} using the SCREEN utility..."
				          echo ""
				          echo -e "${CClear}IMPORTANT:"
				          echo -e "${CClear}In order to keep STUNMON running in the background,"
				          echo -e "${CClear}properly exit the SCREEN session by using: ${CGreen}CTRL-A + D${CClear}"
				          echo ""
				          /opt/sbin/screen -dmS "stunmon" $APPPATH
				          sleep 5
				          /opt/sbin/screen -r stunmon
				          exit 0
				        fi
				      else
				        if [ "$SLOT" = "-now" ]; then
				          sleep 1
				        else
				          clear
				          echo -e "${CClear}Connecting to existing ${CGreen}STUNMON v$Version${CClear} SCREEN session...${CClear}"
				          echo ""
				          echo -e "${CClear}IMPORTANT:${CClear}"
				          echo -e "${CClear}In order to keep STUNMON running in the background,${CClear}"
				          echo -e "${CClear}properly exit the SCREEN session by using: ${CGreen}CTRL-A + D${CClear}"
				          echo ""
				          echo -e "${CClear}Switching to the SCREEN session in T-5 sec...${CClear}"
				          echo -e "${CClear}"
				          spinner 5
				        fi
				      fi
				    /opt/sbin/screen -dr $ScreenSess
				    exit 0
			      ;;
			      
        "")
            # Interactive display -- first-run wizard if not configured
            if [ -z "$STUNMON_MANAGED_SLOTS" ]; then
                first_run_wizard
                load_config
            fi
            update_status_file
            trimlogs
            # Kick off background TLS probe for any running slot without a cache
            for _PS in $STUNMON_MANAGED_SLOTS; do
                if stunmon_alive "$_PS" &&                    [ ! -f "$(slot_rundir $_PS)/tls_cache" ]; then
                    probe_tls_info "$_PS" &
                fi
            done
            display_main
            ;;

        *)
            echo "Unknown command: ${CMD}  (use -h for help)"
            exit 1
            ;;
    esac
}

main "$@"
