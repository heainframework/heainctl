#!/usr/bin/env bash
# heainctl live test 5a: the Config API of a real heain-core tree, driven only through heainctl.
#   G (18000, root) <- Z (18001). Identities: admin (install-time, every role), approver-1, ops-1, view-1.
#  - profiles name certificate files; the node's certificate is verified against the CA;
#  - roles.admins proposed (2b) and approved by an Approver through heainctl; the roles take effect;
#  - a viewer is refused a change (exit 1 with core's message); an operator changes a 2a key;
#  - the fleet view; remote admin through the Master (--node Z): runs on Z, forwarded by G, audited;
#  - config history, diff, export, drift, a dry run; audit and its verification; events; a provisioning token;
#  - --json for scripts; exit codes 2 (usage) and 3 (unreachable).
# Needs ~/heain-core. ~2 min.
# Run from ~/heainctl:  bash scripts/live_5a.sh
set -uo pipefail
HC=$(cd "$(dirname "$0")/.." && pwd)
cd ~/heain-core || { echo "needs ~/heain-core"; exit 1; }
H=./test_1_2_live.sh
T=$HOME/heain-core/.test-1.2
C=$T/certs; L=$T/logs; P=$T/pids; BIN=$T/node; W=$T/heainctl-5a
G=https://127.0.0.1:18000; Z=https://127.0.0.1:18001
PASS=0; FAIL=0
ok()  { echo "  PASS: $*"; PASS=$((PASS+1)); }
bad() { echo "  FAIL: $*"; FAIL=$((FAIL+1)); }
as() { local who=$1; shift; curl -sk --noproxy '*' --cert "$C/$who.pem" --key "$C/$who.key" --cacert "$C/ca.pem" "$@"; }
j() { python3 -c "import json,sys;d=json.load(sys.stdin);print($1)" 2>/dev/null; }
mkcert() { [ -f "$C/$1.pem" ] && return; openssl genrsa -out "$C/$1.key" 2048 >/dev/null 2>&1
  openssl req -new -key "$C/$1.key" -subj "/CN=$1" -out "$C/$1.csr" >/dev/null 2>&1
  openssl x509 -req -in "$C/$1.csr" -CA "$C/ca.pem" -CAkey "$C/ca.key" -CAcreateserial -out "$C/$1.pem" \
    -days 825 -sha256 -extfile <(printf "subjectAltName=DNS:%s" "$1") >/dev/null 2>&1; chmod 600 "$C/$1.key"; }
CTL() { HEAINCTL_CONFIG=$W/heainctl.json NO_PROXY='*' "$W/heainctl" "$@"; }
# rc <args>: the exit code only
rc() { CTL "$@" >/dev/null 2>&1; echo $?; }
f() { as admin $1/v1/admin/config | j "[x for x in d['fields'] if x['key']=='$2'][0]$3"; }
COMMON="-ca=$C/ca.pem -admin-node-id=admin -approver-ids=approver-1"
node() { local id=$1 tier=$2 port=$3 raft=$4 pp=$5 pid=$6; shift 6
  local par=""; [ -n "$pp" ] && par="-parent-addr=https://127.0.0.1:$pp/health -parent-node-id=$pid -promote-raft-addr=127.0.0.1:$(( raft + 100 )) -promote-data-dir=$T/promote-$id"
  nohup "$BIN" -node-id=$id -tier=$tier -raft-addr=127.0.0.1:$raft -data-dir="$T/data-$id" -http-addr=127.0.0.1:$port \
    -cert="$C/$id.pem" -key="$C/$id.key" $COMMON -bootstrap=true -approval-store-path="$T/data-$id/approvals.db" \
    -ingest-queue-path="$T/data-$id/queue.db" $par "$@" >> "$L/$id.log" 2>&1 &
  echo $! > "$P/$id.pid"; }

echo "== 0. G <- Z; build heainctl"
$H clean >/dev/null; $H build >/dev/null || { echo "core build failed"; exit 1; }; $H certs >/dev/null
mkdir -p "$L" "$P" "$T/data-G" "$T/data-Z" "$W"; for c in admin approver-1 ops-1 view-1; do mkcert $c; done
openssl genrsa -out "$W/prov.key" 2048 >/dev/null 2>&1
openssl req -new -key "$W/prov.key" -subj "/CN=heain-test-provisioning-ca" -out "$W/prov.csr" >/dev/null 2>&1
openssl x509 -req -in "$W/prov.csr" -CA "$C/ca.pem" -CAkey "$C/ca.key" -CAcreateserial -out "$W/prov.pem" -days 30 -sha256 \
  -extfile <(printf "basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign") >/dev/null 2>&1
: > "$L/G.log"; : > "$L/Z.log"
node G GLOBAL_PRIMARY 18000 19000 "" "" -provision-ca-cert=$W/prov.pem -provision-ca-key=$W/prov.key; sleep 4
node Z SECONDARY 18001 19001 18000 G -farm-registry-ttl=30s; sleep 4
( cd "$HC" && GOFLAGS= GOWORK=off go build -ldflags "-X github.com/heainframework/heainctl/internal/ctl.Version=live-5a" -o "$W/heainctl" ./cmd/heainctl ) \
  && [ "$(CTL version)" = "heainctl live-5a" ] && ok "heainctl builds" || { bad "build"; $H stop-all >/dev/null 2>&1; exit 1; }
[ "$(as admin -o /dev/null -w '%{http_code}' -X PUT -d '{"value":"2s"}' $G/v1/admin/config/system/config.sync_interval)" = 200 ] || bad "sync interval"

echo "== 1. profiles"
for who in admin approver-1 ops-1 view-1; do CTL profile add $who --url $G --cert "$C/$who.pem" --key "$C/$who.key" --ca "$C/ca.pem" >/dev/null || bad "profile $who"; done
[ "$(CTL profile list --json | j "(d['current'], sorted(d['profiles']))")" = "('admin', ['admin', 'approver-1', 'ops-1', 'view-1'])" ] && ! grep -q "PRIVATE KEY" "$W/heainctl.json" \
  && [ "$(stat -c %a "$W/heainctl.json")" = 600 ] && ok "four profiles (admin current); the file names the key files, holds no key, mode 600" || bad "profiles"
[ "$(CTL whoami --json | j "(d['node'], d['identity'], sorted(d['roles']))")" = "('G', 'admin', ['operator', 'policy-admin', 'security-admin', 'viewer'])" ] \
  && o=$(CTL whoami) && echo "$o" | grep -q "^identity: *admin" && ok "whoami: admin holds every role on G (table and --json)" || bad "whoami: $(CTL whoami --json)"

echo "== 2. roles through P5, with heainctl on both sides"
r=$(CTL config propose roles.admins '{"ops-1":["operator"],"view-1":["viewer"]}' --reason "two more admins" --json)
A=$(echo "$r" | j "d['action_id']"); [ -n "$A" ] && ok "admin proposed roles.admins (2b) -> P5 $A" || bad "propose: $r"
o=$(CTL --profile approver-1 policy pending); echo "$o" | grep -q "$A" && ok "the Approver sees it in policy pending (table)" || bad "pending: $(CTL --profile approver-1 policy pending)"
e=$(CTL policy approve $A 2>&1); c=$?
[ "$c" = 1 ] && echo "$e" | grep -q "403" && ok "admin is not an Approver: refused, exit 1 with core's answer" || bad "admin approve: $c $e"
r=$(CTL --profile approver-1 policy approve $A --json 2>&1); [ "$(echo "$r" | j "d['approver'], d['result'] in ('APPROVED', 'AUTO_APPROVED')")" = "approver-1 True" ] && ok "approver-1 approved it" || bad "approve: $r"
for k in $(seq 1 10); do [ "$(CTL --profile ops-1 whoami --json | j "','.join(d['roles'])")" = "operator,viewer" ] && break; sleep 1; done
[ "$(CTL --profile ops-1 whoami --json | j "','.join(d['roles'])")$(CTL --profile view-1 whoami --json | j "','.join(d['roles'])")" = "operator,viewerviewer" ] && ok "ops-1 is an operator, view-1 a viewer" || bad "roles"

echo "== 3. changes, refusals, the fleet"
e=$(CTL --profile view-1 config set apps.heartbeat_interval 9s 2>&1); c=$?
[ "$c" = 1 ] && echo "$e" | grep -q "^heainctl: 403" && ok "a viewer may not change a key: exit 1, core's 403 shown" || bad "viewer set: $c $e"
[ "$(CTL --profile ops-1 config set apps.heartbeat_interval 9s --json | j "d['status']")" = applied ] && [ "$(f $G apps.heartbeat_interval "['value']")" = 9s ] && ok "ops-1 set a 2a key on G (applied at once)" || bad "ops set"
[ "$(CTL config get apps.heartbeat_interval --json | j "(d['value'], d['part'])")" = "('9s', 'system')" ] && ok "config get" || bad "config get"
for k in $(seq 1 30); do [ "$(CTL nodes list --json | j "sorted(n['node'] for n in d['nodes'])")" = "['G', 'Z']" ] && break; sleep 2; done
o=$(CTL nodes list); echo "$o" | grep -q "^[A-Z_]" && echo "$o" | grep -qw Z && ok "nodes list: G and Z (the fleet view, as a table)" || bad "nodes: $(CTL nodes list --json | j "[(n['node'], sorted(n)) for n in d['nodes']]")"

echo "== 4. remote admin through the Master"
for k in $(seq 1 30); do [ "$(CTL --profile ops-1 --node Z whoami --json | j "','.join(d['roles'])")" = "operator,viewer" ] && break; sleep 2; done
[ "$(CTL --profile ops-1 --node Z whoami --json | j "(d['node'], d['identity'], d['forwarded_by'])")" = "('Z', 'ops-1', 'G')" ] && ok "--node Z: whoami runs on Z as ops-1, forwarded by G" || bad "fwd whoami: $(CTL --profile ops-1 --node Z whoami --json)"
CTL --profile ops-1 --node Z config set apps.heartbeat_interval 7s >/dev/null
[ "$(f $Z apps.heartbeat_interval "['value']")$(f $G apps.heartbeat_interval "['value']")" = 7s9s ] && ok "a change through G lands on Z only" || bad "fwd set: Z=$(f $Z apps.heartbeat_interval "['value']")"
CTL profile add z-ops --url $G --cert "$C/ops-1.pem" --key "$C/ops-1.key" --ca "$C/ca.pem" --node Z >/dev/null
[ "$(CTL --profile z-ops config get apps.heartbeat_interval --json | j "d['value']")" = 7s ] && ok "a profile can name its target node (z-ops)" || bad "profile node"
[ "$(as admin "$Z/v1/admin/audit?limit=2000" | j "sum(1 for x in d['records'] if 'forward' in x['event']['Action'] or (x['event'].get('Detail') or {}).get('forwarded_by')=='G')")" -ge 1 ] 2>/dev/null \
  && ok "Z's audit records the forwarded requests" || bad "fwd audit"

echo "== 5. config history, export, drift"
H1=$(CTL config history --json | j "max(x.get('version', x.get('n', 0)) for x in (d if isinstance(d, list) else next(v for v in d.values() if isinstance(v, list))))")
o=$(CTL config history); [ -n "$H1" ] && echo "$o" | head -1 | grep -q "^[A-Z]" && ok "config history (latest version $H1)" || bad "history: $(CTL config history --json | head -c 300)"
CTL config export -o "$W/export.json" 2>/dev/null; python3 -c "import json;json.load(open('$W/export.json'))" && ok "config export -o: valid JSON" || bad "export"
[ "$(CTL config changes --data '{"set":{"apps.heartbeat_interval":"11s"}}' --dry-run --json | j "d.get('dry_run', True)")" != "" ] && [ "$(f $G apps.heartbeat_interval "['value']")" = 9s ] && ok "a dry run changes nothing" || bad "dry run: $(f $G apps.heartbeat_interval "['value']")"
c=$(rc --node Z config drift); [ "$c" = 0 ] && ok "config drift on Z (against its parent)" || bad "drift: $(CTL --node Z config drift 2>&1 | head -c 300)"

echo "== 6. audit, events, tokens, raw"
[ "$(CTL audit verify --json | j "d['ok']")" = True ] && o=$(CTL audit verify) && echo "$o" | grep -q "^ok: *yes" && ok "audit verify: the chain holds" || bad "verify: $(CTL audit verify --json)"
o=$(CTL audit list --limit 5); echo "$o" | head -1 | grep -q "^SEQ" && ok "audit list --limit 5 (table)" || bad "audit list: $(CTL audit list --limit 5 | head -3)"
[ "$(CTL events --after 0 --types 'config.*' --json | j "len(d['events'])>0")" = True ] && ok "events: the config changes" || bad "events: $(CTL events --after 0 --json | head -c 300)"
CTL provision token shop.s1 -o "$W/tok.json" 2>/dev/null; [ "$(stat -c %a "$W/tok.json")" = 600 ] && [ -n "$(j "d['token']" < "$W/tok.json")" ] && ok "provision token -o: written 0600" || bad "token"
[ "$(CTL raw GET /v1/admin/inventory --json | j "d['node']")" = G ] && ok "raw GET for anything else" || bad "raw"
CTL diagnostics bundle -o "$W/bundle.tgz" 2>/dev/null; tar tzf "$W/bundle.tgz" >/dev/null 2>&1 && ok "diagnostics bundle -o: a tar.gz" || bad "bundle"

echo "== 7. exit codes"
[ "$(rc config frob)$(rc whoami --nope)$(rc config set onlykey)" = 222 ] && ok "usage mistakes: exit 2" || bad "usage"
[ "$(rc whoami --url https://127.0.0.1:18999)" = 3 ] && ok "nothing listening: exit 3" || bad "unreachable"
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$W/other.key" -out "$W/other.pem" -days 1 -subj "/CN=other" >/dev/null 2>&1
[ "$(rc whoami --ca "$W/other.pem")" = 3 ] && ok "a node whose certificate the CA did not sign: refused, exit 3" || bad "foreign ca"

echo "== cleanup"
$H stop-all >/dev/null 2>&1
echo
echo "RESULT: $PASS passed, $FAIL failed"
echo "(logs: $W)"
