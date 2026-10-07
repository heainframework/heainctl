# heainctl

The command line for heain-core's Config API (`/v1/admin/*`) (Step 5a, 2026-10-08). It is a thin client: core checks every role, four-eyes and P5. heainctl sends what your identity asks for and shows core's answer.

- **One binary** that uses only the Go standard library. Install it with `go install github.com/heainframework/heainctl/cmd/heainctl@latest`, or with `go build ./cmd/heainctl`.
- **Your admin certificate** is the identity. Its CN gets roles through `roles.admins` (viewer, operator, policy-admin, security-admin), or is an Approver (`roles.approvers`).
- **The node's certificate** is always verified against the deployment's CA. Use `--server-name` when you connect by an address that is not in its SAN.

## Author decisions (2026-10-08)

Step 5 runs in this order:
1. **5a:** heainctl.
2. **5b:** heain-console, the web screens behind heain-gateway.
3. **5c:** the license.

heainctl is one tool for the whole admin surface, with profiles, remote admin through a Master, and JSON for automation. It is its own repo, as spec 03 proposed, so the closed core binary stays minimal.

## Profiles

```sh
heainctl profile add prod --url https://10.0.0.1:18000 --cert ops.pem --key ops.key --ca ca.pem
heainctl profile add zone-2 --url https://10.0.0.1:18000 --cert ops.pem --key ops.key --ca ca.pem --node Z2   # a node below, through the Master
heainctl profile use prod
heainctl profile list
```

- **Where they are kept:** `~/.config/heainctl/config.json` (mode 600), or `$HEAINCTL_CONFIG`.
- **What a profile holds:** it names the certificate, key and CA files, and never holds a key. heainctl warns when a key file can be read by others.
- **Choosing one:** `--profile` or `$HEAINCTL_PROFILE` picks a profile. `--url`, `--cert`, `--key`, `--ca`, `--server-name` and `--node` override it.

## Commands

`heainctl help` lists the areas, and `heainctl help <area>` lists the commands in one area.

| Area | Commands |
|---|---|
| who and where | `whoami`, `nodes list`, `nodes get ID`, `roles list`, `roles set NODE --data` |
| config | `config list`, `get KEY`, `set KEY VALUE` (2a, at once), `propose KEY VALUE --reason` (2b, P5), `changes --data '{"set":{},"unset":[]}' [--dry-run] [--confirm-within 10m]`, `history`, `version N`, `confirm N`, `diff FROM [TO]`, `export [-o FILE]`, `import FILE [--replace]`, `rollback VERSION`, `drift [BASELINE]` |
| P5 | `policy pending [--subtree]`, `policy approve ID`, `policy reject ID [--reason]` |
| apps | `apps list`, `instances`, `packages`, `deploy APP VERSION`, `stop / start / restart INSTANCE`, `remove APP`, `rollback APP`, `package-add PACKAGE_JSON`, `package-upload APP VERSION ARCHIVE`, `package-fetch APP VERSION` |
| core releases | `releases list`, `add RELEASE_JSON`, `upload VERSION BINARY`, `fetch VERSION`; `upgrade apply VERSION`, `upgrade rollback`; `rollouts list`, `get`, `create --version V [--kind --app --targets --canary --soak --dry-run]`, `pause / resume / abort / rollback ID` |
| observation | `audit list [--from --limit]`, `audit verify`, `journal list`, `journal verify`, `metrics list [--since 1h]`, `metrics latest`, `inventory`, `alerts`, `events [--after] [--types alert.*,config.*] [--follow]` |
| governance | `legal-hold list`, `set TICKET... --reason`, `lift TICKET... --reason`; `duty-profiles list`, `set SLOT FILE`; `governance metrics`, `governance ack KEY`; `breakglass status`, `breakglass ack --comment` |
| license (Step 5c) | `license show`, `license install LICENSE_JSON` (security-admin; at the root it reaches the whole tree), `license remove` |
| support | `diagnostics bundle -o FILE`, `logs APP.INSTANCE`, `matrix`, `connectivity`; `provision token LABEL -o FILE` (written 0600) |
| anything else | `raw METHOD PATH [--data JSON\|@file]` |

**`VALUE`** is JSON when it parses as JSON, and a string otherwise (`7s`, `'{"ops-1":["operator"]}'`).

**Remote admin:** `--node ID` runs any `/v1/admin` command on node ID below the profile's node. The Master checks your roles, audits the request and forwards it hop by hop over the node plane. The target runs it as you, checks your roles there, and audits it again:

```sh
heainctl --node Z2 config set apps.heartbeat_interval 7s
```

## Output and exit codes

- **Output:** lists people read are printed as tables, and everything else as indented JSON. `--json` prints core's answer exactly, for scripts.
- **Exit codes:**
  - **0:** done.
  - **1:** core refused. Its status, code and message are printed, for example `heainctl: 403 self_approval: ...`.
  - **2:** usage.
  - **3:** core could not be reached, or its certificate did not verify.

## Tests

```sh
go test ./...                # against a fake core with mutual TLS
bash scripts/live_5a.sh      # needs ~/heain-core; a real G <- Z tree, ~2 min
```

The live test drives a real tree only through heainctl. It covers:

- profiles and the identities' roles;
- `roles.admins` proposed and approved through P5;
- a viewer refused, and an operator changing a key;
- the fleet view;
- remote admin to Z through G, audited on Z;
- config history, export, drift and a dry run;
- audit verify, events, a provisioning token, `raw` and a diagnostics bundle;
- the exit codes, including a node whose certificate the CA did not sign.
