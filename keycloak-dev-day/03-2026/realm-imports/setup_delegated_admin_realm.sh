#!/usr/bin/env bash
# =============================================================================
# setup_delegated_admin_realm.sh
#
# Imports delegated-admin-realm.json, then creates:
#   - Group hierarchy (event listener auto-creates *-manager groups + FGAP)
#   - Manager + member users  (password: Test123!)
#
# Automatic (handled by event listeners, no manual steps needed):
#   - query-users / query-groups roles  → ManagerGroupMembershipPropagationEventListener
#     (fires on GROUP_MEMBERSHIP CREATE; grants roles when user joins a *-manager group)
#   - delegated-user-management FGAP permission → GroupBasedDelegationEventListener
#     (fires on GROUP CREATE; accumulates all *-manager policies)
#
# Usage:
#   bash setup_delegated_admin_realm.sh [--delete]
#
#   --delete   Drop and reimport the realm before running
# =============================================================================
set -euo pipefail

KC="${KC:-http://localhost:8080}"
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASS="${ADMIN_PASS:-admin}"
REALM="delegated-admin"
REALM_JSON="$(cd "$(dirname "$0")" && pwd)/delegated-admin-realm.json"
USER_PASSWORD="Test123!"

# Colours
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
ok()   { echo -e "  ${GREEN}✓${NC}  $*"; }
warn() { echo -e "  ${YELLOW}⚠${NC}  $*"; }
err()  { echo -e "  ${RED}✗${NC}  $*"; }

# =============================================================================
# Auth
# =============================================================================
get_token() {
  curl -sf -X POST "${KC}/realms/master/protocol/openid-connect/token" \
    -d "grant_type=password&client_id=admin-cli&username=${ADMIN_USER}&password=${ADMIN_PASS}" \
    | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])"
}

api()  { curl -sf -H "Authorization: Bearer ${TOKEN}" -H "Content-Type: application/json" "$@"; }
api_no_fail() { curl -s  -H "Authorization: Bearer ${TOKEN}" -H "Content-Type: application/json" "$@"; }

# =============================================================================
# Group helpers
# =============================================================================
find_group() {
  # $1 = group name; returns id or empty string
  local name="$1"
  api "${KC}/admin/realms/${REALM}/groups?search=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${name}'))")&exact=true&max=200" \
    | python3 -c "
import sys, json
data = json.load(sys.stdin)
def search(groups, name):
    for g in groups:
        if g['name'] == name:
            print(g['id']); return True
        if search(g.get('subGroups', []), name): return True
    return False
search(data, '${name}')
"
}

find_group_kc26() {
  # Keycloak 26 search returns a tree (parents + matching subGroups) – recurse.
  local name="$1"
  api "${KC}/admin/realms/${REALM}/groups?search=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${name}'))")&exact=true&max=200" \
    | python3 -c "
import sys, json
data = json.load(sys.stdin)
def find(groups, name):
    for g in groups:
        if g.get('name') == name:
            print(g['id']); return True
        if find(g.get('subGroups', []), name): return True
    return False
find(data, '${name}')
"
}

create_top_group() {
  local name="$1"
  local status
  status=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "${KC}/admin/realms/${REALM}/groups" \
    -H "Authorization: Bearer ${TOKEN}" \
    -H "Content-Type: application/json" \
    -d "{\"name\":\"${name}\"}")
  echo "$status"
}

create_child_group() {
  local parent_id="$1" name="$2"
  local status
  status=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "${KC}/admin/realms/${REALM}/groups/${parent_id}/children" \
    -H "Authorization: Bearer ${TOKEN}" \
    -H "Content-Type: application/json" \
    -d "{\"name\":\"${name}\"}")
  echo "$status"
}

# =============================================================================
# Step 0 – optional delete
# =============================================================================
if [[ "${1:-}" == "--delete" ]]; then
  echo ""
  echo "▶ [0] Deleting existing realm '${REALM}'..."
  TOKEN=$(get_token)
  status=$(curl -s -o /dev/null -w "%{http_code}" \
    -X DELETE "${KC}/admin/realms/${REALM}" \
    -H "Authorization: Bearer ${TOKEN}")
  [[ "$status" == "204" ]] && ok "Realm deleted." || warn "Realm not found (status ${status})."
fi

# =============================================================================
# Step 1 – import realm
# =============================================================================
echo ""
echo "▶ [1] Importing realm from ${REALM_JSON}..."
TOKEN=$(get_token)
status=$(curl -s -o /tmp/realm_import_out.txt -w "%{http_code}" \
  -X POST "${KC}/admin/realms" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  --data-binary "@${REALM_JSON}")
if [[ "$status" == "201" ]]; then
  ok "Realm '${REALM}' imported."
elif [[ "$status" == "409" ]]; then
  warn "Realm '${REALM}' already exists – skipping import."
else
  err "Import failed (HTTP ${status}): $(cat /tmp/realm_import_out.txt)"
  exit 1
fi

TOKEN=$(get_token)  # refresh token after realm creation

# =============================================================================
# Step 2 – create groups
# The event listener fires on CREATE and:
#   • creates  <name>-manager  at the same level
#   • moves    <name>          under <name>-manager
#   • creates FGAP group policy + group permission
# We just need to POST the managed group; the listener handles the rest.
# =============================================================================
echo ""
echo "▶ [2] Creating groups..."

create_group_with_retry() {
  # $1=name  $2=parent_name (empty for top-level)
  local name="$1" parent_name="${2:-}"

  if [[ -z "$parent_name" ]]; then
    local status
    status=$(create_top_group "$name")
    if [[ "$status" == "201" ]]; then
      sleep 0.5   # let event listener commit
      local id; id=$(find_group_kc26 "$name")
      local mgr_id; mgr_id=$(find_group_kc26 "${name}-manager")
      ok "Group '${name}' (id=${id})  manager '${name}-manager' (id=${mgr_id})"
    elif [[ "$status" == "409" ]]; then
      warn "Group '${name}' already exists – skipping."
    else
      err "Failed to create '${name}' (HTTP ${status})"
    fi
  else
    # Find the managed parent (listener may have nested it under <parent>-manager)
    local parent_id; parent_id=$(find_group_kc26 "$parent_name")
    if [[ -z "$parent_id" ]]; then
      err "Parent group '${parent_name}' not found – cannot create '${name}'"
      return
    fi
    local status
    status=$(create_child_group "$parent_id" "$name")
    if [[ "$status" == "201" ]]; then
      sleep 0.5
      local id; id=$(find_group_kc26 "$name")
      local mgr_id; mgr_id=$(find_group_kc26 "${name}-manager")
      ok "Group '${name}' (id=${id})  manager '${name}-manager' (id=${mgr_id})"
    elif [[ "$status" == "409" ]]; then
      warn "Group '${name}' already exists – skipping."
    else
      err "Failed to create '${name}' (HTTP ${status})"
    fi
  fi
}

# Platform root → both tenants → departments
create_group_with_retry "tenants"
create_group_with_retry "acme"             "tenants"
create_group_with_retry "hooli"            "tenants"
create_group_with_retry "acme-engineering" "acme"
create_group_with_retry "acme-finance"     "acme"
create_group_with_retry "hooli-sales"      "hooli"
create_group_with_retry "hooli-support"    "hooli"

# =============================================================================
# Step 3 – create users
# =============================================================================
echo ""
echo "▶ [3] Creating users..."

create_user() {
  local email="$1" first="$2" last="$3"
  local body
  body=$(python3 -c "import json; print(json.dumps({
    'username': '${email}', 'email': '${email}',
    'firstName': '${first}', 'lastName': '${last}',
    'enabled': True, 'emailVerified': True,
    'credentials': [{'type':'password','value':'${USER_PASSWORD}','temporary':False}]
  }))")
  local status
  status=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "${KC}/admin/realms/${REALM}/users" \
    -H "Authorization: Bearer ${TOKEN}" \
    -H "Content-Type: application/json" \
    -d "$body")
  [[ "$status" == "201" ]] && ok "User '${email}'" \
    || { [[ "$status" == "409" ]] && warn "User '${email}' already exists." \
    || err "User '${email}' failed (HTTP ${status})"; }
}

create_user "super.admin@devday.io"    "Super"    "Admin"
create_user "platform.user@devday.io" "Platform" "User"
create_user "it.admin@acme.com"        "IT Admin" "Acme"
create_user "alex.johnson@acme.com"    "Alex"     "Johnson"
create_user "eng.admin@acme.com"       "Eng"      "Admin"
create_user "bob.smith@acme.com"       "Bob"      "Smith"
create_user "finance.admin@acme.com"   "Finance"  "Admin"
create_user "carol.white@acme.com"     "Carol"    "White"
create_user "it.admin@hooli.com"      "IT Admin" "Hooli"
create_user "dave.brown@hooli.com"    "Dave"     "Brown"
create_user "sales.admin@hooli.com"   "Sales"    "Admin"
create_user "eve.davis@hooli.com"     "Eve"      "Davis"
create_user "support.admin@hooli.com" "Support"  "Admin"
create_user "frank.miller@hooli.com"  "Frank"    "Miller"

# =============================================================================
# Step 4 – assign users to groups + realm-management roles for managers
# =============================================================================
echo ""
echo "▶ [4] Assigning users to groups and roles..."

get_user_id() {
  api "${KC}/admin/realms/${REALM}/users?email=${1}&exact=true" \
    | python3 -c "import sys,json; d=json.load(sys.stdin); print(d[0]['id'] if d else '')"
}

assign_user_to_group() {
  # $1=email  $2=group_name
  # query-users / query-groups are auto-granted by ManagerGroupMembershipPropagationEventListener
  # when the user is added to a *-manager group – no explicit role step needed here.
  local email="$1" group_name="$2"

  local user_id; user_id=$(get_user_id "$email")
  if [[ -z "$user_id" ]]; then
    err "User '${email}' not found"
    return
  fi

  local group_id; group_id=$(find_group_kc26 "$group_name")
  if [[ -z "$group_id" ]]; then
    err "Group '${group_name}' not found"
    return
  fi

  local status
  status=$(curl -s -o /dev/null -w "%{http_code}" \
    -X PUT "${KC}/admin/realms/${REALM}/users/${user_id}/groups/${group_id}" \
    -H "Authorization: Bearer ${TOKEN}")
  [[ "$status" == "204" ]] && ok "${email}  →  ${group_name}" \
    || err "Assign ${email} → ${group_name} failed (HTTP ${status})"
}

# Platform level
assign_user_to_group "super.admin@devday.io"    "tenants-manager"
assign_user_to_group "platform.user@devday.io"  "tenants"

# Acme Corp – tenant level
assign_user_to_group "it.admin@acme.com"        "acme-manager"
assign_user_to_group "it.admin@acme.com"        "tenants"                  # visible in parent
assign_user_to_group "alex.johnson@acme.com"    "acme"

# Acme Corp – department level
assign_user_to_group "eng.admin@acme.com"       "acme-engineering-manager"
assign_user_to_group "eng.admin@acme.com"       "acme"                     # visible in parent
assign_user_to_group "bob.smith@acme.com"       "acme-engineering"
assign_user_to_group "finance.admin@acme.com"   "acme-finance-manager"
assign_user_to_group "finance.admin@acme.com"   "acme"                     # visible in parent
assign_user_to_group "carol.white@acme.com"     "acme-finance"

# Hooli Inc – tenant level
assign_user_to_group "it.admin@hooli.com"       "hooli-manager"
assign_user_to_group "it.admin@hooli.com"       "tenants"                  # visible in parent
assign_user_to_group "dave.brown@hooli.com"     "hooli"

# Hooli Inc – department level
assign_user_to_group "sales.admin@hooli.com"    "hooli-sales-manager"
assign_user_to_group "sales.admin@hooli.com"    "hooli"                    # visible in parent
assign_user_to_group "eve.davis@hooli.com"      "hooli-sales"
assign_user_to_group "support.admin@hooli.com"  "hooli-support-manager"
assign_user_to_group "support.admin@hooli.com"  "hooli"                    # visible in parent
assign_user_to_group "frank.miller@hooli.com"   "hooli-support"

# =============================================================================
# Summary
# (Step 5 – delegated-user-management FGAP permission is created automatically
#  by GroupBasedDelegationEventListener on every GROUP CREATE event.
#  No manual step needed here.)
# =============================================================================
echo ""
echo "▶ [5] Summary"
echo ""
echo "  Realm  : ${KC}/admin/master/console/#/${REALM}"
echo "  Login  : ${KC}/realms/${REALM}/account"
echo "  Client : delegated-admin-ui"
echo "  Password: ${USER_PASSWORD}"
echo ""
echo "  Group tree:"
python3 - <<PYEOF
import requests
KC    = "${KC}"
REALM = "${REALM}"
TOKEN = "${TOKEN}"
h     = {"Authorization": f"Bearer {TOKEN}"}

def render(gid, indent=0):
    g = requests.get(f"{KC}/admin/realms/{REALM}/groups/{gid}", headers=h).json()
    print("    " + "  "*indent + g["path"])
    if g.get("subGroupCount", 0) > 0:
        children = requests.get(f"{KC}/admin/realms/{REALM}/groups/{gid}/children",
                                params={"max": 200}, headers=h).json()
        for c in sorted(children, key=lambda x: x["name"]):
            render(c["id"], indent+1)

tops = requests.get(f"{KC}/admin/realms/{REALM}/groups", params={"max": 200}, headers=h).json()
for g in sorted(tops, key=lambda x: x["name"]):
    render(g["id"])
PYEOF

echo ""
echo "  FGAP permissions:"
python3 - <<PYEOF
import requests
KC    = "${KC}"
REALM = "${REALM}"
TOKEN = "${TOKEN}"
h     = {"Authorization": f"Bearer {TOKEN}"}
clients = requests.get(f"{KC}/admin/realms/{REALM}/clients", headers=h).json()
fgap    = next((c for c in clients if c["clientId"]=="admin-permissions"), None)
if fgap:
    base  = f"{KC}/admin/realms/{REALM}/clients/{fgap['id']}/authz/resource-server"
    perms = requests.get(f"{base}/permission", params={"max": 200}, headers=h).json()
    for p in sorted(perms, key=lambda x: x.get("name","")):
        print(f"    [{p.get('decisionStrategy','?'):11}] {p['name']}")
PYEOF

echo ""
echo "Done ✓"
