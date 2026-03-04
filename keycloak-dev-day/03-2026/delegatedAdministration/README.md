# Group Permission Policy Extension

A Keycloak event listener extension that automates **Fine-Grained Admin Permissions (FGAP)**
for group-based delegated administration.

When a group is created in the realm, the extension automatically scaffolds the full
delegation structure — manager group, FGAP policy, scope permission, and global Users
permission — so that whoever is placed in a `*-manager` group gains delegated admin rights
over that group and its users, with zero manual configuration in the Keycloak UI.

---

## Event Listeners

| Class | ID | Purpose |
|---|---|---|
| `GroupBasedDelegationEventListener` | `group-based-delegation` | Fires on `GROUP CREATE/UPDATE` — builds the full FGAP scaffold |
| `ManagerGroupMembershipPropagationEventListener` | `manager-group-membership-propagation` | Fires on `GROUP_MEMBERSHIP CREATE` — grants roles and propagates manager membership downward |

Both are registered in `META-INF/services/org.keycloak.events.EventListenerProviderFactory`
and must be enabled in **Realm Settings → Events → Event Listeners**.

---

## Listener 1 — `GroupBasedDelegationEventListener`

### Trigger

```
AdminEvent  ▸  ResourceType.GROUP  ▸  OperationType.CREATE | UPDATE
```

### Early exits (no-ops)

- Group name ends with `-manager` → already a manager group; skip to prevent infinite recursion.
- Group's parent ends with `-manager` → group was already moved by a previous run; skip to avoid double-processing.

### Steps on `GROUP CREATE`

#### Step 1 — Create `<groupname>-manager` at the same level

The manager group is placed as a **sibling** of the new group:

- Top-level group → manager group is also top-level.
- Subgroup of `parent` → manager group is a child of the same `parent`.

Uses `orElseGet` — fully idempotent if the manager group already exists.

```
Before:   /acme                     After:   /acme-manager
                                               └── /acme
```

```
Before:   /tenants/acme             After:   /tenants/acme-manager
                                               └── /tenants/acme-manager/acme
```

#### Step 2 — Move the group under its manager

```java
session.groups().moveGroup(realm, group, managerGroup);
```

This is a **model-level** operation — it does **not** fire a new admin event,
so there is no risk of recursion.

#### Step 3 — Create a FGAP group policy

A `group`-type policy is created on the `admin-permissions` resource server backed
by the manager group:

```json
{
  "type": "group",
  "name": "tenants-acme-manager",
  "logic": "POSITIVE",
  "decisionStrategy": "UNANIMOUS",
  "groups": [{ "id": "<acme-manager-id>", "extendChildren": true }]
}
```

`extendChildren: true` — members of any subgroup of `acme-manager` also satisfy the policy,
enabling nested manager hierarchies.

#### Step 4 — Create a FGAP scope permission on the group resource

A `scope`-type permission is created targeting the group's own FGAP resource:

```json
{
  "type": "scope",
  "name": "tenants-acme",
  "decisionStrategy": "UNANIMOUS",
  "resourceType": "Groups",
  "resources": ["<acme-uuid>"],
  "scopes": [
    "manage-members", "manage-membership",
    "view", "manage",
    "impersonate-members", "view-members"
  ],
  "policies": ["<tenants-acme-manager policy id>"]
}
```

`resourceType: "Groups"` is required by Keycloak 26's `AdminPermissionsSchema` validation.
Specifying the exact resource ID prevents wildcard matching across all groups.

If the FGAP resource for the group does not yet exist (Keycloak initialises them lazily),
the listener creates it and attaches all six group-management scopes.

#### Step 5 — Upsert the global `delegated-user-management` Users permission

A single global permission accumulates ALL manager policies across ALL root hierarchies:

- **First group created** → permission is created with `AFFIRMATIVE` strategy:

```json
{
  "type": "scope",
  "name": "delegated-user-management",
  "decisionStrategy": "AFFIRMATIVE",
  "resourceType": "Users",
  "scopes": ["manage", "manage-group-membership"],
  "policies": ["<tenants-manager policy id>"]
}
```

- **Every subsequent group** → the new manager policy is added idempotently via
  `existing.addAssociatedPolicy(managerPolicy)`.

**Why one global `AFFIRMATIVE` permission?**

Keycloak's resource server evaluates every matching permission under `UNANIMOUS` by default.
Two separate permissions — e.g. `acme-users` and `hooli-users` — would mutually deny each
other's managers: `it.admin@acme.com` satisfies `acme-users` but fails `hooli-users` → **DENY**.
One `AFFIRMATIVE` permission means any single matching policy grants access.

### Steps on `GROUP UPDATE`

Checks whether a permission already exists for the group.
- If yes → leaves it in place (names are stable since creation) and re-runs step 5 to
  ensure the global Users permission is current.
- If no → falls through to the full `setupDelegation()` flow above.

### Naming scheme

`buildGroupPath()` walks the group's ancestry, strips `-manager` segments, and joins with `-`:

| Keycloak path | Policy name | Permission name |
|---|---|---|
| `/tenants-manager/tenants` | `tenants-manager` | `tenants` |
| `/tenants-manager/tenants/acme-manager/acme` | `tenants-acme-manager` | `tenants-acme` |
| `…/acme-manager/acme/acme-engineering-manager/acme-engineering` | `tenants-acme-acme-engineering-manager` | `tenants-acme-acme-engineering` |

### Full example — creating `acme` inside `tenants`

```
POST /admin/realms/delegated-admin/groups/<tenants-id>/children
{"name": "acme"}
```

Listener fires and produces:

```
/tenants-manager                         ← existing root
  └── /tenants                           ← existing business group
        └── /acme-manager                ← NEW: created in step 1
              └── /acme                  ← moved here in step 2

FGAP policies:
  tenants-acme-manager  (group policy → acme-manager)   ← step 3

FGAP permissions:
  tenants-acme          (scope perm  → acme resource)   ← step 4
  delegated-user-management  +acme-manager policy       ← step 5 (upserted)
```

After `it.admin@acme.com` is placed in `acme-manager`:
- They can view/manage all members of `acme` and its subgroups.
- They can move users in/out of `acme` and its subgroups.
- They cannot touch any user outside their scope.

---

## Listener 2 — `ManagerGroupMembershipPropagationEventListener`

### Trigger

```
AdminEvent  ▸  ResourceType.GROUP_MEMBERSHIP  ▸  OperationType.CREATE
```

Resource path pattern: `users/{userId}/groups/{groupId}`

Only fires when the target group name ends with `-manager`. All other group memberships
are ignored.

### Steps

#### Step 1 — Grant `query-users` and `query-groups` realm-management roles

```java
assignManagerRoles(realm, user);
```

Looks up the `realm-management` client and grants both roles to the user unless already
assigned. This allows the manager to search for users and browse groups via the Keycloak
Admin API (required for the delegated admin UI).

#### Step 2 — Find the managed group

Looks for the direct child of the manager group whose name does **not** end with `-manager`:

```
acme-manager
  ├── acme              ← this is the "managed group" – recursion starts here
  └── (no other non-manager children expected)
```

#### Step 3 — Propagate membership downward

Recursively walks the subtree of the managed group and adds the user to every
`*-manager` group found there.

```
acme-manager           ← user just joined here (trigger)
  └── acme
        ├── acme-engineering-manager   ← user auto-joined (propagation)
        │     └── acme-engineering
        └── acme-finance-manager       ← user auto-joined (propagation)
              └── acme-finance
```

Skips groups the user already belongs to — fully idempotent.

### Full example — adding `it.admin@acme.com` to `acme-manager`

```
PUT /admin/realms/delegated-admin/users/<it-admin-id>/groups/<acme-manager-id>
```

Listener fires:

1. Grants `query-users` + `query-groups` → `it.admin@acme.com`
2. Finds managed group `acme`
3. Walks `acme`'s subtree:
   - Finds `acme-engineering-manager` → adds user
   - Finds `acme-finance-manager` → adds user

Result: `it.admin@acme.com` is a member of:
```
acme-manager
acme-engineering-manager    (propagated)
acme-finance-manager        (propagated)
```

This means the Acme IT admin can manage Engineering and Finance users as well —
without any manual setup.

> **Note:** If you prefer each department to have an independent admin with no
> cross-department access (as in the B2B demo setup), simply do **not** add the
> tenant IT admin to the tenant's manager group. Add dedicated department admins
> directly to each `*-department-manager` group instead.

---

## Configuration

### Registering the listeners

In Keycloak Admin UI: **Realm Settings → Events → Event Listeners**, add:

```
group-based-delegation
manager-group-membership-propagation
jboss-logging
```

Or in the realm JSON:

```json
"eventsListeners": [
  "jboss-logging",
  "group-based-delegation",
  "manager-group-membership-propagation"
]
```

### Prerequisites

The realm must have **Admin Permissions** enabled:

```json
"adminPermissionsEnabled": true
```

This causes Keycloak to provision the `admin-permissions` client and FGAP resource server
that the extension writes into.

---

## Building

```bash
cd extensions/group-permission-policy-extension
mvn clean package -DskipTests
```

The JAR is output to `target/`. Mount it into the Keycloak `providers/` directory
(see `docker-compose.yaml`).

---

## Summary of automation

| Action | Automated by |
|---|---|
| Create `*-manager` group | `GroupBasedDelegationEventListener` |
| Move business group under manager | `GroupBasedDelegationEventListener` |
| Create FGAP group policy | `GroupBasedDelegationEventListener` |
| Create FGAP scope permission on the group | `GroupBasedDelegationEventListener` |
| Upsert global `delegated-user-management` Users permission | `GroupBasedDelegationEventListener` |
| Grant `query-users` + `query-groups` to a manager user | `ManagerGroupMembershipPropagationEventListener` |
| Propagate manager membership to child manager groups | `ManagerGroupMembershipPropagationEventListener` |
