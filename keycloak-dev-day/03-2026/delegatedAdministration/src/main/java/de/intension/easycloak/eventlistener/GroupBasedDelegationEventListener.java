package de.intension.easycloak.eventlistener;

import org.keycloak.authorization.AuthorizationProvider;
import org.keycloak.authorization.model.Policy;
import org.keycloak.authorization.model.Resource;
import org.keycloak.authorization.model.ResourceServer;
import org.keycloak.authorization.model.Scope;
import org.keycloak.authorization.store.PolicyStore;
import org.keycloak.authorization.store.ResourceStore;
import org.keycloak.authorization.store.ScopeStore;
import org.keycloak.authorization.store.StoreFactory;
import org.keycloak.events.Event;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.events.admin.OperationType;
import org.keycloak.events.admin.ResourceType;
import org.keycloak.models.ClientModel;
import org.keycloak.models.GroupModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.cache.UserCache;
import org.keycloak.models.utils.RepresentationToModel;
import org.keycloak.representations.idm.authorization.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Event listener that implements group-based delegated administration via Keycloak FGAP.
 *
 * <p>For every group created in the realm, this listener automatically:
 * <ol>
 *   <li>Creates a {@code <groupname>-manager} group at the same hierarchy level.</li>
 *   <li>Moves the new group to become a child of that manager group.</li>
 *   <li>Creates a FGAP group policy backed by the manager group.</li>
 *   <li>Creates a FGAP scope permission for the original group using that policy.</li>
 * </ol>
 *
 * <p>Resulting structure for top-level {@code europe}:
 * <pre>
 *   europe-manager          &lt;-- add managers here
 *     └── europe            &lt;-- the managed group
 * </pre>
 * For subgroup {@code germany} created inside {@code europe}:
 * <pre>
 *   europe-manager
 *     └── europe
 *           └── germany-manager     &lt;-- add germany managers here
 *                 └── germany
 * </pre>
 *
 * <p>To grant delegated manager access, add the user to the {@code <groupname>-manager} group.
 * Groups whose name ends with {@value #MANAGER_SUFFIX} are skipped to prevent infinite recursion.
 */
public class GroupBasedDelegationEventListener implements EventListenerProvider {

    private static final Logger LOGGER = LoggerFactory.getLogger(GroupBasedDelegationEventListener.class);

    /** Suffix that marks a group as a delegation manager group. */
    static final String MANAGER_SUFFIX = "-manager";

    /** Keycloak's built-in resource server client for FGAP. */
    private static final String CLIENT_ID = "admin-permissions";

    /** FGAP resource type for groups. */
    private static final String RESOURCE_TYPE_GROUPS = "Groups";

    /** FGAP resource type that covers all user records. */
    private static final String RESOURCE_TYPE_USERS = "Users";

    /** All scopes granted to a group manager. */
    private static final List<String> GROUP_SCOPES = List.of(
            "manage-members", "manage-membership", "view", "manage", "impersonate-members", "view-members");

    /** Scopes granted to a manager for editing/moving users inside their managed groups. */
    private static final List<String> USER_SCOPES = List.of("manage", "manage-group-membership");

    /**
     * Single global permission that accumulates ALL manager policies across ALL root hierarchies.
     * One global name is required because Keycloak evaluates every matching Users-type permission
     * under the resource-server's UNANIMOUS strategy: a second {@code asia-users} permission would
     * DENY {@code manager@europe.de}, and vice-versa, making cross-hierarchy editing impossible.
     */
    private static final String GLOBAL_USER_PERMISSION_NAME = "delegated-user-management";

    /** Extracts the {@code id} field from a JSON representation. */
    private static final Pattern ID_PATTERN =
            Pattern.compile("\"id\"\\s*:\\s*\"([a-zA-Z0-9][a-zA-Z0-9\\-_]{0,254})\"");

    private final AuthorizationProvider authorizationProvider;
    private final KeycloakSession session;

    public GroupBasedDelegationEventListener(KeycloakSession session, AuthorizationProvider authorizationProvider) {
        this.session = Objects.requireNonNull(session, "session must not be null");
        this.authorizationProvider = Objects.requireNonNull(authorizationProvider, "authorizationProvider must not be null");
    }

    @Override
    public void close() {
        // nothing to close
    }

    @Override
    public void onEvent(Event event) {
        // only admin events are relevant
    }

    @Override
    public void onEvent(AdminEvent adminEvent, boolean includeRepresentation) {
        if (adminEvent == null || adminEvent.getResourceType() != ResourceType.GROUP) {
            return;
        }
        OperationType opType = adminEvent.getOperationType();
        if (opType != OperationType.CREATE && opType != OperationType.UPDATE) {
            return;
        }

        String groupId = extractGroupId(adminEvent.getRepresentation());
        if (groupId == null) {
            LOGGER.warn("Could not extract group ID from admin event representation");
            return;
        }

        RealmModel realm = session.getContext().getRealm();
        GroupModel group = session.groups().getGroupById(realm, groupId);
        if (group == null) {
            LOGGER.warn("Group not found with ID: {}", groupId);
            return;
        }

        // Skip manager groups themselves – they have no delegation setup of their own.
        if (group.getName().endsWith(MANAGER_SUFFIX)) {
            LOGGER.debug("Skipping manager group: {}", group.getName());
            return;
        }
        // Skip groups that are already a direct child of a manager group
        // (i.e. already moved by a previous delegation setup – avoids double-processing).
        if (group.getParent() != null && group.getParent().getName().endsWith(MANAGER_SUFFIX)) {
            LOGGER.debug("Skipping group '{}' – already under manager group '{}'",
                    group.getName(), group.getParent().getName());
            return;
        }

        ResourceServer resourceServer = getResourceServer(realm);
        if (resourceServer == null) {
            LOGGER.error("Resource server for '{}' not found. Is FGAP (admin permissions) enabled for the realm?", CLIENT_ID);
            return;
        }

        try {
            if (opType == OperationType.CREATE) {
                LOGGER.debug("Setting up FGAP delegation for new group: {}", group.getName());
                setupDelegation(group, realm, resourceServer);
            } else {
                LOGGER.debug("Refreshing FGAP delegation for updated group: {}", group.getName());
                refreshDelegation(group, realm, resourceServer);
            }
        } catch (Exception e) {
            LOGGER.error("Error setting up FGAP delegation for group: {}", group.getName(), e);
        }
    }

    // -------------------------------------------------------------------------
    // Core delegation setup
    // -------------------------------------------------------------------------

    /**
     * Creates the full FGAP delegation structure for a newly created group.
     * <ol>
     *   <li>Creates {@code <groupname>-manager} at the same hierarchy level as the group.</li>
     *   <li>Moves the group to become a child of that manager group.</li>
     *   <li>Creates the group policy backed by the manager group.</li>
     *   <li>Creates the scope permission on the group's FGAP resource.</li>
     * </ol>
     * Result (top-level):  {@code europe-manager → [europe]}
     * Result (subgroup):   {@code parent/germany-manager → [germany]}
     */
    private void setupDelegation(GroupModel group, RealmModel realm, ResourceServer resourceServer) {
        String managerGroupName = group.getName() + MANAGER_SUFFIX;
        // Capture the original parent BEFORE the move – the manager group is placed at this level.
        GroupModel originalParent = group.getParent();

        // 1. Create the <groupname>-manager group at the SAME level as the original group.
        GroupModel managerGroup = getOrCreateManagerGroup(realm, managerGroupName, originalParent);
        if (managerGroup == null) {
            LOGGER.error("Could not create manager group '{}' for group '{}'", managerGroupName, group.getName());
            return;
        }
        LOGGER.debug("Manager group ready: {}", managerGroup.getName());

        // 2. Move the original group to become a CHILD of the manager group.
        moveGroupUnderManager(realm, group, managerGroup);

        // 3. Create (or reuse) the group policy backed by the manager group.
        //    buildPolicyName/buildPermissionName skip -manager segments so names are stable.
        String policyName = buildPolicyName(group);
        Policy policy = getOrCreateGroupPolicy(policyName, resourceServer, group, managerGroup);
        if (policy == null) {
            LOGGER.error("Could not create group policy '{}' for group '{}'", policyName, group.getName());
            return;
        }
        LOGGER.debug("Group policy ready: {}", policy.getName());

        // 4. Create (or reuse) the scope permission on this group's resource.
        String permissionName = buildPermissionName(group);
        Policy permission = getOrCreateGroupPermission(permissionName, group, managerGroup, policy, resourceServer);
        if (permission != null) {
            LOGGER.info("FGAP delegation ready – group: '{}', manager group: '{}', policy: '{}', permission: '{}'",
                    group.getName(), managerGroupName, policyName, permissionName);
        }

        // 5. Add this group's manager policy to the single root-level Users permission.
        //    We deliberately use ONE permission per root-group hierarchy (e.g. "europe-users")
        //    rather than one per leaf group, because Keycloak evaluates ALL matching
        //    Users-type permissions under a UNANIMOUS resource-server strategy.  A per-leaf
        //    permission for france would DENY a germany manager, making the overall result DENY.
        addManagerPolicyToUsersPermission(group, policy, resourceServer);

        // 6. Propagate ancestor manager group members into the new manager group.
        //    This ensures that higher-level managers (e.g. acme-manager members) can
        //    immediately see and manage the newly created sub-group.
        propagateAncestorManagers(managerGroup, realm);
    }

    /**
     * Walks up the group hierarchy from {@code managerGroup}'s parent and finds
     * all ancestor groups whose name ends with {@code -manager}.  Members of each
     * ancestor manager group are added to {@code managerGroup}, giving them
     * automatic delegated access to the new sub-group.
     *
     * <p>After each {@code user.joinGroup()} the user is explicitly evicted from
     * the {@link UserCache} so that subsequent reads (including the JWT groups
     * claim and the admin console) see the updated group memberships immediately
     * without waiting for a Keycloak restart.
     *
     * <p>Example: when {@code globex-manager} is created under {@code acme},
     * this method walks up and finds {@code acme-manager} and {@code tenants-manager},
     * then copies their members into {@code globex-manager}.
     */
    private void propagateAncestorManagers(GroupModel managerGroup, RealmModel realm) {
        try {
            UserCache userCache = session.getProvider(UserCache.class);

            GroupModel cursor = managerGroup.getParent();
            int propagated = 0;
            while (cursor != null) {
                if (cursor.getName().endsWith(MANAGER_SUFFIX)) {
                    List<UserModel> ancestorMembers = session.users()
                            .getGroupMembersStream(realm, cursor)
                            .toList();
                    for (UserModel user : ancestorMembers) {
                        if (!user.isMemberOf(managerGroup)) {
                            user.joinGroup(managerGroup);
                            // Evict the user from the Infinispan cache so that the
                            // updated group membership is visible immediately.
                            if (userCache != null) {
                                userCache.evict(realm, user);
                            }
                            propagated++;
                            LOGGER.debug("Propagated user '{}' from '{}' to '{}'",
                                    user.getUsername(), cursor.getName(), managerGroup.getName());
                        }
                    }
                }
                cursor = cursor.getParent();
            }
            if (propagated > 0) {
                LOGGER.info("Propagated {} ancestor manager member(s) into '{}'",
                        propagated, managerGroup.getName());
            }
        } catch (Exception e) {
            LOGGER.error("Error propagating ancestor managers to '{}': {}",
                    managerGroup.getName(), e.getMessage(), e);
        }
    }

    /**
     * Moves {@code group} to become a direct child of {@code managerGroup}.
     * This is a model-level operation and does NOT fire additional admin events.
     */
    private void moveGroupUnderManager(RealmModel realm, GroupModel group, GroupModel managerGroup) {
        try {
            session.groups().moveGroup(realm, group, managerGroup);
            LOGGER.debug("Moved group '{}' to be a child of '{}'", group.getName(), managerGroup.getName());
        } catch (Exception e) {
            LOGGER.error("Error moving group '{}' under manager group '{}': {}",
                    group.getName(), managerGroup.getName(), e.getMessage(), e);
        }
    }

    /**
     * On group update: if a permission/policy already exists for this group,
     * leave it in place (names were set at creation time). Otherwise treat as create.
     * Either way, ensure the companion Users permission is up-to-date.
     */
    private void refreshDelegation(GroupModel group, RealmModel realm, ResourceServer resourceServer) {
        StoreFactory sf = authorizationProvider.getStoreFactory();
        String permissionName = buildPermissionName(group);
        Policy existing = sf.getPolicyStore().findByName(resourceServer, permissionName);
        if (existing == null) {
            LOGGER.debug("No existing permission found on update – creating FGAP setup for group: {}", group.getName());
            setupDelegation(group, realm, resourceServer);
        } else {
            LOGGER.debug("Existing FGAP permission '{}' retained on group update.", permissionName);
            // Idempotently ensure the Users permission is current.
            String policyName = buildPolicyName(group);
            Policy managerPolicy = sf.getPolicyStore().findByName(resourceServer, policyName);
            if (managerPolicy != null) {
                addManagerPolicyToUsersPermission(group, managerPolicy, resourceServer);
            }
        }
    }

    // -------------------------------------------------------------------------
    // Manager group
    // -------------------------------------------------------------------------

    /**
     * Returns or creates the {@code <groupname>-manager} group as a sibling of the managed group.
     * <ul>
     *   <li>If the managed group is top-level, the manager group is also top-level.</li>
     *   <li>If the managed group is a subgroup, the manager group is placed inside the same parent.</li>
     * </ul>
     */
    private GroupModel getOrCreateManagerGroup(RealmModel realm, String managerGroupName, GroupModel parent) {
        try {
            if (parent == null) {
                // Top-level managed group → create manager group at top level too.
                return session.groups().getTopLevelGroupsStream(realm)
                        .filter(g -> managerGroupName.equals(g.getName()))
                        .findFirst()
                        .orElseGet(() -> session.groups().createGroup(realm, managerGroupName));
            } else {
                // Subgroup → create manager group inside the same parent.
                return parent.getSubGroupsStream()
                        .filter(g -> managerGroupName.equals(g.getName()))
                        .findFirst()
                        .orElseGet(() -> session.groups().createGroup(realm, managerGroupName, parent));
            }
        } catch (Exception e) {
            LOGGER.error("Error creating manager group '{}': {}", managerGroupName, e.getMessage(), e);
            return null;
        }
    }

    // -------------------------------------------------------------------------
    // Group policy
    // -------------------------------------------------------------------------

    /**
     * Returns or creates a group-type FGAP policy that grants access to direct members
     * of the {@code managerGroup}.
     */
    private Policy getOrCreateGroupPolicy(String policyName, ResourceServer resourceServer,
                                          GroupModel group, GroupModel managerGroup) {
        try {
            PolicyStore policyStore = authorizationProvider.getStoreFactory().getPolicyStore();
            Policy existing = policyStore.findByName(resourceServer, policyName);
            if (existing != null) {
                LOGGER.debug("Reusing existing policy: {}", policyName);
                return existing;
            }

            GroupPolicyRepresentation rep = new GroupPolicyRepresentation();
            rep.setName(policyName);
            rep.setDescription("Delegation policy: members of '" + managerGroup.getName()
                    + "' may manage '" + group.getName() + "'");
            rep.setType("group");
            rep.setLogic(Logic.POSITIVE);
            rep.setDecisionStrategy(DecisionStrategy.UNANIMOUS);
            // extendChildren=true: members of the manager group AND any of its subgroups get access.
            rep.addGroup(managerGroup.getId(), true);

            return RepresentationToModel.toModel(rep, authorizationProvider,
                    policyStore.create(resourceServer, rep));
        } catch (Exception e) {
            LOGGER.error("Error creating group policy '{}': {}", policyName, e.getMessage(), e);
            return null;
        }
    }

    // -------------------------------------------------------------------------
    // Scope permission
    // -------------------------------------------------------------------------

    /**
     * Returns or creates a scope permission for the given group.
     *
     * <p>Keycloak FGAP stores each group as a resource named by the group's UUID.
     * {@code AdminPermissionsSchema} requires both {@code resourceType} (schema validation)
     * and a specific resource ID in {@code resources} (avoids wildcard match across all groups).
     *
     * <p>Both the business group AND the manager group are added as resources so that
     * delegated admins can also manage membership of the manager group (promote/demote managers).
     */
    private Policy getOrCreateGroupPermission(String permissionName, GroupModel group,
                                              GroupModel managerGroup, Policy policy,
                                              ResourceServer resourceServer) {
        try {
            StoreFactory sf = authorizationProvider.getStoreFactory();
            PolicyStore policyStore = sf.getPolicyStore();

            Policy existing = policyStore.findByName(resourceServer, permissionName);
            if (existing != null) {
                LOGGER.debug("Reusing existing permission: {}", permissionName);
                return existing;
            }

            Resource resource = resolveGroupResource(group, resourceServer, sf);
            if (resource == null) {
                LOGGER.error("No FGAP resource found for group '{}'. "
                        + "Ensure 'admin permissions' is enabled in realm settings.", group.getName());
                return null;
            }

            // Also resolve the manager group's FGAP resource so delegated admins
            // can add/remove users from the -manager group (promote/demote managers).
            Resource managerResource = resolveGroupResource(managerGroup, resourceServer, sf);
            Set<String> resourceIds = new LinkedHashSet<>();
            resourceIds.add(resource.getId());
            if (managerResource != null) {
                resourceIds.add(managerResource.getId());
                LOGGER.debug("Including manager group '{}' resource in permission '{}'",
                        managerGroup.getName(), permissionName);
            } else {
                LOGGER.warn("No FGAP resource found for manager group '{}' – "
                        + "delegated admins won't be able to promote/demote managers", managerGroup.getName());
            }

            Set<String> scopeIds = resolveScopeIds(resourceServer, sf.getScopeStore());
            if (scopeIds.isEmpty()) {
                LOGGER.error("No group management scopes found on resource server – cannot create permission for '{}'",
                        group.getName());
                return null;
            }

            ScopePermissionRepresentation rep = new ScopePermissionRepresentation();
            rep.setName(permissionName);
            rep.setDescription("Permission to manage group: " + group.getName());
            rep.setType("scope");
            rep.setLogic(Logic.POSITIVE);
            rep.setDecisionStrategy(DecisionStrategy.UNANIMOUS);
            rep.setPolicies(Set.of(policy.getId()));
            // resourceType is required by AdminPermissionsSchema validation (Keycloak 26+).
            // Both the business group and its manager group are included as resources.
            rep.setResourceType(RESOURCE_TYPE_GROUPS);
            rep.setResources(resourceIds);
            rep.setScopes(scopeIds);

            return RepresentationToModel.toModel(rep, authorizationProvider,
                    policyStore.create(resourceServer, rep));
        } catch (Exception e) {
            LOGGER.error("Error creating permission '{}': {}", permissionName, e.getMessage(), e);
            return null;
        }
    }

    // -------------------------------------------------------------------------
    // User management permission
    // -------------------------------------------------------------------------

    /**
     * Adds {@code managerPolicy} to the single global Users-resource permission
     * ({@value #GLOBAL_USER_PERMISSION_NAME}).
     *
     * <p>A global name is required because Keycloak evaluates ALL matching Users-type permissions
     * under the resource-server's UNANIMOUS strategy.  Two separate root-hierarchy permissions
     * (e.g. {@code europe-users} and {@code asia-users}) would mutually DENY each other's managers:
     * {@code manager@europe.de} satisfies {@code europe-users} but not {@code asia-users} → DENY.
     * One global permission with AFFIRMATIVE strategy sidesteps this entirely.
     */
    private void addManagerPolicyToUsersPermission(GroupModel group, Policy managerPolicy,
                                                   ResourceServer resourceServer) {
        getOrCreateUserPermission(GLOBAL_USER_PERMISSION_NAME, managerPolicy, resourceServer);
    }

    /**
     * Returns or creates a scope permission on the {@code Users} resource type that grants
     * {@code manage} and {@code manage-group-membership} to members of {@code managerPolicy}.
     *
     * <p>Decision strategy is {@code AFFIRMATIVE}: the permission is shared across multiple
     * manager policies (all child group managers accumulate here).
     * If the permission already exists, {@code managerPolicy} is added idempotently.
     */
    private Policy getOrCreateUserPermission(String permName, Policy managerPolicy,
                                             ResourceServer resourceServer) {
        try {
            StoreFactory sf = authorizationProvider.getStoreFactory();
            PolicyStore policyStore = sf.getPolicyStore();

            Policy existing = policyStore.findByName(resourceServer, permName);
            if (existing != null) {
                // Accumulate additional manager policies (e.g. when a new child group is added).
                boolean alreadyLinked = existing.getAssociatedPolicies().stream()
                        .anyMatch(p -> p.getId().equals(managerPolicy.getId()));
                if (!alreadyLinked) {
                    existing.addAssociatedPolicy(managerPolicy);
                    LOGGER.debug("Linked policy '{}' to existing user permission '{}'",
                            managerPolicy.getName(), permName);
                }
                return existing;
            }

            // Resolve scope IDs for manage + manage-group-membership.
            ScopeStore scopeStore = sf.getScopeStore();
            Set<String> scopeIds = new LinkedHashSet<>();
            for (String scopeName : USER_SCOPES) {
                Scope scope = scopeStore.findByName(resourceServer, scopeName);
                if (scope != null) {
                    scopeIds.add(scope.getId());
                } else {
                    LOGGER.warn("User scope '{}' not found on resource server – skipping", scopeName);
                }
            }
            if (scopeIds.isEmpty()) {
                LOGGER.error("No user-management scopes found – cannot create user permission '{}'", permName);
                return null;
            }

            ScopePermissionRepresentation rep = new ScopePermissionRepresentation();
            rep.setName(permName);
            rep.setDescription("User management permission: " + permName);
            rep.setType("scope");
            rep.setLogic(Logic.POSITIVE);
            // AFFIRMATIVE: any single linked policy matching grants access; required for parent
            // group permissions that accumulate multiple child manager policies.
            rep.setDecisionStrategy(DecisionStrategy.AFFIRMATIVE);
            rep.setResourceType(RESOURCE_TYPE_USERS);
            rep.setScopes(scopeIds);
            rep.setPolicies(Set.of(managerPolicy.getId()));

            Policy created = RepresentationToModel.toModel(rep, authorizationProvider,
                    policyStore.create(resourceServer, rep));
            LOGGER.info("Created user management permission '{}'", permName);
            return created;
        } catch (Exception e) {
            LOGGER.error("Error creating user permission '{}': {}", permName, e.getMessage(), e);
            return null;
        }
    }

    // -------------------------------------------------------------------------
    // Resource & scope helpers
    // -------------------------------------------------------------------------

    /**
     * Finds the FGAP resource for the group (keyed by the group UUID).
     * If it does not yet exist (FGAP initialises resources lazily), it is created here.
     */
    private Resource resolveGroupResource(GroupModel group, ResourceServer resourceServer, StoreFactory sf) {
        ResourceStore resourceStore = sf.getResourceStore();

        // Keycloak names per-group FGAP resources by the group's UUID.
        Resource existing = resourceStore.findByName(resourceServer, group.getId());
        if (existing != null) {
            // Heal resources created by an older version of this listener that omitted the type.
            // Without type=Groups, Keycloak cannot correlate the resource to a real group
            // when filtering the /groups listing endpoint via FGAP.
            if (!RESOURCE_TYPE_GROUPS.equals(existing.getType())) {
                existing.setType(RESOURCE_TYPE_GROUPS);
                LOGGER.info("Patched missing type=Groups on FGAP resource for group '{}'", group.getName());
            }
            return existing;
        }

        try {
            Resource created = resourceStore.create(resourceServer, group.getId(), resourceServer.getClientId());
            created.setType(RESOURCE_TYPE_GROUPS);
            created.setDisplayName(group.getName());
            // Attach all group-management scopes.
            Set<Scope> scopes = new HashSet<>();
            ScopeStore scopeStore = sf.getScopeStore();
            for (String scopeName : GROUP_SCOPES) {
                Scope scope = scopeStore.findByName(resourceServer, scopeName);
                if (scope != null) {
                    scopes.add(scope);
                }
            }
            created.updateScopes(scopes);
            LOGGER.debug("Created FGAP resource for group '{}' (id: {})", group.getName(), group.getId());
            return created;
        } catch (Exception e) {
            LOGGER.error("Error creating FGAP resource for group '{}': {}", group.getName(), e.getMessage(), e);
            return null;
        }
    }

    /** Resolves scope UUIDs from the resource server for all group-management scopes. */
    private Set<String> resolveScopeIds(ResourceServer resourceServer, ScopeStore scopeStore) {
        Set<String> ids = new LinkedHashSet<>();
        for (String scopeName : GROUP_SCOPES) {
            Scope scope = scopeStore.findByName(resourceServer, scopeName);
            if (scope != null) {
                ids.add(scope.getId());
            } else {
                LOGGER.warn("Scope '{}' not found on resource server", scopeName);
            }
        }
        return ids;
    }

    // -------------------------------------------------------------------------
    // Naming helpers
    // -------------------------------------------------------------------------

    /**
     * Builds the permission name for a group using its full hierarchy path.
     * Example: top-level {@code bw} → {@code "bw"},
     * subgroup {@code hq/bw} → {@code "hq-bw"}.
     */
    private String buildPermissionName(GroupModel group) {
        return buildGroupPath(group);
    }

    /**
     * Builds the policy name: full path + {@value #MANAGER_SUFFIX}.
     * Example: {@code "bw-manager"} or {@code "hq-bw-manager"}.
     */
    private String buildPolicyName(GroupModel group) {
        return buildGroupPath(group) + MANAGER_SUFFIX;
    }

    /**
     * Returns a dash-joined path from the root down to (and including) the given group.
     * Top-level group {@code hq} → {@code "hq"}.
     * Subgroup {@code hq → bw} → {@code "hq-bw"}.
     */
    private String buildGroupPath(GroupModel group) {
        Deque<String> parts = new ArrayDeque<>();
        GroupModel current = group;
        while (current != null) {
            // Exclude -manager groups from the logical path so that "europe" and
            // "europe-manager/europe" both produce the same name ("europe").
            if (!current.getName().endsWith(MANAGER_SUFFIX)) {
                parts.addFirst(current.getName());
            }
            current = current.getParent();
        }
        return String.join("-", parts);
    }

    // -------------------------------------------------------------------------
    // Infrastructure helpers
    // -------------------------------------------------------------------------

    /** Looks up the {@code admin-permissions} resource server. */
    private ResourceServer getResourceServer(RealmModel realm) {
        try {
            ClientModel client = session.clients().getClientByClientId(realm, CLIENT_ID);
            if (client == null) {
                LOGGER.error("Client '{}' not found in realm '{}'", CLIENT_ID, realm.getName());
                return null;
            }
            return authorizationProvider.getStoreFactory().getResourceServerStore().findByClient(client);
        } catch (Exception e) {
            LOGGER.error("Error looking up resource server for client '{}': {}", CLIENT_ID, e.getMessage(), e);
            return null;
        }
    }

    /**
     * Extracts the {@code id} value from a Keycloak admin event JSON representation.
     * Uses a tight regex rather than a full JSON parse to avoid dependency on a JSON library.
     */
    private String extractGroupId(String representation) {
        if (representation == null || representation.isBlank()) {
            return null;
        }
        Matcher m = ID_PATTERN.matcher(representation);
        return m.find() ? m.group(1) : null;
    }
}
