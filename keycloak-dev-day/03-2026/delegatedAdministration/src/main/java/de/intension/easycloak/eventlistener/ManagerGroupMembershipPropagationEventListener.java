package de.intension.easycloak.eventlistener;

import org.keycloak.events.Event;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.events.admin.OperationType;
import org.keycloak.events.admin.ResourceType;
import org.keycloak.models.ClientModel;
import org.keycloak.models.GroupModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * When a user is added to a {@code -manager} group, automatically adds that user to
 * <em>all</em> descendant {@code -manager} groups as well.
 *
 * <p>This mirrors the hierarchical structure created by {@link GroupBasedDelegationEventListener}:
 * <pre>
 *   europe-manager              ← user added here
 *     └── europe
 *           └── germany-manager  ← user auto-added here
 *                 └── germany
 *                       └── berlin-manager  ← user auto-added here
 *                             └── berlin
 * </pre>
 *
 * <p>The propagation is downward only and skips groups the user already belongs to.
 * Adding a user to a non-{@code -manager} group is ignored entirely.
 */
public class ManagerGroupMembershipPropagationEventListener implements EventListenerProvider {

    private static final Logger LOGGER =
            LoggerFactory.getLogger(ManagerGroupMembershipPropagationEventListener.class);

    /**
     * Admin event resource path pattern for adding a user to a group:
     * {@code users/{userId}/groups/{groupId}}
     */
    private static final Pattern MEMBERSHIP_PATH =
            Pattern.compile("users/([^/]+)/groups/([^/]+)");

    private static final String MANAGER_SUFFIX = GroupBasedDelegationEventListener.MANAGER_SUFFIX;

    /** Client and roles automatically granted when a user joins a {@code -manager} group. */
    private static final String REALM_MANAGEMENT_CLIENT  = "realm-management";
    private static final String[] MANAGER_ROLES = {"query-users", "query-groups"};

    private final KeycloakSession session;

    public ManagerGroupMembershipPropagationEventListener(KeycloakSession session) {
        this.session = Objects.requireNonNull(session, "session must not be null");
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
        if (adminEvent == null
                || adminEvent.getResourceType() != ResourceType.GROUP_MEMBERSHIP
                || adminEvent.getOperationType() != OperationType.CREATE) {
            return;
        }

        String resourcePath = adminEvent.getResourcePath();
        if (resourcePath == null) return;

        Matcher m = MEMBERSHIP_PATH.matcher(resourcePath);
        if (!m.find()) return;

        String userId  = m.group(1);
        String groupId = m.group(2);

        RealmModel realm = session.getContext().getRealm();

        GroupModel group = session.groups().getGroupById(realm, groupId);
        if (group == null) {
            LOGGER.warn("Group not found: {}", groupId);
            return;
        }

        // Only propagate when the target group is a manager group.
        if (!group.getName().endsWith(MANAGER_SUFFIX)) {
            return;
        }

        UserModel user = session.users().getUserById(realm, userId);
        if (user == null) {
            LOGGER.warn("User not found: {}", userId);
            return;
        }

        LOGGER.debug("User '{}' added to '{}' – propagating to child manager groups",
                user.getUsername(), group.getName());

        assignManagerRoles(realm, user);

        // The managed group is the direct child of this manager group whose name
        // does NOT end with -manager (e.g. europe-manager → europe).
        GroupModel managedGroup = group.getSubGroupsStream()
                .filter(g -> !g.getName().endsWith(MANAGER_SUFFIX))
                .findFirst()
                .orElse(null);

        if (managedGroup == null) {
            LOGGER.debug("No managed group found under '{}' – nothing to propagate", group.getName());
            return;
        }

        int count = propagate(user, managedGroup);
        if (count > 0) {
            LOGGER.info("Propagated user '{}' to {} descendant manager group(s) from '{}'",
                    user.getUsername(), count, group.getName());
        } else {
            LOGGER.debug("No new child manager groups to join for user '{}' from '{}'",
                    user.getUsername(), group.getName());
        }
    }

    // -------------------------------------------------------------------------
    // Role assignment
    // -------------------------------------------------------------------------

    /**
     * Grants {@code query-users} and {@code query-groups} from {@code realm-management}
     * to the given user, unless they are already assigned.
     */
    private void assignManagerRoles(RealmModel realm, UserModel user) {
        ClientModel mgmtClient = session.clients().getClientByClientId(realm, REALM_MANAGEMENT_CLIENT);
        if (mgmtClient == null) {
            LOGGER.warn("Client '{}' not found – skipping role assignment", REALM_MANAGEMENT_CLIENT);
            return;
        }
        for (String roleName : MANAGER_ROLES) {
            RoleModel role = mgmtClient.getRole(roleName);
            if (role == null) {
                LOGGER.warn("Role '{}' not found in '{}' – skipping", roleName, REALM_MANAGEMENT_CLIENT);
                continue;
            }
            if (user.hasRole(role)) {
                LOGGER.debug("User '{}' already has role '{}'", user.getUsername(), roleName);
            } else {
                user.grantRole(role);
                LOGGER.info("Granted role '{}' to user '{}'", roleName, user.getUsername());
            }
        }
    }

    // -------------------------------------------------------------------------
    // Propagation
    // -------------------------------------------------------------------------

    /**
     * Recursively walks {@code managedGroup}'s subtree and adds {@code user} to every
     * {@code -manager} group found there.
     *
     * <p>Structure assumed by each recursion level:
     * <pre>
     *   managedGroup
     *     ├── childName-manager  ← join user here, then recurse via childName
     *     │     └── childName    ← recurse into this
     *     └── anotherChild-manager
     *           └── anotherChild
     * </pre>
     *
     * @return number of manager groups the user was newly added to
     */
    private int propagate(UserModel user, GroupModel managedGroup) {
        int joined = 0;
        for (GroupModel child : managedGroup.getSubGroupsStream().toList()) {
            if (!child.getName().endsWith(MANAGER_SUFFIX)) {
                // Could be a non-manager subgroup that itself has child manager groups – recurse.
                joined += propagate(user, child);
                continue;
            }

            // child is a -manager group → add user if not already a member.
            if (!user.isMemberOf(child)) {
                user.joinGroup(child);
                LOGGER.debug("  → joined '{}' to '{}'", user.getUsername(), child.getName());
                joined++;
            } else {
                LOGGER.debug("  → '{}' already member of '{}', skipping", user.getUsername(), child.getName());
            }

            // Recurse: find the managed sibling inside this manager group and go deeper.
            child.getSubGroupsStream()
                    .filter(g -> !g.getName().endsWith(MANAGER_SUFFIX))
                    .forEach(subManaged -> propagate(user, subManaged));
        }
        return joined;
    }
}
