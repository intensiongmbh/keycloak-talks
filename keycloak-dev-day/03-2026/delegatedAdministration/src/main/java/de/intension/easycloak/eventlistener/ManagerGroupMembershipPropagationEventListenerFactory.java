package de.intension.easycloak.eventlistener;

import org.keycloak.Config;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventListenerProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

/**
 * SPI factory for {@link ManagerGroupMembershipPropagationEventListener}.
 *
 * <p>Register in the Keycloak realm via the Admin UI (Events → Event Listeners) or via:
 * <pre>
 *   PUT /admin/realms/{realm}
 *   {"eventsListeners": ["jboss-logging", "group-based-delegation", "manager-group-membership-propagation"]}
 * </pre>
 */
public class ManagerGroupMembershipPropagationEventListenerFactory
        implements EventListenerProviderFactory {

    public static final String FACTORY_ID = "manager-group-membership-propagation";

    @Override
    public EventListenerProvider create(KeycloakSession session) {
        return new ManagerGroupMembershipPropagationEventListener(session);
    }

    @Override
    public void init(Config.Scope config) {
        // no configuration needed
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // no post-init needed
    }

    @Override
    public void close() {
        // nothing to close
    }

    @Override
    public String getId() {
        return FACTORY_ID;
    }
}
