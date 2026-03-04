package de.intension.easycloak.eventlistener;

import org.keycloak.Config;
import org.keycloak.authorization.AuthorizationProvider;
import org.keycloak.authorization.policy.evaluation.DefaultPolicyEvaluator;
import org.keycloak.authorization.policy.evaluation.PolicyEvaluator;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventListenerProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

/**
 * Factory for {@link GroupBasedDelegationEventListener}.
 *
 * <p>Register this factory ID ({@value #FACTORY_ID}) in the realm's event listener settings
 * (Realm settings → Events → Event listeners) to activate group-based delegated administration.
 */
public class GroupBasedDelegationEventListenerFactory implements EventListenerProviderFactory {

    /** Factory ID used to register this listener in Keycloak realm settings. */
    public static final String FACTORY_ID = "group-based-delegation";

    private final PolicyEvaluator policyEvaluator = new DefaultPolicyEvaluator();

    @Override
    public EventListenerProvider create(KeycloakSession session) {
        AuthorizationProvider authorizationProvider =
                new AuthorizationProvider(session, session.getContext().getRealm(), policyEvaluator);
        return new GroupBasedDelegationEventListener(session, authorizationProvider);
    }

    @Override
    public void init(Config.Scope config) {
        // no configuration needed
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // nothing to do
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
