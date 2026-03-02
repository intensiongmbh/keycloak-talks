package de.intension.custom.policy;


import com.google.auto.service.AutoService;
import org.keycloak.authorization.AuthorizationProvider;
import org.keycloak.authorization.policy.provider.PolicyProvider;
import org.keycloak.authorization.policy.provider.PolicyProviderFactory;
import org.keycloak.authorization.policy.provider.regex.RegexPolicyProvider;
import org.keycloak.authorization.policy.provider.regex.RegexPolicyProviderFactory;
import org.keycloak.models.KeycloakSession;

@AutoService(PolicyProviderFactory.class)
public class CustomRegexPolicyProviderFactory extends RegexPolicyProviderFactory {

  private static final String ID = "custom-regex";
  private CustomRegexPolicyProvider provider = new CustomRegexPolicyProvider(this::toRepresentation);

  @Override
  public PolicyProvider create(KeycloakSession session) {
    return provider;
  }

  @Override
  public PolicyProvider create(AuthorizationProvider authorization) {
    return provider;
  }
}
