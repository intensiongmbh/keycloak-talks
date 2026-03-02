package de.intension.custom.policy;


import org.jboss.logging.Logger;
import org.keycloak.authorization.AuthorizationProvider;
import org.keycloak.authorization.model.Policy;
import org.keycloak.authorization.policy.evaluation.Evaluation;
import org.keycloak.authorization.policy.provider.regex.RegexPolicyProvider;
import org.keycloak.representations.idm.authorization.RegexPolicyRepresentation;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.Objects;
import java.util.function.BiFunction;

public class CustomRegexPolicyProvider extends RegexPolicyProvider {
  private static final Logger logger = Logger.getLogger(CustomRegexPolicyProvider.class);
  private static final String ALLOW_IMPERSONATION_BY_KEY = "allow-impersonation-by";

  public CustomRegexPolicyProvider(BiFunction<Policy, AuthorizationProvider, RegexPolicyRepresentation> representationFunction) {
    super(representationFunction);
  }

  @Override
  public void evaluate(Evaluation evaluation) {
    var permission = evaluation.getPermission();
    var accessedResource = permission.getResource();

    var authz = evaluation.getAuthorizationProvider();
    var session = authz.getKeycloakSession();
    var realm = session.getContext().getRealm();

    // Get the targetUser if null, then deny
    String targetUserId = accessedResource.getName();
    logger.infof("targetUserId: %s", targetUserId);
    var targetUser = session.users().getUserById(realm, targetUserId);

    if (targetUser == null) {
      evaluation.deny();
      logger.info("Target User null, Denying access");
      return;
    }
    logger.infof("Target user: %s", targetUser.getUsername());

    // get attribute of accessedResource (User)
    if (!targetUser.getAttributes().containsKey(ALLOW_IMPERSONATION_BY_KEY)) {
      evaluation.deny();
      logger.infof("Target User does not have attribute: '%s', Denying access", ALLOW_IMPERSONATION_BY_KEY);
      return;
    }
    // get all allowed impersonators
    String requesterEmail = session.users().getUserById(realm, evaluation.getContext().getIdentity().getId()).getEmail();
    List<Impersonator> allowedImpersonators =
        targetUser.getAttributes().get(ALLOW_IMPERSONATION_BY_KEY)
            .stream()
            .map(this::tokenize)
            .toList();
    if (allowedImpersonators.isEmpty()) {
      evaluation.deny();
      logger.info("Denying access, list of allowed impersonators is empty");
      return;
    }

    allowedImpersonators.forEach(impersonator -> logger.infof("Allowed impersonator: %s", impersonator));
    if (allowedImpersonators.stream().anyMatch(impersonator ->
        impersonator.email().equals(requesterEmail)
            && impersonator.isBetweenTimeFrame(new Date(System.currentTimeMillis())))) {
      evaluation.grant();
      logger.info("Granting access");
    } else {
      evaluation.deny();
      logger.info("Denying access");
    }

  }

  private Impersonator tokenize(String impersonationString) {
    String[] parts = impersonationString.split(";");
    if (parts.length != 3) {
      throw new IllegalArgumentException("Invalid impersonation string format");
    }

    try {
      SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd");

      String email = parts[0];
      Date start = sdf.parse(parts[1]);
      Date end = sdf.parse(parts[2]);

      return new Impersonator(email, start, end);
    } catch (Exception e) {
      throw new RuntimeException("Failed to parse dates", e);
    }
  }
}
