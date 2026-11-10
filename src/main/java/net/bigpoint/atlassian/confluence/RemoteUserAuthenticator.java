package net.bigpoint.atlassian.confluence;

import com.atlassian.confluence.user.ConfluenceAuthenticator;

import java.security.Principal;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Provides remote-user Single Sign-On (SSO) authentication for Confluence.
 *
 * Authentication is handled by an Apache reverse proxy using Kerberos.
 * Once authenticated, Apache forwards the username through the
 * "remote_user" HTTP request header.
 *
 * The authenticator resolves that username against Confluence's
 * configured user directories and establishes an authenticated session.
 *
 * Updated for Confluence 10.2.19 using the Jakarta Servlet API.
 *
 * Existing authenticated Confluence sessions are prioritized
 * to preserve compatibility with session-based functionality,
 * including ScriptRunner user impersonation.
 *
 * WARNING: Session-first behavior must be evaluated against
 * the deployment's SSO security requirements.
 */
public class RemoteUserAuthenticator extends ConfluenceAuthenticator {

    private static final long serialVersionUID = 1L;

    private static final Log log =
            LogFactory.getLog(RemoteUserAuthenticator.class);

    /**
     * Resolves the authenticated remote user and establishes
     * the corresponding Confluence session.
     *
     * Authentication sequence:
     * 1. Retrieve the username supplied by Apache.
     * 2. Reject requests without a remote identity.
     * 3. Resolve the username in Confluence's user directories.
     * 4. Reuse an existing session when the identity matches.
     * 5. Establish an authorized session through Seraph.
     *
     * @param request the incoming HTTP request
     * @param response the HTTP response
     * @return the authenticated Confluence principal, or null
     *         when authentication cannot be established
     */
    protected Principal resolveSessionUser(HttpServletRequest request) {
    return getUserFromSession(request);
}
    @Override
    public Principal getUser(
            HttpServletRequest request,
            HttpServletResponse response) {

        // 1. Preserve an existing authenticated Confluence session.
        Principal sessionUser = resolveSessionUser(request);

        if (sessionUser != null) {
            log.debug("Using existing authenticated Confluence session");
            return sessionUser;
        }

     /* STEP 2: Retrieve the authenticated username from Apache.
         *
         * The header name is retained for compatibility with the
         * existing Kerberos reverse-proxy configuration.
         */
        String remoteUser = request.getHeader("remote_user");

        if (remoteUser == null || remoteUser.isBlank()) {
            return null;
        }

        remoteUser = remoteUser.trim();

        /*
         * STEP 3: Resolve the username in Confluence's user directory.
         *
         * Kerberos authentication does not automatically guarantee
         * that the user exists in Confluence.
         */
        Principal user = getUser(remoteUser);

        if (user == null) {
            log.warn("SSO user not found in Confluence directory");
            return null;
        }

        /*
         * STEP 5: Establish an authenticated session.
         *
         * Use Confluence/Seraph session management rather than
         * manually modifying internal session attributes.
         */
        if (authoriseUserAndEstablishSession(request, response, user)) {
            log.debug("SSO authentication successful");
            return user;
        }

        /*
         * STEP 6: Return null if session authorization fails.
         */
        log.warn("SSO session authorization failed");
        return null;
    }
}
