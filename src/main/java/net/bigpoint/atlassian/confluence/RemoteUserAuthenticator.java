package net.bigpoint.atlassian.confluence;

import com.atlassian.confluence.user.ConfluenceAuthenticator;

import java.security.Principal;

import com.atlassian.seraph.auth.DefaultAuthenticator;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Category;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * A simple Authenticator which allows us to grab a user name from http header or from the session.
 * We use it in a scenario where we have a web server running as reverse proxy. It does Kerberos authentication for us
 * and on success writes the user name (nickname, e.g. jsmith) into a custom header.
 * For now, we use "remote_user" for this.
 */
public class RemoteUserAuthenticator extends ConfluenceAuthenticator {
    private static final long serialVersionUID = 1L;
    private static final Log log = LogFactory.getLog(RemoteUserAuthenticator.class);

    public Principal getUser(HttpServletRequest request, HttpServletResponse response) {

        // If we have a valid session, try to grab session user and use it for authentication.
        if (request.getSession() != null) {
            Principal sessionUser = getUserFromSession(request);
            if (sessionUser != null) {
                return sessionUser;
            }
        }

        // Otherwise we will need to get the nickname from the request otherwise.
        // getRemoteUser does not work so far so we make our reverse proxy write a header we use.
        // This works but sucks, hopefully we will learn how to fix this.
        // This would be what we actually want to do but the result will always be null for unknown reasons:

        // String remoteUser = request.getRemoteUser();
        // log.warn("request.getRemoteUser() = " + request.getRemoteUser() );

        // And here is our workaround.
        String remoteUser = request.getHeader("remote_user");
        log.info("request.getHeader(\"remote_user\") = " + remoteUser);

        // Still null? just return it. Confluence will consider this as anonymous and redirect to login dialog
        // in case anonymous has no permissions.
        if (remoteUser == null) {
            return null;
        }

        // Try to retrieve the user from the configured user repository.
        Principal user = getUser(remoteUser);

        if (user == null) {
            log.error("Authenticated user '" + remoteUser + "' cannot be found in any user repository");
            return null;
        }

        // Modify session signaling that we are authenticated now.
        request.getSession().setAttribute(DefaultAuthenticator.LOGGED_IN_KEY, user);
        request.getSession().setAttribute(DefaultAuthenticator.LOGGED_OUT_KEY, null);

        log.info("Logged in via SSO with User " + remoteUser);

        return user;
    }
}

