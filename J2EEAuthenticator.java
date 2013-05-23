package com.atlassian.confluence.ex;

import com.atlassian.confluence.user.ConfluenceAuthenticator;

import java.security.Principal;

import com.atlassian.seraph.auth.DefaultAuthenticator;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Category;

/**
 * A simple Authenticator which retrieves a user from the user accessor using the container provided principal from
 * {@link javax.servlet.http.HttpServletRequest#getRemoteUser)
 */
public class J2EEAuthenticator extends ConfluenceAuthenticator
{
    private static final long serialVersionUID = 1L;
    private static final Category log = Category.getInstance(J2EEAuthenticator.class);

    public Principal getUser(HttpServletRequest request, HttpServletResponse response)
    {
        log.debug("inside getUser()");

        if (request.getSession() != null && request.getSession().getAttribute(DefaultAuthenticator.LOGGED_IN_KEY) != null)
        {
            log.debug("Session found; user already logged in");
            return (Principal) request.getSession().getAttribute(DefaultAuthenticator.LOGGED_IN_KEY);
        }

        String remoteUser = request.getRemoteUser();
        log.debug("getRemoteUser() = " + remoteUser);

        if (remoteUser == null)
        {
            /*
            * If remoteUser isnull, the there is no container authenticated user in this user session, so I'm returing null
            * to get the Confluence logon
            */
            return null;
        }

        // Try to retrieve the user from the configured user repository
        Principal user = getUser(remoteUser);
        if (user == null)
        {
            log.warn("Authenticated user cannot be found in any user repository");
            return null;
        }

        log.info("Logged in via SSO with User " + user);
        request.getSession().setAttribute(DefaultAuthenticator.LOGGED_IN_KEY, user);
        request.getSession().setAttribute(DefaultAuthenticator.LOGGED_OUT_KEY, null);

        return user;
    }
}
