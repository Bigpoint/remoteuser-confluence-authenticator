
package net.bigpoint.atlassian.confluence;

import com.atlassian.confluence.user.ConfluenceUser;
import com.atlassian.seraph.auth.DefaultAuthenticator;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import org.junit.Before;
import org.junit.Test;

import java.security.Principal;

import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

public class RemoteUserAuthenticatorTest {

    private TestableAuthenticator authenticator;
    private HttpServletRequest request;
    private HttpServletResponse response;
    private ConfluenceUser user;

    private static class TestableAuthenticator
        extends RemoteUserAuthenticator {

        @Override
        public ConfluenceUser getUser(String username) {
            return super.getUser(username);
        }

        @Override
        public Principal getUserFromSession(
                HttpServletRequest request) {
            return super.getUserFromSession(request);
        }

        @Override
        public boolean authoriseUserAndEstablishSession(
                HttpServletRequest request,
                HttpServletResponse response,
                Principal principal) {
            return super.authoriseUserAndEstablishSession(
                    request, response, principal);
        }
    }
    @Before
    public void setUp() {
        // Spy on the authenticator so Confluence services are not required.
        authenticator = spy(new TestableAuthenticator());

        request = mock(HttpServletRequest.class);
        response = mock(HttpServletResponse.class);
        user = mock(ConfluenceUser.class);

        when(user.getName()).thenReturn("test");
    }

    @Test
    public void testAuthenticate() {
        // Apache Kerberos has authenticated the user.
        when(request.getHeader("remote_user")).thenReturn("test");

        // Simulate Confluence finding the corresponding account.
        doReturn(user).when(authenticator).getUser("test");

        // No existing Seraph session.
        doReturn(null).when(authenticator).getUserFromSession(request);

        // Simulate successful session authorization.
        doReturn(true).when(authenticator)
                .authoriseUserAndEstablishSession(request, response, user);

        Principal principal = authenticator.getUser(request, response);

        assertSame(user, principal);

        verify(authenticator).getUser("test");
        verify(authenticator)
                .authoriseUserAndEstablishSession(request, response, user);
    }

    @Test
    public void testAuthenticateWithLoggedInSession() {
        when(request.getHeader("remote_user")).thenReturn("test");

        doReturn(user).when(authenticator).getUser("test");
        doReturn(user).when(authenticator).getUserFromSession(request);

        Principal principal = authenticator.getUser(request, response);

        assertSame(user, principal);

        // An existing matching session should be reused.
        verify(authenticator, never())
                .authoriseUserAndEstablishSession(
                        any(HttpServletRequest.class),
                        any(HttpServletResponse.class),
                        any(Principal.class));
    }

    @Test
    public void testAuthenticateDoesNotCreateSessionIfLoginFails() {
        when(request.getHeader("remote_user")).thenReturn("test");

        // The user does not exist in Confluence.
        doReturn(null).when(authenticator).getUser("test");

        Principal principal = authenticator.getUser(request, response);

        assertNull(principal);

        // Authentication must fail before session establishment.
        verify(authenticator, never())
                .authoriseUserAndEstablishSession(
                        any(HttpServletRequest.class),
                        any(HttpServletResponse.class),
                        any(Principal.class));
    }

    @Test
    public void testMissingRemoteUserHeader() {
        when(request.getHeader("remote_user")).thenReturn(null);

        Principal principal = authenticator.getUser(request, response);

        assertNull(principal);

        // Never attempt to establish a session without an identity.
        verify(authenticator, never())
                .authoriseUserAndEstablishSession(
                        any(HttpServletRequest.class),
                        any(HttpServletResponse.class),
                        any(Principal.class));
    }

    @Test
    public void testSessionAuthorizationFailure() {
        when(request.getHeader("remote_user")).thenReturn("test");

        doReturn(user).when(authenticator).getUser("test");
        doReturn(null).when(authenticator).getUserFromSession(request);

        // Confluence refuses to establish the session.
        doReturn(false).when(authenticator)
                .authoriseUserAndEstablishSession(request, response, user);

        Principal principal = authenticator.getUser(request, response);

        assertNull(principal);
    }
    @Test
    public void shouldPreserveImpersonatedSession() {

        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);

        Principal impersonatedUser = () -> "test.user";

        // Apache continues identifying the original administrator.
        when(request.getHeader("remote_user"))
                .thenReturn("admin.user");

        RemoteUserAuthenticator authenticator =
                spy(new RemoteUserAuthenticator());

        // Simulate an existing impersonated Confluence session.
        doReturn(impersonatedUser)
                .when(authenticator)
                .resolveSessionUser(request);

        Principal result = authenticator.getUser(request, response);

        assertNotNull(result);
        assertEquals("test.user", result.getName());
    }
}
