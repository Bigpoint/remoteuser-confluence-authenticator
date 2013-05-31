package net.bigpoint.atlassian.confluence;

import com.atlassian.confluence.user.UserAccessor;
import com.atlassian.crowd.exception.UserNotFoundException;
import com.atlassian.seraph.auth.DefaultAuthenticator;
import com.atlassian.spring.container.ContainerContext;
import com.atlassian.spring.container.ContainerManager;
import com.atlassian.user.User;
import com.atlassian.user.impl.DefaultUser;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.security.Principal;

import static org.mockito.Mockito.*;
import static org.junit.Assert.*;

public class RemoteUserAuthenticatorTest {

    private RemoteUserAuthenticator authenticator;

    private @Mock ContainerContext containerContext;
    private @Mock UserAccessor userAccessor;

    private final DefaultUser user = new DefaultUser("test", "Test User", "test@example.com");

    @Before
    public void setUp() throws Exception
    {
        MockitoAnnotations.initMocks(this);

        authenticator = new RemoteUserAuthenticator();

        ContainerManager.getInstance().setContainerContext(containerContext);
        when(containerContext.getComponent("userAccessor")).thenReturn(userAccessor);
    }

    @Test
    public void testAuthenticate() throws Exception
    {
        HttpSession session = mock(HttpSession.class);
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);

        when(request.getSession(false)).thenReturn(null); // no session initially
        when(request.getSession()).thenReturn(session); // created on demand
        when(request.getHeader("remote_user")).thenReturn("test");
        when(userAccessor.getUser("test")).thenReturn(user);

        Principal principal = authenticator.getUser(request, response);

        assertEquals(user, principal);
        verify(userAccessor).getUser("test");
    }

    @Test
    public void testAuthenticateWithLoggedInSession() throws Exception
    {
        HttpSession session = mock(HttpSession.class);
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);

        when(request.getSession()).thenReturn(session); // session is created by Seraph
        when(session.getAttribute(DefaultAuthenticator.LOGGED_IN_KEY)).thenReturn(user);
        when(userAccessor.getUser(user.getName())).thenReturn(user);

        Principal principal = authenticator.getUser(request, response);

        assertEquals(user, principal);
        verify(userAccessor, atLeastOnce()).getUser(user.getName());
        verifyNoMoreInteractions(userAccessor);
    }

    @Test
    public void testAuthenticateDoesNotCreateSessionIfLoginFails() throws Exception
    {
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        HttpSession session = mock(HttpSession.class);

        when(request.getSession()).thenReturn(session); // session is created

        when(request.getHeader("remote_user")).thenReturn("test");
        when(userAccessor.getUser("test")).thenReturn(null); // user doesn't exist -- fails authentication

        Principal principal = authenticator.getUser(request, response);

        assertNull(principal);
        verify(session, never()).setAttribute(DefaultAuthenticator.LOGGED_IN_KEY, user);
        verify(userAccessor).getUser("test");
        verifyNoMoreInteractions(userAccessor);
    }
}