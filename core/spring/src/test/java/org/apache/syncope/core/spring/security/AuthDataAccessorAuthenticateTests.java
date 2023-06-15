package org.apache.syncope.core.spring.security;

import org.apache.commons.lang3.tuple.Triple;
import org.apache.syncope.common.keymaster.client.api.ConfParamOps;
import org.apache.syncope.common.lib.types.CipherAlgorithm;
import org.apache.syncope.core.persistence.api.dao.RealmDAO;
import org.apache.syncope.core.persistence.api.dao.UserDAO;
import org.apache.syncope.core.persistence.api.entity.Realm;
import org.apache.syncope.core.persistence.api.entity.user.User;
import org.apache.syncope.core.spring.security.utils.EncryptorOracle;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.runners.Enclosed;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.mockito.Mockito;
import org.springframework.security.core.Authentication;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

@RunWith(Enclosed.class)
public class AuthDataAccessorAuthenticateTests {
    private static final String USERNAME = "username";
    private static final String PASSWORD = "password";
    private static final String DOMAIN = "Master";
    private static final String INVALID_USERNAME = "invalidUsername";
    private static final String INVALID_PASSWORD = "invalidPassword";
    private static final String ACTIVE = "active";
    private static final User user;

    static {
        try {
            user = createUser(USERNAME, PASSWORD, CipherAlgorithm.BCRYPT, PASSWORD);
        } catch (NoSuchPaddingException | IllegalBlockSizeException | NoSuchAlgorithmException | BadPaddingException |
                 InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }

    public static User createUser(String username, String password, CipherAlgorithm cipherAlgorithm, String secretKey)
            throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException,
            InvalidKeyException {
        User user = Mockito.mock(User.class);
        Mockito.when(user.getUsername()).thenReturn(username);
        Mockito.when(user.getPassword()).thenReturn(EncryptorOracle.encode(password, cipherAlgorithm, secretKey));
        Mockito.when(user.getCipherAlgorithm()).thenReturn(cipherAlgorithm);
        Mockito.when(user.getStatus()).thenReturn(ACTIVE);
        return user;
    }

    public static UserDAO createUserDAO(List<User> users) {
        UserDAO userDAO = Mockito.mock(UserDAO.class);
        for (User user : users)
            Mockito.when(userDAO.findByUsername(user.getUsername())).thenReturn(user);
        return userDAO;
    }

    public static ConfParamOps createConfParamOps(String domain) {
        ConfParamOps confParamOps = Mockito.mock(ConfParamOps.class);
        Mockito.when(confParamOps.get(domain, "authentication.attributes", new String[]{"username"},
                String[].class)).thenReturn(new String[]{USERNAME});
        Mockito.when(confParamOps.get(domain, "authentication.statuses", new String[]{}, String[].class))
                .thenReturn(new String[]{ACTIVE});
        Mockito.when(confParamOps.get(domain, "log.lastlogindate", true, Boolean.class))
                .thenReturn(false);
        return confParamOps;
    }

    public static RealmDAO createRealmDAO() {
        RealmDAO realmDAO = Mockito.mock(RealmDAO.class);
        Realm realm = Mockito.mock(Realm.class);
        Mockito.when(realmDAO.findAncestors(Mockito.any(Realm.class))).thenReturn(List.of(realm));
        return realmDAO;
    }

    public static Authentication createAuthentication(String username, String password, String domain) {
        Authentication authentication = Mockito.mock(Authentication.class);
        Mockito.when(authentication.getName()).thenReturn(username);
        Mockito.when(authentication.getCredentials()).thenReturn(password);
        SyncopeAuthenticationDetails details = new SyncopeAuthenticationDetails(domain, null);
        Mockito.when(authentication.getDetails()).thenReturn(details);
        return authentication;
    }

    public static Authentication createAuthentication(AuthenticationType authenticationType) {
        Authentication authentication;
        switch (authenticationType) {
            case NULL -> authentication = null;
            case INVALID_USERNAME -> authentication = createAuthentication(INVALID_USERNAME, PASSWORD, DOMAIN);
            case INVALID_PASSWORD -> authentication = createAuthentication(USERNAME, INVALID_PASSWORD, DOMAIN);
            case EMPTY_PASSWORD -> authentication = createAuthentication(USERNAME, "", DOMAIN);
            case NULL_PASSWORD -> authentication = createAuthentication(USERNAME, null, DOMAIN);
            // Case valid
            default -> authentication = createAuthentication(USERNAME, PASSWORD, DOMAIN);
        }
        return authentication;
    }

    public enum AuthenticationType {
        NULL,
        VALID,
        INVALID_USERNAME,
        INVALID_PASSWORD,
        EMPTY_PASSWORD,
        NULL_PASSWORD
    }

    @RunWith(Parameterized.class)
    public static class AuthDataAccessorAuthenticateTest {
        private final Triple<User, Boolean, String> expected;
        private final Class<Throwable> exceptionClass;
        private final String domain;
        private final Authentication authentication;
        private AuthDataAccessor sut;

        public AuthDataAccessorAuthenticateTest(Triple<User, Boolean, String> expected, Class<Throwable> exceptionClass, String domain,
                                                AuthenticationType authenticationType) {
            this.expected = expected;
            this.exceptionClass = exceptionClass;
            this.domain = domain;
            this.authentication = createAuthentication(authenticationType);
        }

        @Parameterized.Parameters
        public static Collection<Object[]> getParameters() {
            return Arrays.asList(new Object[][]{
                    {null, NullPointerException.class, null, AuthenticationType.VALID},
                    {null, NullPointerException.class, DOMAIN, AuthenticationType.NULL},
                    {Triple.of(user, true, null), null, DOMAIN, AuthenticationType.VALID},
                    {Triple.of(null, null, null), null, DOMAIN, AuthenticationType.INVALID_USERNAME},
                    {Triple.of(user, false, null), null, DOMAIN, AuthenticationType.INVALID_PASSWORD},
                    {Triple.of(user, false, null), null, DOMAIN, AuthenticationType.EMPTY_PASSWORD},
                    {null, NullPointerException.class, DOMAIN, AuthenticationType.NULL_PASSWORD}
            });
        }

        @Before
        public void init() {
            UserDAO userDAO = createUserDAO(List.of(user));
            RealmDAO realmDAO = createRealmDAO();
            ConfParamOps confParamOps = createConfParamOps(DOMAIN);
            this.sut = new AuthDataAccessor(new SecurityProperties(), realmDAO, userDAO, null, null,
                    null, confParamOps, null, null, null,
                    null, null, null);
        }

        @Test
        public void testAuthenticate() {
            try {
                Triple<User, Boolean, String> result = sut.authenticate(this.domain, this.authentication);
                Assert.assertEquals(result, this.expected);
            } catch (Exception e) {
                if (this.exceptionClass == null) {
                    Assert.fail("Exception thrown");
                    e.printStackTrace();
                }
                Assert.assertTrue(this.exceptionClass.isInstance(e));
            }
        }

    }

}
