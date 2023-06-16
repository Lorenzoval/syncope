package org.apache.syncope.core.spring.security;

import org.apache.commons.lang3.tuple.Triple;
import org.apache.syncope.common.keymaster.client.api.ConfParamOps;
import org.apache.syncope.common.lib.types.AnyTypeKind;
import org.apache.syncope.common.lib.types.CipherAlgorithm;
import org.apache.syncope.core.persistence.api.dao.AnySearchDAO;
import org.apache.syncope.core.persistence.api.dao.RealmDAO;
import org.apache.syncope.core.persistence.api.dao.UserDAO;
import org.apache.syncope.core.persistence.api.dao.search.AttrCond;
import org.apache.syncope.core.persistence.api.dao.search.SearchCond;
import org.apache.syncope.core.persistence.api.entity.Realm;
import org.apache.syncope.core.persistence.api.entity.user.User;
import org.apache.syncope.core.spring.security.utils.EncryptorOracle;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.experimental.runners.Enclosed;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.mockito.Mockito;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.core.Authentication;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.OffsetDateTime;
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
    private static final String IOT_DEVICE = "iot_device";

    public static User createUser(String username, String password, CipherAlgorithm cipherAlgorithm, String secretKey,
                                  Boolean suspended, String status, int failedLogins)
            throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException,
            InvalidKeyException {
        User user = Mockito.mock(User.class);
        Mockito.when(user.getUsername()).thenReturn(username);
        Mockito.when(user.getPassword()).thenReturn(EncryptorOracle.encode(password, cipherAlgorithm, secretKey));
        Mockito.when(user.getCipherAlgorithm()).thenReturn(cipherAlgorithm);
        Mockito.when(user.getStatus()).thenReturn(status);
        Mockito.when(user.isSuspended()).thenReturn(suspended);
        Mockito.when(user.getFailedLogins()).thenReturn(failedLogins);
        return user;
    }

    public static UserDAO createUserDAO(List<User> users) {
        UserDAO userDAO = Mockito.mock(UserDAO.class);
        for (User user : users)
            Mockito.when(userDAO.findByUsername(user.getUsername())).thenReturn(user);
        return userDAO;
    }

    public static AnySearchDAO createAnySearchDAO(List<User> users, String attribute) {
        AnySearchDAO anySearchDAO = Mockito.mock(AnySearchDAO.class);
        for (User user : users) {
            AttrCond attrCond = new AttrCond(AttrCond.Type.EQ);
            attrCond.setSchema(attribute);
            attrCond.setExpression(user.getUsername());
            Mockito.when(anySearchDAO.search(SearchCond.getLeaf(attrCond), AnyTypeKind.USER)).thenReturn(List.of(user));
        }
        return anySearchDAO;
    }

    public static ConfParamOps createConfParamOps(String domain, String attribute, boolean logLastLoginDate) {
        ConfParamOps confParamOps = Mockito.mock(ConfParamOps.class);
        Mockito.when(confParamOps.get(domain, "authentication.attributes", new String[]{"username"},
                String[].class)).thenReturn(new String[]{attribute});
        Mockito.when(confParamOps.get(domain, "authentication.statuses", new String[]{}, String[].class))
                .thenReturn(new String[]{ACTIVE});
        Mockito.when(confParamOps.get(domain, "log.lastlogindate", true, Boolean.class))
                .thenReturn(logLastLoginDate);
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
            default -> authentication = createAuthentication(USERNAME, PASSWORD, DOMAIN); // Case VALID
        }
        return authentication;
    }

    public static Triple<User, Boolean, String> expectedResultToTriple(ExpectedResult expectedResult, User user) {
        Triple<User, Boolean, String> triple = null;
        switch (expectedResult) {
            case NULL_NULL_NULL -> triple = Triple.of(null, null, null);
            case USER_TRUE_NULL -> triple = Triple.of(user, true, null);
            case USER_FALSE_NULL -> triple = Triple.of(user, false, null);
            default -> {
            } // Case NULL
        }
        return triple;
    }

    private enum AuthenticationType {
        NULL,
        VALID,
        INVALID_USERNAME,
        INVALID_PASSWORD,
        EMPTY_PASSWORD,
        NULL_PASSWORD
    }

    private enum ExpectedResult {
        // To be expanded as needed
        NULL,
        NULL_NULL_NULL,
        USER_FALSE_NULL,
        USER_TRUE_NULL
    }

    @RunWith(Parameterized.class)
    public static class AuthDataAccessorAuthenticateTest {
        private final ExpectedResult expectedResult;
        private final Class<Throwable> exceptionClass;
        private final String domain;
        private final Authentication authentication;
        private final String attribute;
        private Triple<User, Boolean, String> expected;
        private AuthDataAccessor sut;

        public AuthDataAccessorAuthenticateTest(ExpectedResult expectedResult, Class<Throwable> exceptionClass, String domain,
                                                AuthenticationType authenticationType, String attribute) {
            this.expectedResult = expectedResult;
            this.exceptionClass = exceptionClass;
            this.domain = domain;
            this.authentication = createAuthentication(authenticationType);
            this.attribute = attribute;
        }

        @Parameterized.Parameters
        public static Collection<Object[]> getParameters() {
            return Arrays.asList(new Object[][]{
                    {ExpectedResult.NULL, NullPointerException.class, null, AuthenticationType.VALID, USERNAME},
                    {ExpectedResult.NULL, NullPointerException.class, DOMAIN, AuthenticationType.NULL, USERNAME},
                    {ExpectedResult.USER_TRUE_NULL, null, DOMAIN, AuthenticationType.VALID, USERNAME},
                    {ExpectedResult.NULL_NULL_NULL, null, DOMAIN, AuthenticationType.INVALID_USERNAME, USERNAME},
                    {ExpectedResult.USER_FALSE_NULL, null, DOMAIN, AuthenticationType.INVALID_PASSWORD, USERNAME},
                    {ExpectedResult.USER_FALSE_NULL, null, DOMAIN, AuthenticationType.EMPTY_PASSWORD, USERNAME},
                    {ExpectedResult.NULL, NullPointerException.class, DOMAIN, AuthenticationType.NULL_PASSWORD,
                            USERNAME},
                    {ExpectedResult.NULL, NullPointerException.class, null, AuthenticationType.VALID, IOT_DEVICE},
                    {ExpectedResult.NULL, NullPointerException.class, DOMAIN, AuthenticationType.NULL, IOT_DEVICE},
                    {ExpectedResult.USER_TRUE_NULL, null, DOMAIN, AuthenticationType.VALID, IOT_DEVICE},
                    {ExpectedResult.NULL_NULL_NULL, null, DOMAIN, AuthenticationType.INVALID_USERNAME, IOT_DEVICE},
                    {ExpectedResult.USER_FALSE_NULL, null, DOMAIN, AuthenticationType.INVALID_PASSWORD, IOT_DEVICE},
                    {ExpectedResult.USER_FALSE_NULL, null, DOMAIN, AuthenticationType.EMPTY_PASSWORD, IOT_DEVICE},
                    {ExpectedResult.NULL, NullPointerException.class, DOMAIN, AuthenticationType.NULL_PASSWORD,
                            IOT_DEVICE},
            });
        }

        @Before
        public void init() throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException,
                BadPaddingException, InvalidKeyException {
            User user = createUser(USERNAME, PASSWORD, CipherAlgorithm.BCRYPT, PASSWORD, false, ACTIVE, 0);
            this.expected = expectedResultToTriple(this.expectedResult, user);
            UserDAO userDAO = createUserDAO(List.of(user));
            AnySearchDAO anySearchDAO = null;
            if (!USERNAME.equals(this.attribute))
                anySearchDAO = createAnySearchDAO(List.of(user), this.attribute);
            RealmDAO realmDAO = createRealmDAO();
            ConfParamOps confParamOps = createConfParamOps(DOMAIN, this.attribute, false);
            this.sut = new AuthDataAccessor(new SecurityProperties(), realmDAO, userDAO, null, anySearchDAO,
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

    public static class AuthDataAccessorAuthenticateMiscTests {

        @Test
        public void testSuspended() throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException,
                BadPaddingException, InvalidKeyException {
            User user = createUser(USERNAME, PASSWORD, CipherAlgorithm.BCRYPT, PASSWORD, true, ACTIVE, 0);
            UserDAO userDAO = createUserDAO(List.of(user));
            RealmDAO realmDAO = createRealmDAO();
            ConfParamOps confParamOps = createConfParamOps(DOMAIN, USERNAME, false);
            Authentication authentication = createAuthentication(AuthenticationType.VALID);
            AuthDataAccessor sut = new AuthDataAccessor(new SecurityProperties(), realmDAO, userDAO, null,
                    null, null, confParamOps, null, null,
                    null, null, null, null);
            Assert.assertThrows(DisabledException.class, () -> sut.authenticate(DOMAIN, authentication));
        }

        @Test
        public void testNullSuspended() throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException,
                BadPaddingException, InvalidKeyException {
            User user = createUser(USERNAME, PASSWORD, CipherAlgorithm.BCRYPT, PASSWORD, null, ACTIVE, 0);
            UserDAO userDAO = createUserDAO(List.of(user));
            RealmDAO realmDAO = createRealmDAO();
            ConfParamOps confParamOps = createConfParamOps(DOMAIN, USERNAME, false);
            Authentication authentication = createAuthentication(AuthenticationType.VALID);
            AuthDataAccessor sut = new AuthDataAccessor(new SecurityProperties(), realmDAO, userDAO, null,
                    null, null, confParamOps, null, null,
                    null, null, null, null);
            Triple<User, Boolean, String> result = sut.authenticate(DOMAIN, authentication);
            Assert.assertEquals(result, Triple.of(user, true, null));
        }

        @Test
        public void testUndefinedStatus() throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException,
                BadPaddingException, InvalidKeyException {
            User user = createUser(USERNAME, PASSWORD, CipherAlgorithm.BCRYPT, PASSWORD, false, USERNAME, 0);
            UserDAO userDAO = createUserDAO(List.of(user));
            RealmDAO realmDAO = createRealmDAO();
            ConfParamOps confParamOps = createConfParamOps(DOMAIN, USERNAME, false);
            Authentication authentication = createAuthentication(AuthenticationType.VALID);
            AuthDataAccessor sut = new AuthDataAccessor(new SecurityProperties(), realmDAO, userDAO, null,
                    null, null, confParamOps, null, null,
                    null, null, null, null);
            Assert.assertThrows(DisabledException.class, () -> sut.authenticate(DOMAIN, authentication));
        }

        @Test
        public void testLogLastLoginDate() throws NoSuchPaddingException, IllegalBlockSizeException,
                NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
            User user = createUser(USERNAME, PASSWORD, CipherAlgorithm.BCRYPT, PASSWORD, false, ACTIVE, 0);
            UserDAO userDAO = createUserDAO(List.of(user));
            RealmDAO realmDAO = createRealmDAO();
            ConfParamOps confParamOps = createConfParamOps(DOMAIN, USERNAME, true);
            Authentication authentication = createAuthentication(AuthenticationType.VALID);
            AuthDataAccessor sut = new AuthDataAccessor(new SecurityProperties(), realmDAO, userDAO, null,
                    null, null, confParamOps, null, null,
                    null, null, null, null);
            sut.authenticate(DOMAIN, authentication);
            Mockito.verify(user, Mockito.times(1))
                    .setLastLoginDate(Mockito.any(OffsetDateTime.class));
            Mockito.verify(userDAO, Mockito.times(1)).save(user);
        }

        @Test
        public void testFailedLogins() throws NoSuchPaddingException, IllegalBlockSizeException,
                NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
            User user = createUser(USERNAME, PASSWORD, CipherAlgorithm.BCRYPT, PASSWORD, false, ACTIVE, 1);
            UserDAO userDAO = createUserDAO(List.of(user));
            RealmDAO realmDAO = createRealmDAO();
            ConfParamOps confParamOps = createConfParamOps(DOMAIN, USERNAME, false);
            Authentication authentication = createAuthentication(AuthenticationType.VALID);
            AuthDataAccessor sut = new AuthDataAccessor(new SecurityProperties(), realmDAO, userDAO, null,
                    null, null, confParamOps, null, null,
                    null, null, null, null);
            sut.authenticate(DOMAIN, authentication);
            Mockito.verify(user, Mockito.times(1)).setFailedLogins(0);
            Mockito.verify(userDAO, Mockito.times(1)).save(user);
        }

        @Test
        public void testIncreaseFailedLogins() throws NoSuchPaddingException, IllegalBlockSizeException,
                NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
            User user = createUser(USERNAME, PASSWORD, CipherAlgorithm.BCRYPT, PASSWORD, false, ACTIVE, 0);
            UserDAO userDAO = createUserDAO(List.of(user));
            RealmDAO realmDAO = createRealmDAO();
            ConfParamOps confParamOps = createConfParamOps(DOMAIN, USERNAME, false);
            Authentication authentication = createAuthentication(AuthenticationType.INVALID_PASSWORD);
            AuthDataAccessor sut = new AuthDataAccessor(new SecurityProperties(), realmDAO, userDAO, null,
                    null, null, confParamOps, null, null,
                    null, null, null, null);
            sut.authenticate(DOMAIN, authentication);
            Mockito.verify(user, Mockito.times(1)).setFailedLogins(1);
            Mockito.verify(userDAO, Mockito.times(1)).save(user);
        }

    }

}
