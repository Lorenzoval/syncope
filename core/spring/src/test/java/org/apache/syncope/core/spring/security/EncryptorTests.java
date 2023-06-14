package org.apache.syncope.core.spring.security;

import org.apache.syncope.common.lib.types.CipherAlgorithm;
import org.apache.syncope.core.spring.ApplicationContextProvider;
import org.apache.syncope.core.spring.security.utils.EncryptorOracle;
import org.junit.*;
import org.junit.experimental.runners.Enclosed;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.springframework.context.ConfigurableApplicationContext;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Collection;
import java.util.Objects;

import static org.mockito.Mockito.*;

@RunWith(Enclosed.class)
public class EncryptorTests {
    private static final String PASSWORD = "password";
    private static final String SHORT_KEY = "passwordpasswor";
    private static final String KEY = "passwordpassword";
    private static final String LONG_KEY = "passwordpasswordd";

    private static Encryptor newEncryptor(String secretKey) throws NoSuchMethodException, InvocationTargetException,
            InstantiationException, IllegalAccessException {
        Constructor<Encryptor> constructor;
        constructor = Encryptor.class.getDeclaredConstructor(String.class);
        constructor.setAccessible(true);
        return constructor.newInstance(secretKey);
    }

    public static abstract class EncryptorTest {
        public static MockedStatic<ApplicationContextProvider> applicationContextProvider;

        @BeforeClass
        public static void setUp() {
            SecurityProperties securityProperties = new SecurityProperties();
            ConfigurableApplicationContext context = Mockito.mock(ConfigurableApplicationContext.class);
            when(context.getBean(SecurityProperties.class)).thenReturn(securityProperties);
            applicationContextProvider = Mockito.mockStatic(ApplicationContextProvider.class);
            applicationContextProvider.when(ApplicationContextProvider::getApplicationContext).thenReturn(context);
        }

        @AfterClass
        public static void tearDown() {
            applicationContextProvider.close();
        }
    }

    @RunWith(Parameterized.class)
    public static class EncryptorEncodeTest extends EncryptorTest {
        Encryptor sut;
        String value;
        CipherAlgorithm cipherAlgorithm;
        String secretKey;

        public EncryptorEncodeTest(String value, CipherAlgorithm cipherAlgorithm, String secretKey) {
            this.value = value;
            this.cipherAlgorithm = cipherAlgorithm;
            this.secretKey = secretKey;
        }

        @Parameterized.Parameters
        public static Collection<Object[]> getParameters() {
            return Arrays.asList(new Object[][]{
                    {null, CipherAlgorithm.SHA1, KEY},
                    {"", CipherAlgorithm.SHA1, KEY},
                    {PASSWORD, CipherAlgorithm.SHA1, KEY},
                    {"", CipherAlgorithm.SHA256, KEY},
                    {PASSWORD, CipherAlgorithm.SHA256, KEY},
                    {"", CipherAlgorithm.SHA512, KEY},
                    {PASSWORD, CipherAlgorithm.SHA512, KEY},
                    {"", CipherAlgorithm.SMD5, KEY},
                    {PASSWORD, CipherAlgorithm.SMD5, KEY},
                    {"", CipherAlgorithm.SSHA1, KEY},
                    {PASSWORD, CipherAlgorithm.SSHA1, KEY},
                    {"", CipherAlgorithm.SSHA256, KEY},
                    {PASSWORD, CipherAlgorithm.SSHA256, KEY},
                    {"", CipherAlgorithm.SSHA512, KEY},
                    {PASSWORD, CipherAlgorithm.SSHA512, KEY},
                    {"", CipherAlgorithm.BCRYPT, KEY},
                    {PASSWORD, CipherAlgorithm.BCRYPT, KEY},
                    {"", CipherAlgorithm.AES, ""},
                    {PASSWORD, CipherAlgorithm.AES, ""},
                    {"", CipherAlgorithm.AES, SHORT_KEY},
                    {PASSWORD, CipherAlgorithm.AES, SHORT_KEY},
                    {"", CipherAlgorithm.AES, KEY},
                    {PASSWORD, CipherAlgorithm.AES, KEY},
                    {"", CipherAlgorithm.AES, LONG_KEY},
                    {PASSWORD, CipherAlgorithm.AES, LONG_KEY},
                    {PASSWORD, null, KEY}
            });
        }

        @Before
        public void init() throws InvocationTargetException, NoSuchMethodException, InstantiationException,
                IllegalAccessException {
            this.sut = newEncryptor(this.secretKey);
        }

        @Test
        public void testEncode() throws UnsupportedEncodingException, NoSuchPaddingException,
                IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException,
                NoSuchFieldException, IllegalAccessException {
            String hash = sut.encode(this.value, this.cipherAlgorithm);
            CipherAlgorithm cipherAlgorithm = Objects.requireNonNullElse(this.cipherAlgorithm, CipherAlgorithm.AES);
            if (this.value != null)
                Assert.assertTrue(EncryptorOracle.encode(sut, this.value, hash, cipherAlgorithm));
            else
                Assert.assertNull(hash);
        }
    }
}
