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
        private final String value;
        private final CipherAlgorithm cipherAlgorithm;
        private final String secretKey;
        private Encryptor sut;

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
                Assert.assertTrue(EncryptorOracle.verify(sut, this.value, hash, cipherAlgorithm));
            else
                Assert.assertNull(hash);
        }
    }

    @RunWith(Parameterized.class)
    public static class EncryptorDecodeTest extends EncryptorTest {
        private static final String AES_KEY_PASSWORD = "cGBbJaKU33UhK4d6b72Y8w==";
        private static final String WRONG_KEY = "aesEncryptionKey";
        private static final String AES_WRONG_KEY_PASSWORD = "xPsi459SpINZAnqIlnbsMw==";
        private static final String ORACLE = "oracle";
        private final String value;
        private final Class<Throwable> exceptionClass;
        private final String encodedValue;
        private final CipherAlgorithm cipherAlgorithm;
        private final String secretKey;
        private Encryptor sut;


        public EncryptorDecodeTest(String value, Class<Throwable> exceptionClass, String encodedValue,
                                   CipherAlgorithm cipherAlgorithm, String secretKey) {
            this.value = value;
            this.exceptionClass = exceptionClass;
            this.encodedValue = encodedValue;
            this.cipherAlgorithm = cipherAlgorithm;
            this.secretKey = secretKey;
        }

        @Parameterized.Parameters
        public static Collection<Object[]> getParameters() {
            return Arrays.asList(new Object[][]{
                    {null, null, null, CipherAlgorithm.AES, KEY},
                    {null, null, AES_KEY_PASSWORD, null, KEY},
                    {null, null, AES_KEY_PASSWORD, CipherAlgorithm.SHA1, KEY},
                    {null, BadPaddingException.class, AES_WRONG_KEY_PASSWORD, CipherAlgorithm.AES, KEY},
                    {"", null, "", CipherAlgorithm.AES, KEY},
                    {null, IllegalBlockSizeException.class, PASSWORD, CipherAlgorithm.AES, ""},
                    {"password", null, ORACLE, CipherAlgorithm.AES, ""},
                    {null, BadPaddingException.class, AES_WRONG_KEY_PASSWORD, CipherAlgorithm.AES, ""},
                    {null, IllegalBlockSizeException.class, PASSWORD, CipherAlgorithm.AES, SHORT_KEY},
                    {"password", null, ORACLE, CipherAlgorithm.AES, SHORT_KEY},
                    {null, BadPaddingException.class, AES_WRONG_KEY_PASSWORD, CipherAlgorithm.AES, SHORT_KEY},
                    {null, IllegalBlockSizeException.class, PASSWORD, CipherAlgorithm.AES, KEY},
                    {"password", null, AES_KEY_PASSWORD, CipherAlgorithm.AES, KEY},
                    {null, BadPaddingException.class, AES_WRONG_KEY_PASSWORD, CipherAlgorithm.AES, KEY},
                    {null, IllegalBlockSizeException.class, PASSWORD, CipherAlgorithm.AES, LONG_KEY},
                    {"password", null, AES_KEY_PASSWORD, CipherAlgorithm.AES, LONG_KEY},
                    {null, BadPaddingException.class, AES_WRONG_KEY_PASSWORD, CipherAlgorithm.AES, LONG_KEY}
            });
        }

        @Before
        public void init() throws InvocationTargetException, NoSuchMethodException, InstantiationException,
                IllegalAccessException {
            this.sut = newEncryptor(this.secretKey);
        }

        @Test
        public void testDecode() throws UnsupportedEncodingException, NoSuchPaddingException,
                IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException,
                NoSuchFieldException, IllegalAccessException {
            if (this.exceptionClass != null) {
                Assert.assertThrows(this.exceptionClass, () -> sut.decode(this.encodedValue, this.cipherAlgorithm));
            } else {
                String value;
                if (ORACLE.equals(this.encodedValue))
                    value = sut.decode(EncryptorOracle.aesOracle(sut, this.value), this.cipherAlgorithm);
                else
                    value = sut.decode(this.encodedValue, this.cipherAlgorithm);
                Assert.assertEquals(value, this.value);
            }
        }

    }
}
