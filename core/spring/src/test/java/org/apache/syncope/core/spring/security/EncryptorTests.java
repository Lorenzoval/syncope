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
            Mockito.when(context.getBean(SecurityProperties.class)).thenReturn(securityProperties);
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

    @RunWith(Parameterized.class)
    public static class EncryptorVerifyTest extends EncryptorTest {
        private final boolean expected;
        private final String value;
        private final CipherAlgorithm cipherAlgorithm;
        private final String encodedValue;
        private Encryptor sut;


        public EncryptorVerifyTest(boolean expected, String value, CipherAlgorithm cipherAlgorithm,
                                   String encodedValue) {
            this.expected = expected;
            this.value = value;
            this.cipherAlgorithm = cipherAlgorithm;
            this.encodedValue = encodedValue;
        }

        @Parameterized.Parameters
        public static Collection<Object[]> getParameters() throws NoSuchPaddingException, IllegalBlockSizeException,
                NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
            return Arrays.asList(new Object[][]{
                    {false, null, CipherAlgorithm.SSHA1, PASSWORD},
                    {true, PASSWORD, null, EncryptorOracle.encode(PASSWORD, CipherAlgorithm.AES, KEY)},
                    {true, "", CipherAlgorithm.SHA1, EncryptorOracle.encode("", CipherAlgorithm.SHA1, KEY)},
                    {false, "", CipherAlgorithm.SHA1, PASSWORD},
                    {true, "", CipherAlgorithm.SHA256, EncryptorOracle.encode("", CipherAlgorithm.SHA256, KEY)},
                    {false, "", CipherAlgorithm.SHA256, PASSWORD},
                    {true, "", CipherAlgorithm.SHA512, EncryptorOracle.encode("", CipherAlgorithm.SHA512, KEY)},
                    {false, "", CipherAlgorithm.SHA512, PASSWORD},
                    {true, "", CipherAlgorithm.AES, EncryptorOracle.encode("", CipherAlgorithm.AES, KEY)},
                    {false, "", CipherAlgorithm.AES, PASSWORD},
                    {true, "", CipherAlgorithm.SMD5, EncryptorOracle.encode("", CipherAlgorithm.SMD5, KEY)},
                    {false, "", CipherAlgorithm.SMD5, PASSWORD},
                    {true, "", CipherAlgorithm.SSHA1, EncryptorOracle.encode("", CipherAlgorithm.SSHA1, KEY)},
                    {false, "", CipherAlgorithm.SSHA1, PASSWORD},
                    {true, "", CipherAlgorithm.SSHA256, EncryptorOracle.encode("", CipherAlgorithm.SSHA256, KEY)},
                    {false, "", CipherAlgorithm.SSHA256, PASSWORD},
                    {true, "", CipherAlgorithm.SSHA512, EncryptorOracle.encode("", CipherAlgorithm.SSHA512, KEY)},
                    {false, "", CipherAlgorithm.SSHA512, PASSWORD},
                    {true, "", CipherAlgorithm.BCRYPT, EncryptorOracle.encode("", CipherAlgorithm.BCRYPT, KEY)},
                    {false, "", CipherAlgorithm.BCRYPT, PASSWORD},
                    {true, PASSWORD, CipherAlgorithm.SHA1, EncryptorOracle.encode(PASSWORD, CipherAlgorithm.SHA1, KEY)},
                    {false, PASSWORD, CipherAlgorithm.SHA1, PASSWORD},
                    {true, PASSWORD, CipherAlgorithm.SHA256, EncryptorOracle.encode(PASSWORD, CipherAlgorithm.SHA256, KEY)},
                    {false, PASSWORD, CipherAlgorithm.SHA256, PASSWORD},
                    {true, PASSWORD, CipherAlgorithm.SHA512, EncryptorOracle.encode(PASSWORD, CipherAlgorithm.SHA512, KEY)},
                    {false, PASSWORD, CipherAlgorithm.SHA512, PASSWORD},
                    {true, PASSWORD, CipherAlgorithm.AES, EncryptorOracle.encode(PASSWORD, CipherAlgorithm.AES, KEY)},
                    {false, PASSWORD, CipherAlgorithm.AES, PASSWORD},
                    {true, PASSWORD, CipherAlgorithm.SMD5, EncryptorOracle.encode(PASSWORD, CipherAlgorithm.SMD5, KEY)},
                    {false, PASSWORD, CipherAlgorithm.SMD5, PASSWORD},
                    {true, PASSWORD, CipherAlgorithm.SSHA1, EncryptorOracle.encode(PASSWORD, CipherAlgorithm.SSHA1, KEY)},
                    {false, PASSWORD, CipherAlgorithm.SSHA1, PASSWORD},
                    {true, PASSWORD, CipherAlgorithm.SSHA256, EncryptorOracle.encode(PASSWORD, CipherAlgorithm.SSHA256, KEY)},
                    {false, PASSWORD, CipherAlgorithm.SSHA256, PASSWORD},
                    {true, PASSWORD, CipherAlgorithm.SSHA512, EncryptorOracle.encode(PASSWORD, CipherAlgorithm.SSHA512, KEY)},
                    {false, PASSWORD, CipherAlgorithm.SSHA512, PASSWORD},
                    {true, PASSWORD, CipherAlgorithm.BCRYPT, EncryptorOracle.encode(PASSWORD, CipherAlgorithm.BCRYPT, KEY)},
                    {false, PASSWORD, CipherAlgorithm.BCRYPT, PASSWORD},
            });
        }

        @Before
        public void init() throws InvocationTargetException, NoSuchMethodException, InstantiationException,
                IllegalAccessException {
            this.sut = newEncryptor(KEY);
        }

        @Test
        public void testVerify() {
            boolean result = this.sut.verify(this.value, this.cipherAlgorithm, this.encodedValue);
            Assert.assertEquals(result, this.expected);
        }

    }

    @RunWith(Parameterized.class)
    public static class EncryptorEncodeDecodeTest extends EncryptorTest {
        private final Class<Throwable> exceptionClass;
        private final String secretKey;
        private final boolean restart;
        private Encryptor sut;


        public EncryptorEncodeDecodeTest(Class<Throwable> exceptionClass, String secretKey, boolean restart) {
            this.exceptionClass = exceptionClass;
            this.secretKey = secretKey;
            this.restart = restart;
        }

        @Parameterized.Parameters
        public static Collection<Object[]> getParameters() {
            return Arrays.asList(new Object[][]{
                    {null, "", false},
                    {BadPaddingException.class, "", true},
                    {null, KEY, false},
                    {null, KEY, true}
            });
        }

        @Before
        public void init() throws InvocationTargetException, NoSuchMethodException, InstantiationException,
                IllegalAccessException {
            this.sut = newEncryptor(secretKey);
        }

        @Test
        public void testEncodeDecode() throws UnsupportedEncodingException, NoSuchPaddingException,
                IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException,
                InvocationTargetException, NoSuchMethodException, InstantiationException, IllegalAccessException {
            String encoded = this.sut.encode(PASSWORD, CipherAlgorithm.AES);
            if (restart)
                this.sut = newEncryptor(this.secretKey);
            if (this.exceptionClass == null)
                Assert.assertEquals(this.sut.decode(encoded, CipherAlgorithm.AES), PASSWORD);
            else
                Assert.assertThrows(this.exceptionClass, () -> this.sut.decode(encoded, CipherAlgorithm.AES));
        }

    }

    @RunWith(Parameterized.class)
    public static class EncryptorSaltTest extends EncryptorTest {
        private final CipherAlgorithm cipherAlgorithm;
        private Encryptor sut;


        public EncryptorSaltTest(CipherAlgorithm cipherAlgorithm) {
            this.cipherAlgorithm = cipherAlgorithm;
        }

        @Parameterized.Parameters
        public static Collection<Object[]> getParameters() {
            return Arrays.asList(new Object[][]{
                    {CipherAlgorithm.SMD5},
                    {CipherAlgorithm.SSHA1},
                    {CipherAlgorithm.SSHA256},
                    {CipherAlgorithm.SSHA512},
                    {CipherAlgorithm.BCRYPT}
            });
        }

        @Before
        public void init() throws InvocationTargetException, NoSuchMethodException, InstantiationException,
                IllegalAccessException {
            this.sut = newEncryptor(KEY);
        }

        @Test
        public void testEncodeDecode() throws UnsupportedEncodingException, NoSuchPaddingException,
                IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
            String encoded = this.sut.encode(PASSWORD, cipherAlgorithm);
            Assert.assertNotEquals(encoded, this.sut.encode(PASSWORD, cipherAlgorithm));
        }

    }

    public static class EncryptorSingletonTest {

        @Test
        public void testSingleton() {
            Encryptor encryptor = Encryptor.getInstance();
            Assert.assertNotNull(encryptor);
            Encryptor sameEncryptor = Encryptor.getInstance();
            Assert.assertSame(encryptor, sameEncryptor);
            Encryptor differentEncryptor = Encryptor.getInstance(KEY);
            Assert.assertNotSame(encryptor, differentEncryptor);
        }

    }

}
