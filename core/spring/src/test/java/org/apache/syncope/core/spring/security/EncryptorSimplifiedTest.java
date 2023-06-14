package org.apache.syncope.core.spring.security;

import org.apache.syncope.common.lib.types.CipherAlgorithm;
import org.apache.syncope.core.spring.ApplicationContextProvider;
import org.apache.syncope.core.spring.security.utils.EncryptorOracle;
import org.junit.*;
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

import static org.mockito.Mockito.*;

public class EncryptorSimplifiedTest {
    private static final String PASSWORD = "password";
    private static final String SHORT_KEY = "passwordpasswor";
    private static final String KEY = "passwordpassword";
    private static final String LONG_KEY = "passwordpasswordd";
    public static MockedStatic<ApplicationContextProvider> applicationContextProvider;
    Encryptor sut;

    private static Encryptor newEncryptor(String secretKey) throws NoSuchMethodException, InvocationTargetException,
            InstantiationException, IllegalAccessException {
        Constructor<Encryptor> constructor;
        constructor = Encryptor.class.getDeclaredConstructor(String.class);
        constructor.setAccessible(true);
        return constructor.newInstance(secretKey);
    }

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


    @Before
    public void init() throws InvocationTargetException, NoSuchMethodException, InstantiationException,
            IllegalAccessException {
        this.sut = newEncryptor(KEY);
    }

    @Test
    public void testEncode() throws UnsupportedEncodingException, NoSuchPaddingException,
            IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException,
            NoSuchFieldException, IllegalAccessException {
        String hash = sut.encode(PASSWORD, CipherAlgorithm.AES);
        Assert.assertTrue(EncryptorOracle.encode(sut, PASSWORD, hash, CipherAlgorithm.AES));
    }
}
