package org.apache.syncope.core.spring.security.utils;

import org.apache.syncope.common.lib.types.CipherAlgorithm;
import org.apache.syncope.core.spring.ApplicationContextProvider;
import org.apache.syncope.core.spring.security.Encryptor;
import org.apache.syncope.core.spring.security.SecurityProperties;
import org.jasypt.commons.CommonUtils;
import org.jasypt.digest.StandardStringDigester;
import org.springframework.security.crypto.bcrypt.BCrypt;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class EncryptorOracle {

    private EncryptorOracle() {
    }

    public static boolean encode(Encryptor sut, String value, String generated, CipherAlgorithm cipherAlgorithm)
            throws NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException,
            NoSuchFieldException, IllegalAccessException, InvalidKeyException {
        boolean check;
        switch (cipherAlgorithm) {
            case SHA1, SHA256, SHA512 -> {
                StandardStringDigester digester = new StandardStringDigester();
                digester.setAlgorithm(cipherAlgorithm.getAlgorithm());
                digester.setIterations(1);
                digester.setSaltSizeBytes(0);
                digester.setStringOutputType(CommonUtils.STRING_OUTPUT_TYPE_HEXADECIMAL);
                check = digester.matches(value, generated);
            }
            case SMD5, SSHA1, SSHA512, SSHA256 -> {
                SecurityProperties securityProperties =
                        ApplicationContextProvider.getApplicationContext().getBean(SecurityProperties.class);
                StandardStringDigester digester = new StandardStringDigester();
                digester.setAlgorithm(cipherAlgorithm.getAlgorithm().replaceFirst("S-", ""));
                digester.setIterations(securityProperties.getDigester().getSaltIterations());
                digester.setSaltSizeBytes(securityProperties.getDigester().getSaltSizeBytes());
                digester.setInvertPositionOfPlainSaltInEncryptionResults(
                        securityProperties.getDigester().isInvertPositionOfPlainSaltInEncryptionResults());
                digester.setInvertPositionOfSaltInMessageBeforeDigesting(
                        securityProperties.getDigester().isInvertPositionOfSaltInMessageBeforeDigesting());
                digester.setUseLenientSaltSizeCheck(
                        securityProperties.getDigester().isUseLenientSaltSizeCheck());
                digester.setStringOutputType(CommonUtils.STRING_OUTPUT_TYPE_HEXADECIMAL);
                check = digester.matches(value, generated);
            }
            case BCRYPT -> check = BCrypt.checkpw(value, generated);
            default -> {
                // Case AES
                Field keySpecField = Encryptor.class.getDeclaredField("keySpec");
                keySpecField.setAccessible(true);
                SecretKeySpec keySpec = (SecretKeySpec) keySpecField.get(sut);
                Cipher cipher = Cipher.getInstance(CipherAlgorithm.AES.getAlgorithm());
                cipher.init(Cipher.DECRYPT_MODE, keySpec);
                String decoded = new String(cipher.doFinal(Base64.getDecoder().decode(generated)),
                        StandardCharsets.UTF_8);
                check = decoded.equals(value);
            }
        }
        return check;
    }
}
