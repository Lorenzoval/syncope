package org.apache.syncope.core.spring.security;

import org.junit.Assert;
import org.junit.Test;

import java.util.ArrayList;

public class DefaultPasswordGeneratorTest {

    @Test
    public void testGenerate() {
        DefaultPasswordGenerator passwordGenerator = new DefaultPasswordGenerator();
        String generatedPassword = passwordGenerator.generate(new ArrayList<>());
        Assert.assertNotNull(generatedPassword);
    }

}
