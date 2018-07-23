package com.github.kxfeng.securepreferences;

import android.support.test.InstrumentationRegistry;

import org.junit.Before;
import org.junit.Test;

import javax.crypto.SecretKey;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotSame;

public class AppKeyStoreTest {

    @Before
    public void before() {
        AppKeyStore.init(InstrumentationRegistry.getTargetContext());
    }

    @Test
    public void getOrCreateSecretKey() {
        SecretKey keyA1 = AppKeyStore.getOrCreateSecretKey("key_test_alias_a", "AES", 256);
        SecretKey keyA2 = AppKeyStore.getOrCreateSecretKey("key_test_alias_a", "AES", 256);
        SecretKey keyB = AppKeyStore.getOrCreateSecretKey("key_test_alias_b", "AES", 128);

        assertNotSame(keyA1, keyA2);
        assertEquals(keyA1, keyA2);
        assertNotEquals(keyA1, keyB);
    }
}