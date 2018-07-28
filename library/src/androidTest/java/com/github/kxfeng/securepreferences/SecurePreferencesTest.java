package com.github.kxfeng.securepreferences;

import android.content.Context;
import android.content.SharedPreferences;
import android.support.test.InstrumentationRegistry;

import org.junit.Before;
import org.junit.Test;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import javax.crypto.SecretKey;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class SecurePreferencesTest {

    private SharedPreferences preferences;

    private SharedPreferences rawPreferences;

    @Before
    public void before() {
        Context appContext = InstrumentationRegistry.getTargetContext();
        AppKeyStore.init(appContext);
        SecretKey secretKey = AppKeyStore.getOrCreateSecretKey("secure_pres_key", "AES", 256);

        String prefsName = "test_secure_prefs";
        preferences = new SecurePreferences(appContext, prefsName, secretKey);
        rawPreferences = appContext.getSharedPreferences(prefsName, Context.MODE_PRIVATE);
    }

    @Test
    public void testRaw() {
        preferences.edit().clear().apply();

        assertFalse(preferences.contains("key1"));
        assertFalse(rawPreferences.contains("key1"));

        preferences.edit().putString("key1", "value").apply();

        assertTrue(preferences.contains("key1"));
        assertFalse(rawPreferences.contains("key1"));
    }

    @Test
    public void getAll() {
        preferences.edit().clear().apply();
        assertEquals(0, preferences.getAll().size());

        preferences.edit()
            .putString("key_str", "value")
            .putInt("key_int", Integer.MAX_VALUE)
            .apply();

        Map<String, ?> map = preferences.getAll();
        assertEquals(2, map.size());

        assertEquals("value", map.get("key_str"));

        // type will be erased.
        assertEquals(Integer.toString(Integer.MAX_VALUE), map.get("key_int"));
    }

    @Test
    public void getString() {
        preferences.edit().putString("key_str", "value").apply();
        assertEquals("value", preferences.getString("key_str", null));
    }

    @Test
    public void getStringSet() {
        Set<String> set = new HashSet<>();
        set.add("v1");
        set.add("v2");
        preferences.edit().putStringSet("key_set", set).apply();
        Set<String> set2 = preferences.getStringSet("key_set", null);
        assertEquals(set, set2);
    }

    @Test
    public void getInt() {
        preferences.edit().putInt("key_int_max", Integer.MAX_VALUE).apply();
        assertEquals(Integer.MAX_VALUE, preferences.getInt("key_int_max", 0));

        preferences.edit().putInt("key_int_min", Integer.MIN_VALUE).apply();
        assertEquals(Integer.MIN_VALUE, preferences.getInt("key_int_min", 0));
    }

    @Test
    public void getLong() {
        preferences.edit().putLong("key_long_max", Long.MAX_VALUE).apply();
        assertEquals(Long.MAX_VALUE, preferences.getLong("key_long_max", 0));

        preferences.edit().putLong("key_long_min", Long.MIN_VALUE).apply();
        assertEquals(Long.MIN_VALUE, preferences.getLong("key_long_min", 0));
    }

    @Test
    public void getFloat() {
        preferences.edit().putFloat("key_float_max", Float.MAX_VALUE).apply();
        assertEquals(Float.MAX_VALUE, preferences.getFloat("key_float_max", 0), 0);

        preferences.edit().putLong("key_float_min", Long.MIN_VALUE).apply();
        assertEquals(Long.MIN_VALUE, preferences.getFloat("key_float_min", 0), 0);
    }

    @Test
    public void getBoolean() {
        preferences.edit().putBoolean("key_bool", true).apply();
        assertTrue(preferences.getBoolean("key_bool", false));
    }

    @Test
    public void contains() {
        preferences.edit().clear().apply();
        assertFalse(preferences.contains("key"));
        preferences.edit().putString("key", "value").apply();
        assertTrue(preferences.contains("key"));
    }
}