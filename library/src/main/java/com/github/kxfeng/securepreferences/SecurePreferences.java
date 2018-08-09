package com.github.kxfeng.securepreferences;

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.SharedPreferences;
import android.provider.Settings;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.text.TextUtils;
import android.util.Base64;
import android.util.Log;

import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

/**
 * A secure SharedPreferences which keys and values are both encrypted by AES secret key.
 */
public class SecurePreferences implements SharedPreferences {
    private static final String CIPHER_GCM_TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int CIPHER_GCM_TAG_BIT_LENGTH = 128;
    private static final int CIPHER_GCM_IV_BIT_SIZE = 96;

    private static final int BASE64_FLAGS = Base64.NO_WRAP;
    private static final Charset CHARSET_UTF8 = Charset.forName("UTF-8");

    private static final String TAG = "SecurePreferences";

    private SharedPreferences mRawPrefs;
    private SecretKey mSecretKey;
    private byte[] mConstantKeyIv;

    /**
     * @param name      Preferences name
     * @param secretKey Secret key for "AES/GCM/NoPadding", key size can be 128, 192 or 256 bits.
     */
    public SecurePreferences(Context context, String name, SecretKey secretKey) {
        mRawPrefs = context.getSharedPreferences(name, Context.MODE_PRIVATE);
        mSecretKey = secretKey;
        mConstantKeyIv = getConstantKeyIv(context);
    }

    /**
     * For type of entries value, only String and Set<String> types can be restored, other types will convert to String.
     */
    @Override
    public Map<String, ?> getAll() {
        Map<String, ?> all = mRawPrefs.getAll();
        Map<String, Object> decryptedAll = new HashMap<>();

        for (Map.Entry<String, ?> entry : all.entrySet()) {
            String decodedKey = decryptKey(entry.getKey());
            Object rawValue = entry.getValue();

            if (rawValue instanceof String) {
                decryptedAll.put(decodedKey, decryptValue((String) rawValue));
            } else if (rawValue instanceof Set) {
                @SuppressWarnings("unchecked")
                Set<String> rawSet = (Set<String>) rawValue;

                Set<String> decryptedSet = new HashSet<>(rawSet.size());
                for (String text : rawSet) {
                    decryptedSet.add(decryptValue(text));
                }
                decryptedAll.put(decodedKey, decryptedSet);
            }
            // other type value it not set by this class, ignore
        }
        return decryptedAll;
    }

    @Nullable
    @Override
    public String getString(String key, @Nullable String defValue) {
        String encrypted = mRawPrefs.getString(encryptKey(key), null);
        String value = decryptValue(encrypted);
        return value == null ? defValue : value;
    }

    @Nullable
    @Override
    public Set<String> getStringSet(String key, @Nullable Set<String> defValues) {
        Set<String> encryptedSet = mRawPrefs.getStringSet(encryptKey(key), null);
        Set<String> values = null;
        if (encryptedSet != null) {
            values = new HashSet<>(encryptedSet.size());

            for (String text : encryptedSet) {
                values.add(decryptValue(text));
            }
        }
        return values == null ? defValues : values;
    }

    @Override
    public int getInt(String key, int defValue) {
        String encrypted = mRawPrefs.getString(encryptKey(key), null);
        String value = decryptValue(encrypted);

        if (value == null) {
            return defValue;
        }
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException ex) {
            return defValue;
        }
    }

    @Override
    public long getLong(String key, long defValue) {
        String encrypted = mRawPrefs.getString(encryptKey(key), null);
        String value = decryptValue(encrypted);

        if (value == null) {
            return defValue;
        }
        try {
            return Long.parseLong(value);
        } catch (NumberFormatException ex) {
            return defValue;
        }
    }

    @Override
    public float getFloat(String key, float defValue) {
        String encrypted = mRawPrefs.getString(encryptKey(key), null);
        String value = decryptValue(encrypted);

        if (value == null) {
            return defValue;
        }
        try {
            return Float.parseFloat(value);
        } catch (NumberFormatException ex) {
            return defValue;
        }
    }

    @Override
    public boolean getBoolean(String key, boolean defValue) {
        String encrypted = mRawPrefs.getString(encryptKey(key), null);
        String value = decryptValue(encrypted);

        if (value == null) {
            return defValue;
        }
        try {
            return Boolean.parseBoolean(value);
        } catch (NumberFormatException ex) {
            return defValue;
        }
    }

    @Override
    public boolean contains(String key) {
        return mRawPrefs.contains(encryptKey(key));
    }

    @Override
    public Editor edit() {
        return new Editor();
    }

    @Override
    public void registerOnSharedPreferenceChangeListener(SharedPreferences.OnSharedPreferenceChangeListener listener) {
        mRawPrefs.registerOnSharedPreferenceChangeListener(listener);
    }

    @Override
    public void unregisterOnSharedPreferenceChangeListener(SharedPreferences.OnSharedPreferenceChangeListener listener) {
        mRawPrefs.unregisterOnSharedPreferenceChangeListener(listener);
    }

    private String encryptKey(@Nullable String text) {
        if (TextUtils.isEmpty(text)) {
            return text;
        }
        try {
            byte[] encrypted = encrypt(text.getBytes(CHARSET_UTF8), mConstantKeyIv);
            return Base64.encodeToString(encrypted, BASE64_FLAGS);
        } catch (GeneralSecurityException ex) {
            Log.w(TAG, "encryptKey error:" + ex);
            return null;
        }
    }

    private String decryptKey(@Nullable String text) {
        if (TextUtils.isEmpty(text)) {
            return text;
        }
        try {
            byte[] decode = Base64.decode(text.getBytes(CHARSET_UTF8), BASE64_FLAGS);
            byte[] decrypted = decrypt(decode, mConstantKeyIv);
            return new String(decrypted, CHARSET_UTF8);
        } catch (GeneralSecurityException | IllegalArgumentException ex) {
            Log.w(TAG, "decryptKey error:" + ex);
            return null;
        }
    }

    @Nullable
    private String encryptValue(@Nullable String text) {
        if (TextUtils.isEmpty(text)) {
            return text;
        }
        try {
            byte[] iv = CryptoUtil.randomBytes(CIPHER_GCM_IV_BIT_SIZE / 8);
            byte[] encrypted = encrypt(text.getBytes(CHARSET_UTF8), iv);
            return new CiphertextIv(encrypted, iv).toString();
        } catch (GeneralSecurityException ex) {
            Log.w(TAG, "encryptValue error:" + ex);
            return null;
        }
    }

    @Nullable
    private String decryptValue(@Nullable String text) {
        if (TextUtils.isEmpty(text)) {
            return text;
        }
        try {
            CiphertextIv ciphertextIv = new CiphertextIv(text);
            byte[] decrypted = decrypt(ciphertextIv.ciphertext, ciphertextIv.iv);
            return new String(decrypted, CHARSET_UTF8);
        } catch (GeneralSecurityException ex) {
            Log.w(TAG, "decryptValue error:" + ex);
            return null;
        }
    }

    private byte[] encrypt(@NonNull byte[] data, @NonNull byte[] iv) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(CIPHER_GCM_TRANSFORMATION);
        AlgorithmParameterSpec gcmParameterSpec = CryptoUtil.getGcmParameterSpec(iv, CIPHER_GCM_TAG_BIT_LENGTH);
        cipher.init(Cipher.ENCRYPT_MODE, mSecretKey, gcmParameterSpec);

        return cipher.doFinal(data);
    }

    private byte[] decrypt(@NonNull byte[] data, @NonNull byte[] iv) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(CIPHER_GCM_TRANSFORMATION);
        AlgorithmParameterSpec gcmParameterSpec = CryptoUtil.getGcmParameterSpec(iv, CIPHER_GCM_TAG_BIT_LENGTH);
        cipher.init(Cipher.DECRYPT_MODE, mSecretKey, gcmParameterSpec);

        return cipher.doFinal(data);
    }

    private byte[] getConstantKeyIv(Context context) {
        @SuppressLint("HardwareIds")
        byte[] ids = Settings.Secure.getString(context.getContentResolver(), Settings.Secure.ANDROID_ID).getBytes(CHARSET_UTF8);
        return Arrays.copyOf(ids, CIPHER_GCM_IV_BIT_SIZE / 8);
    }

    public class Editor implements SharedPreferences.Editor {

        private SharedPreferences.Editor mEditor;

        @SuppressLint("CommitPrefEdits")
        Editor() {
            mEditor = mRawPrefs.edit();
        }

        @Override
        public SharedPreferences.Editor putString(String key, @Nullable String value) {
            mEditor.putString(encryptKey(key), encryptValue(value));
            return this;
        }

        @Override
        public SharedPreferences.Editor putStringSet(String key, @Nullable Set<String> values) {
            Set<String> encryptSet = null;
            if (values != null) {
                encryptSet = new HashSet<>(values.size());

                for (String text : values) {
                    encryptSet.add(encryptValue(text));
                }
            }
            mEditor.putStringSet(encryptKey(key), encryptSet);
            return this;
        }

        @Override
        public SharedPreferences.Editor putInt(String key, int value) {
            mEditor.putString(encryptKey(key), encryptValue(Integer.toString(value)));
            return this;
        }

        @Override
        public SharedPreferences.Editor putLong(String key, long value) {
            mEditor.putString(encryptKey(key), encryptValue(Long.toString(value)));
            return this;
        }

        @Override
        public SharedPreferences.Editor putFloat(String key, float value) {
            mEditor.putString(encryptKey(key), encryptValue(Float.toString(value)));
            return this;
        }

        @Override
        public SharedPreferences.Editor putBoolean(String key, boolean value) {
            mEditor.putString(encryptKey(key), encryptValue(Boolean.toString(value)));
            return this;
        }

        @Override
        public SharedPreferences.Editor remove(String key) {
            mEditor.remove(encryptKey(key));
            return this;
        }

        @Override
        public SharedPreferences.Editor clear() {
            mEditor.clear();
            return this;
        }

        @Override
        public boolean commit() {
            return mEditor.commit();
        }

        @Override
        public void apply() {
            mEditor.apply();
        }
    }
}
