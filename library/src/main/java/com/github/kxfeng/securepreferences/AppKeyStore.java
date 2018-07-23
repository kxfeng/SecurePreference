package com.github.kxfeng.securepreferences;

import android.annotation.SuppressLint;
import android.annotation.TargetApi;
import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.provider.Settings;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.support.annotation.NonNull;
import android.text.TextUtils;
import android.util.Base64;
import android.util.Log;

import java.io.IOException;
import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AppKeyStore {

    private static Context sApplicationContext;
    private static String sSystemKeyStoreMasterKeyAlias;
    private static String sAppKeyStorePreferencesName;

    private static final String ANDROID_KEY_STORE = "AndroidKeyStore";
    private static final String KEY_COMPATIBLE = "compatible";

    private static final int MASTER_KEY_BIT_SIZE = 256;
    private static final String MASTER_KEY_ALGORITHM = "AES";
    private static final String MASTER_CIPHER_GCM_TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int MASTER_CIPHER_GCM_TAG_BIT_LENGTH = 128;
    private static final int MASTER_CIPHER_GCM_IV_BIT_SIZE = 96;

    private static final Charset CHARSET_UTF8 = Charset.forName("UTF-8");

    private static final String TAG = "AppKeyStore";

    private static boolean sDebugLog = false;

    public static void init(@NonNull Context context) {
        init(context, "app_key_store_master_key", "app_key_store");
    }

    public static void init(@NonNull Context context, @NonNull String systemKeyStoreMasterKeyAlias,
                            @NonNull String appKeyStorePreferenceName) {
        sApplicationContext = context.getApplicationContext();
        sSystemKeyStoreMasterKeyAlias = systemKeyStoreMasterKeyAlias;
        sAppKeyStorePreferencesName = appKeyStorePreferenceName;
    }

    public static void setDebugLog(boolean debugLog) {
        sDebugLog = debugLog;
    }

    /**
     * Get or create a secret key by key alias. If the key not exist, create a new one, otherwise recover
     * the key (from preference). If recover failed, create a new key instead.
     *
     * @throws KeyStoreUnavailableException if failed to encrypt key alias or secrete key for persistence usage.
     *                                      The AppKeyStore is almost unavailable in this case.
     */
    public static SecretKey getOrCreateSecretKey(@NonNull String keyAlias, @NonNull String algorithm, int keySizeInBits) {
        checkInit();

        if (keySizeInBits % 8 != 0) {
            throw new IllegalArgumentException("key bit size must be multiple of 8");
        }

        SecretKey masterKey = getMasterKey();

        SharedPreferences preferences = getKeyStorePreferences();
        String encryptKeyAlias;

        try {
            encryptKeyAlias = encryptKeyAlias(masterKey, keyAlias);
        } catch (GeneralSecurityException ex) {
            throw new KeyStoreUnavailableException("Failed to encrypt key alias, so unable to recover secret key from storage", ex);
        }

        String keyData = preferences.getString(encryptKeyAlias, null);

        if (!TextUtils.isEmpty(keyData)) {
            try {
                return decryptSecretKey(masterKey, keyData, algorithm);
            } catch (GeneralSecurityException ex) {
                Log.w(TAG, "decrypt key fail, create new key instead: " + keyAlias);
            }
        }

        byte[] randomBytes = CryptoUtil.randomBytes(keySizeInBits / 8);
        SecretKey secretKey = new SecretKeySpec(randomBytes, algorithm);

        try {
            String encrypted = encryptSecretKey(masterKey, secretKey);
            preferences.edit().putString(encryptKeyAlias, encrypted).apply();
            return secretKey;
        } catch (GeneralSecurityException ex) {
            throw new KeyStoreUnavailableException("Failed to encrypt the created secret key, so unable to persist it to storage", ex);
        }
    }

    @TargetApi(Build.VERSION_CODES.GINGERBREAD_MR1)
    private static SecretKey getMasterKey() {
        SharedPreferences preferences = getKeyStorePreferences();

        if (preferences.getBoolean(KEY_COMPATIBLE, false)) {
            if (sDebugLog) {
                Log.d(TAG, "get MasterKey compatible flag");
            }
            return getMasterKeyCompat();
        }

        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
            if (sDebugLog) {
                Log.d(TAG, "get MasterKey below Marshmallow");
            }
            preferences.edit().putBoolean(KEY_COMPATIBLE, true).apply();
            return getMasterKeyCompat();
        }

        try {
            return getMasterKeyByKeyStore(sSystemKeyStoreMasterKeyAlias);
        } catch (GeneralSecurityException | IOException ex) {
            Log.w(TAG, "get MasterKey in keystore error, fallback to compat: " + ex.toString());
            preferences.edit().putBoolean(KEY_COMPATIBLE, true).apply();
            return getMasterKeyCompat();
        }
    }

    @TargetApi(Build.VERSION_CODES.M)
    private static SecretKey getMasterKeyByKeyStore(String masterKeyAlias) throws GeneralSecurityException, IOException {
        KeyStore keyStore = KeyStore.getInstance(ANDROID_KEY_STORE);
        keyStore.load(null);

        if (keyStore.containsAlias(masterKeyAlias)) {
            KeyStore.Entry entry = keyStore.getEntry(masterKeyAlias, null);

            if (entry instanceof KeyStore.SecretKeyEntry) {
                if (sDebugLog) {
                    Log.d(TAG, "master key already exist");
                }
                return ((KeyStore.SecretKeyEntry) entry).getSecretKey();
            }

            keyStore.deleteEntry(masterKeyAlias);
            Log.w(TAG, "master key type not match, delete it to recreate");
        }

        if (sDebugLog) {
            Log.d(TAG, "create master key in KeyStore");
        }
        KeyGenerator keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEY_STORE);
        KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(masterKeyAlias, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(MASTER_KEY_BIT_SIZE)
            .setRandomizedEncryptionRequired(false)     // need to init GCMParameterSpec
            .build();
        keyGenerator.init(spec);
        return keyGenerator.generateKey();
    }

    /**
     * In compat mode, use android_id to generate the master secret key.
     * It's not safe, but there's no way to keep safe when system keystore is not available.
     */
    private static SecretKey getMasterKeyCompat() {
        @SuppressLint("HardwareIds")
        byte[] ids = Settings.Secure.getString(sApplicationContext.getContentResolver(),
            Settings.Secure.ANDROID_ID).getBytes(CHARSET_UTF8);

        byte[] key = Arrays.copyOf(ids, MASTER_KEY_BIT_SIZE / 8);
        return new SecretKeySpec(key, MASTER_KEY_ALGORITHM);
    }

    private static String encryptSecretKey(SecretKey masterKey, SecretKey key) throws GeneralSecurityException {
        byte[] iv = CryptoUtil.randomBytes(MASTER_CIPHER_GCM_IV_BIT_SIZE / 8);
        byte[] encrypted = encrypt(masterKey, key.getEncoded(), iv);
        return new CiphertextIv(encrypted, iv).toString();
    }

    private static SecretKey decryptSecretKey(SecretKey masterKey, String encryptedText, @NonNull String algorithm) throws GeneralSecurityException {
        CiphertextIv ciphertextIv = new CiphertextIv(encryptedText);
        byte[] decrypted = decrypt(masterKey, ciphertextIv.ciphertext, ciphertextIv.iv);
        return new SecretKeySpec(decrypted, algorithm);
    }

    private static String encryptKeyAlias(SecretKey masterKey, @NonNull String keyAlias) throws GeneralSecurityException {
        byte[] encrypted = encrypt(masterKey, keyAlias.getBytes(CHARSET_UTF8), getConstantKeyAliasIv());
        return Base64.encodeToString(encrypted, Base64.NO_WRAP);
    }

    private static String decryptKeyAlias(SecretKey masterKey, @NonNull String encryptedText) throws GeneralSecurityException {
        byte[] decoded;
        try {
            decoded = Base64.decode(encryptedText.getBytes(CHARSET_UTF8), Base64.NO_WRAP);
        } catch (IllegalArgumentException ex) {
            throw new GeneralSecurityException("Base64 decode error", ex);
        }
        byte[] decrypted = decrypt(masterKey, decoded, getConstantKeyAliasIv());
        return new String(decrypted, CHARSET_UTF8);
    }

    private static byte[] encrypt(SecretKey key, byte[] data, byte[] iv) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(MASTER_CIPHER_GCM_TRANSFORMATION);
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(MASTER_CIPHER_GCM_TAG_BIT_LENGTH, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, gcmParameterSpec);

        return cipher.doFinal(data);
    }

    private static byte[] decrypt(SecretKey key, byte[] data, byte[] iv) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(MASTER_CIPHER_GCM_TRANSFORMATION);
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(MASTER_CIPHER_GCM_TAG_BIT_LENGTH, iv);
        cipher.init(Cipher.DECRYPT_MODE, key, gcmParameterSpec);

        return cipher.doFinal(data);
    }

    private static void checkInit() {
        if (sApplicationContext == null) {
            throw new IllegalStateException("Must call AppKeyStore.init() before any operation");
        }
    }

    private static byte[] getConstantKeyAliasIv() {
        @SuppressLint("HardwareIds")
        byte[] ids = Settings.Secure.getString(sApplicationContext.getContentResolver(), Settings.Secure.ANDROID_ID).getBytes(CHARSET_UTF8);
        return Arrays.copyOf(ids, MASTER_CIPHER_GCM_IV_BIT_SIZE / 8);
    }

    private static SharedPreferences getKeyStorePreferences() {
        return sApplicationContext.getApplicationContext().getSharedPreferences(sAppKeyStorePreferencesName, Context.MODE_PRIVATE);
    }

    public static class KeyStoreUnavailableException extends RuntimeException {
        KeyStoreUnavailableException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
