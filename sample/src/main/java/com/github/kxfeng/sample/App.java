package com.github.kxfeng.sample;

import android.app.Application;
import android.content.SharedPreferences;

import com.github.kxfeng.securepreferences.AppKeyStore;
import com.github.kxfeng.securepreferences.SecurePreferences;

import javax.crypto.SecretKey;

public class App extends Application {

    private static App INSTANCE = null;

    private SharedPreferences securePreferences = null;

    public static App getInstance() {
        return INSTANCE;
    }

    @Override
    public void onCreate() {
        super.onCreate();

        INSTANCE = this;

        AppKeyStore.init(this);

        SecretKey aesKey = AppKeyStore.getOrCreateSecretKey("SECURE_PREFERENCES_KEY_ALIAS", "AES", 256);
        securePreferences = new SecurePreferences(this, "app_secure_preferences", aesKey);
    }

    public SharedPreferences getSecurePreferences() {
        return securePreferences;
    }
}
