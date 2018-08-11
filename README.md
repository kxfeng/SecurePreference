# secure-preferences
An Android secure SharedPreferences which use AES secret key to encrypt and decrypt key-values. You can use the AppKeyStore class to generate secret keys for app usage, which are protected by Android keystore system.

# Download

```groovy
repositories {
    jcenter()
}
dependencies {
    implementation 'com.github.kxfeng:secure-preferences:1.0.0'
}
```

# Usage

Generate secret key
```java
AppKeyStore.init(this);
SecretKey aesKey = AppKeyStore.getOrCreateSecretKey("SECURE_PREFERENCES_KEY_ALIAS", "AES", 256);
```

Create SecurePreferences
```java
SharedPreferences preferences = new SecurePreferences(this, "app_secure_preferences", aesKey);
```
