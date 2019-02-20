# SecurePreferences
An Android secure SharedPreferences which use AES secret key to encrypt and decrypt key-values. You can use the AppKeyStore class to generate secret keys for app usage, which are protected by Android keystore system.

## Download

```groovy
repositories {
    jcenter()
}
dependencies {
    implementation 'com.github.kxfeng:secure-preferences:1.0.0'
}
```

## Usage

Generate secret key
```java
AppKeyStore.init(this);
SecretKey aesKey = AppKeyStore.getOrCreateSecretKey("SECURE_PREFERENCES_KEY_ALIAS", "AES", 256);
```

Create SecurePreferences
```java
SharedPreferences preferences = new SecurePreferences(this, "app_secure_preferences", aesKey);
```

## License

    Copyright 2019 kxfeng

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
