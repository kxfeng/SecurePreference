package com.github.kxfeng.securepreferences;

import java.security.SecureRandom;

class CryptoUtil {
    private static SecureRandom sSecureRandom = new SecureRandom();

    static byte[] randomBytes(int byteLength) {
        byte[] bytes = new byte[byteLength];
        sSecureRandom.nextBytes(bytes);
        return bytes;
    }
}
