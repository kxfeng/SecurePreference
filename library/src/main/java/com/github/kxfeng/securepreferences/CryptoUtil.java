package com.github.kxfeng.securepreferences;

import android.os.Build;

import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;

class CryptoUtil {
    private static SecureRandom sSecureRandom = new SecureRandom();

    static byte[] randomBytes(int byteLength) {
        byte[] bytes = new byte[byteLength];
        sSecureRandom.nextBytes(bytes);
        return bytes;
    }

    static AlgorithmParameterSpec getGcmParameterSpec(byte[] iv, int tagLen) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.LOLLIPOP) {
            // GCMParameterSpec should work since API 19, but in some device it's not supported (e.g. Google's Android 4.4 emulator).
            // We can use IvParameterSpec instead, it will use the default tag size of 128 bits.
            if (tagLen != 128) {
                throw new IllegalArgumentException("Android 4.4 only support 128 bits tag length");
            }
            return new IvParameterSpec(iv);
        }
        return new GCMParameterSpec(tagLen, iv);
    }
}
