package com.github.kxfeng.securepreferences;

import android.support.annotation.NonNull;
import android.util.Base64;

import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;

class CiphertextIv {

    private static final String DELIMITER = ":";
    private static final int BASE64_FLAGS = Base64.NO_WRAP;

    final byte[] ciphertext;
    final byte[] iv;

    CiphertextIv(byte[] ciphertext, byte[] iv) {
        this.ciphertext = new byte[ciphertext.length];
        System.arraycopy(ciphertext, 0, this.ciphertext, 0, ciphertext.length);
        this.iv = new byte[iv.length];
        System.arraycopy(iv, 0, this.iv, 0, iv.length);
    }

    /**
     * Construct from a encodedText
     *
     * @param encodedText in the format: base64(ciphertext):base64(iv)
     * @throws IllegalCiphertextIvException format not valid
     */
    CiphertextIv(@NonNull String encodedText) throws IllegalCiphertextIvException {
        String[] parts = encodedText.split(DELIMITER);

        if (parts.length != 2) {
            throw new IllegalCiphertextIvException("CiphertextIv not this format: cipher:iv");
        }

        try {
            ciphertext = Base64.decode(parts[0].getBytes("UTF-8"), BASE64_FLAGS);
            iv = Base64.decode(parts[1].getBytes("UTF-8"), BASE64_FLAGS);
        } catch (IllegalArgumentException ex) {
            throw new IllegalCiphertextIvException(ex);
        } catch (UnsupportedEncodingException ex) {
            throw new RuntimeException(ex);
        }
    }

    /**
     * Encode ciphertext and iv
     *
     * @return base64(ciphertext):base64(iv)
     */
    @Override
    public String toString() {
        return Base64.encodeToString(ciphertext, BASE64_FLAGS) + DELIMITER
            + Base64.encodeToString(iv, BASE64_FLAGS);
    }

    private static class IllegalCiphertextIvException extends GeneralSecurityException {
        IllegalCiphertextIvException(String msg) {
            super(msg);
        }

        IllegalCiphertextIvException(Throwable cause) {
            super(cause);
        }
    }
}
