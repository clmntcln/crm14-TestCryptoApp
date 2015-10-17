package fr.louisbl.cryptoapp.symmetric;

import android.support.annotation.NonNull;
import android.util.Log;

import com.tozny.crypto.android.AesCbcWithIntegrity;

import org.spongycastle.util.encoders.Base64;

import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;

public class AesCryptoTest {
    private static final String TAG = "AesCryptoTest";

    public static void testAesCbcWithIntegrity() {

        //////////////////////
        // On sender side
        /////////////////////

        // Generate salt
        byte[] salt = getSalt();

        //  Generate secret keys
        AesCbcWithIntegrity.SecretKeys keys = getSecretKeys("very long passphrase", salt);

        // Encrypt!
        // Compute "encrypted" text, composed of
        // cipherText: encrypted content
        // Iv: initialization vector
        // Mac: hash to check integrity of cipherText
        AesCbcWithIntegrity.CipherTextIvMac encrypted = null;
        try {
            encrypted = AesCbcWithIntegrity.encrypt("super secret text", keys);
        } catch (UnsupportedEncodingException | GeneralSecurityException e) {
            e.printStackTrace();
        }

        // Uh Oh, something went wrong!
        if (encrypted == null) throw new AssertionError();


        // TODO: send encrypted and salt encoded with Base64
        String encryptedString = encrypted.toString();
        String saltString = Base64.toBase64String(salt);

        Log.d(TAG, "encrypted: " + encryptedString);



        ////////////////////////
        // On recipient side
        ////////////////////////

        // Regenerate secret keys from password and salt
        AesCbcWithIntegrity.SecretKeys keysDecrypt;
        keysDecrypt = getSecretKeys("very long passphrase", Base64.decode(saltString));

        // Recreate CipherTextIvMac
        AesCbcWithIntegrity.CipherTextIvMac dataToDecrypt = new AesCbcWithIntegrity.CipherTextIvMac(encryptedString);

        // Decrypt!
        String decrypted = null;
        try {
            decrypted = AesCbcWithIntegrity.decryptString(dataToDecrypt, keysDecrypt);
        } catch (UnsupportedEncodingException | GeneralSecurityException e) {
            e.printStackTrace();
        }

        if (decrypted != null) {
            if (decrypted.equals("super secret text")) {
                // Yay, it works
                Log.d(TAG, "AESCrypto seems to work!");
            } else {
                // Oh no! Decryption failed!
                throw new AssertionError();
            }
        }
    }

    private static byte[] getSalt() {
        byte[] salt = new byte[0];

        // Generate random 128bits salt
        try {
            salt = AesCbcWithIntegrity.generateSalt();
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        }

        // salt generation failed
        if (salt.length <= 0) throw new AssertionError();

        Log.d(TAG, "salt: " + Base64.toBase64String(salt));
        return salt;
    }

    @NonNull
    private static AesCbcWithIntegrity.SecretKeys getSecretKeys(String password, byte[] salt) {
        // The secret keys
        AesCbcWithIntegrity.SecretKeys keys = null;

        // Generate secret keys from password and salt
        // password must be kept secret
        // salt can be stored with each message
        try {
            keys = AesCbcWithIntegrity.generateKeyFromPassword(password, salt);
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        }

        // keys generation failed
        if (keys == null) throw new AssertionError();

        // Output "confidentialityKey:integrityKey"
        Log.d(TAG, "secret keys: " + keys.toString());

        return keys;
    }

}