package fr.louisbl.cryptoapp.asymmetric;

import android.content.Context;
import android.support.annotation.NonNull;
import android.util.Log;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

public class RsaCryptoTest {
    private static final String TAG = "RsaCryptoTest";

    public static void testRSACrypto(Context context) {

        //////////////////////
        // On both sides
        /////////////////////

        // Generate a new public/private key pair
        KeyPair keyPair = getKeyPair();

        // Store keys in shared preferences
        storeKeys(context, keyPair);


        //////////////////////
        // On sender side
        /////////////////////

        // Retrieve public key of recipient
        // In this example with use our own public key
        PublicKey publicKey = keyPair.getPublic();

        // Encrypt!
        String encrypted = null;
        try {
            encrypted = RsaEcb.encrypt("super secret text", publicKey);
        } catch (GeneralSecurityException | UnsupportedEncodingException e) {
            e.printStackTrace();
        }

        // Uh Oh, something went wrong!
        if (encrypted == null) throw new AssertionError();


        // TODO: send encrypted
        Log.d(TAG, "encrypted: " + encrypted);



        //////////////////////
        // On recipient side
        /////////////////////

        // Retrieve our private key
        PrivateKey privateKey = getPrivateKey(context);

        // Decrypt!
        String decrypted = null;
        try {
            decrypted = RsaEcb.decrypt(encrypted, privateKey);
        } catch (GeneralSecurityException | UnsupportedEncodingException e) {
            e.printStackTrace();
        }

        if (decrypted != null) {
            if (decrypted.equals("super secret text")) {
                // Yay, it works
                Log.d(TAG, "RSACrypto seems to work!");
            } else {
                // Oh no! Decryption failed!
                throw new AssertionError();
            }
        }
    }

    @NonNull
    private static PrivateKey getPrivateKey(Context context) {
        String privateKeyString = context.getSharedPreferences("Crypto", Context.MODE_PRIVATE)
                .getString("private key", "");

        Log.d(TAG, privateKeyString);
        PrivateKey privateKey = null;
        try {
            privateKey = RsaEcb.getRSAPrivateKeyFromString(privateKeyString);
        } catch (GeneralSecurityException | UnsupportedEncodingException e) {
            e.printStackTrace();
        }

        if (privateKey == null) throw new AssertionError();

        Log.d(TAG, privateKey.toString());
        return privateKey;
    }

    private static void storeKeys(Context context, KeyPair keyPair) {
        // Do the same for public key
        try {
            Log.d(TAG, RsaEcb.getPrivateKeyString(keyPair.getPrivate()));
            context.getSharedPreferences("Crypto", Context.MODE_PRIVATE)
                    .edit()
                    .putString("private key", RsaEcb.getPrivateKeyString(keyPair.getPrivate()))
                    .commit();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @NonNull
    private static KeyPair getKeyPair() {
        KeyPair keyPair = null;
        try {
            keyPair = RsaEcb.generateKeys();
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        }

        if (keyPair == null) throw new AssertionError();

        try {
            Log.d(TAG, "public key: " + RsaEcb.getPublicKeyString(keyPair.getPublic()));
            Log.d(TAG, "private key: " + RsaEcb.getPrivateKeyString(keyPair.getPrivate()));
        } catch (IOException e) {
            e.printStackTrace();
        }

        return keyPair;
    }
}