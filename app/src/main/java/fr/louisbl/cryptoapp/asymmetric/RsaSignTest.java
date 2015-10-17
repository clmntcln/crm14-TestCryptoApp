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

public class RsaSignTest {

    private static final String TAG = "RsaSignTest";

    public static void testRSASign(Context context) {

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


        // Retrieve our private key
        PrivateKey privateKey = keyPair.getPrivate();

        // Sign!
        String signature = null;
        try {
            signature = RsaEcb.genSignature("challenge", privateKey);
        } catch (UnsupportedEncodingException | GeneralSecurityException e) {
            e.printStackTrace();
        }

        // Uh Oh, something went wrong!
        if (signature == null) throw new AssertionError();


        // TODO: send signature
        Log.d(TAG, "signature: " + signature);


        //////////////////////
        // On recipient side
        /////////////////////


        // Retrieve public key of sender
        // In this example with use our own public key
        PublicKey publicKey = keyPair.getPublic();

        boolean signatureValid = false;
        try {
            signatureValid = RsaEcb.checkSignature(signature, "challenge", publicKey);
        } catch (UnsupportedEncodingException | GeneralSecurityException e) {
            e.printStackTrace();
        }

        if (!signatureValid) {
            // Oh no! signature is not valid
            throw new AssertionError();
        } else {
            // Yay, it works
            Log.d(TAG, "RSASigning seems to work!");
        }

    }


    private static void storeKeys(Context context, KeyPair keyPair) {
        // Do the same for public key
        try {
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
