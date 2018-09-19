package yap.test.keystore;

import android.content.Context;
import android.security.KeyPairGeneratorSpec;
import android.security.KeyChain;
import android.system.Os;
import android.util.Base64;
import android.util.Log;

import java.io.IOException;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyFactory;
import android.security.keystore.*;

import java.security.NoSuchProviderException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Calendar;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.GregorianCalendar;
import java.util.concurrent.ExecutionException;
import java.security.cert.Certificate;

import javax.net.ssl.KeyManager;
import javax.security.auth.x500.X500Principal;

import static yap.test.keystore.Common.NEW_LINE;
import static yap.test.keystore.Common.TAG;

public class KeyGen {

    /** The debug flag. */
    private static final boolean DEBUG = true;

    /** The key type. RSA. */
    public static final String TYPE_RSA = "RSA";

    /** The key type. DSA. */
    public static final String TYPE_DSA = "DSA";

    /** The key type. BKS. */
    public static final String TYPE_BKS = "BKS";

    /** The name of default Android key store provider. */
    public static final String ANDROID_KEYSTORE_PROVIDER = "AndroidKeyStore";

    /** The default key alias. */
    public static final String KEY_ALIAS = "yap";

    /**
     * Generates RSA key. No using Android keystore.
     * */
    public static KeyPair genSimpleRsa() {
        final KeyPairGenerator gen;
        try {
            gen = KeyPairGenerator.getInstance(TYPE_RSA);
            KeyPair pair = gen.genKeyPair();
            logKeyPair(pair);
            return pair;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static KeyPair genRsaKeyWithKeystore(Context context) throws NoSuchAlgorithmException, NoSuchProviderException {

        // Calculate dates
        Calendar start = new GregorianCalendar();
        Calendar end = new GregorianCalendar();
        end.add(Calendar.YEAR, 1);

        // Key params
        final AlgorithmParameterSpec spec;
        spec = new KeyPairGeneratorSpec.Builder(context)
                .setAlias(KEY_ALIAS)
                .setSubject(new X500Principal("CN=" + KEY_ALIAS))
                .setSerialNumber(BigInteger.valueOf(1337))
                .setStartDate(start.getTime())
                .setEndDate(end.getTime())
                .build();

        // Generator

        final KeyPairGenerator generator;
        try {
            generator = KeyPairGenerator.getInstance(TYPE_RSA, ANDROID_KEYSTORE_PROVIDER);
            generator.initialize(spec);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }

        // Generate KeyPair
        final KeyPair pair = generator.generateKeyPair();

        PrivateKey key  = pair.getPrivate();
        KeyFactory factory = KeyFactory.getInstance(key.getAlgorithm(),  ANDROID_KEYSTORE_PROVIDER);
        KeyInfo keyInfo;
        try {
            keyInfo = factory.getKeySpec(key, KeyInfo.class);
            Boolean tmp = keyInfo.isInsideSecureHardware();
            Log.w("isInsideSecureHardware", tmp.toString());
        } catch (InvalidKeySpecException e) {
            //
        }
        logKeyPair(pair);
        KeyStore ks = null;
        try {
            ks = KeyStore.getInstance("AndroidKeyStore");
            ks.load(null);

            Certificate cert = ks.getCertificate(KEY_ALIAS);
            Certificate[] cert_chain = ks.getCertificateChain(KEY_ALIAS);

            String res = Base64.encodeToString(cert.getEncoded(), 0);
            PrintWriter file  = new PrintWriter("storage/self/primary/Download/cert_test");
            file.write("-----BEGIN CERTIFICATE-----\n");
            file.write(res);
            file.write("-----END CERTIFICATE-----\n");
            file.close();
            Log.w("sadf", "dfs");
        } catch (Exception e) {
            //
        }
        return pair;
    }


    public static String checkRsaKeyWithKeystore() {
        KeyStore ks = null;
        final StringBuilder builder = new StringBuilder();
        try {
            ks = KeyStore.getInstance("AndroidKeyStore");
            ks.load(null);

            // Check Alias
            Enumeration<String> aliases = ks.aliases();
            if (ks.containsAlias(KEY_ALIAS)) {
                builder.append("Key Alias - OK").append("\n");
            } else {
                builder.append("Key Alias - Not Found");
                return builder.toString();
            }

            // Check Entry
            final KeyStore.Entry entry = ks.getEntry(KEY_ALIAS, null);
            if (entry == null) {
                builder.append("Key Entry - NULL");
                return builder.toString();
            }
            if (!(entry instanceof KeyStore.PrivateKeyEntry)) {
                builder.append("Key Entry - Not an instance of a PrivateKeyEntry");
                return builder.toString();
            }

            builder.append("Chain boundness:").append(NEW_LINE);

            for (String algo: Arrays.asList("RSA", "EC", "AES")) {
                builder.append("  Algorithm: ").append(algo).append(", isBound:").append(KeyChain.isBoundKeyAlgorithm(algo)).append(NEW_LINE);
            }

            builder.append("Key Entry - OK").append(NEW_LINE).append(entry.toString());

            return builder.toString();
        } catch (Exception e) {
            builder.append(e.getMessage());
            return builder.toString();
        }
    }

    /**
     * Logging information about specified {@link KeyPair}.
     * */
    private static void logKeyPair(KeyPair pair) {
        if (!DEBUG) return;
        if (pair != null) {
            Log.d(TAG, pair.getPrivate().toString());
        } else {
            Log.w(TAG, "KeyPair is null");
        }
    }
}
