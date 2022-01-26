import com.google.protobuf.ByteString;

import javax.crypto.*;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Collections;
import javax.crypto.spec.*;
import javax.crypto.interfaces.*;
import com.sun.crypto.provider.SunJCE;

public class Bob {
    static PublicKeyEncOuterClass.PublicKeyEnc bobPubKeyProtobufSerialized;

    private PublicKey alicePubKey;
    private KeyAgreement bobKeyAgree;
    protected byte[] bobSharedSecret;
    private SecretKeySpec bobAesKey;

    public Bob() {

    }

    public PublicKeyEncOuterClass.PublicKeyEnc generateBobPublicKey(PublicKeyEncOuterClass.PublicKeyEnc alicePublicKey) throws InvalidKeySpecException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException {
        //TODO: receive alicePubKeyEnc from Alice ---- deserialize protobuffed message

        byte[] alicePubKeyEnc = alicePublicKey.getEncodedPublicKeyList().get(0).toByteArray();

        /*
         * Let's turn over to Bob. Bob has received Alice's public key
         * in encoded format.
         * He instantiates a DH public key from the encoded key material.
         */

        KeyFactory bobKeyFac = KeyFactory.getInstance("DH");
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(alicePubKeyEnc);

        alicePubKey = bobKeyFac.generatePublic(x509KeySpec);

        /*
         * Bob gets the DH parameters associated with Alice's public key.
         * He must use the same parameters when he generates his own key
         * pair.
         */
        DHParameterSpec dhParamFromAlicePubKey = ((DHPublicKey)alicePubKey).getParams();

        // Bob creates his own DH key pair
        System.out.println("BOB: Generate DH keypair ...");
        KeyPairGenerator bobKpairGen = KeyPairGenerator.getInstance("DH");
        bobKpairGen.initialize(dhParamFromAlicePubKey);
        KeyPair bobKpair = bobKpairGen.generateKeyPair();

        // Bob creates and initializes his DH KeyAgreement object
        System.out.println("BOB: Initialization ...");
        bobKeyAgree = KeyAgreement.getInstance("DH");
        bobKeyAgree.init(bobKpair.getPrivate());

        // Bob encodes his public key, and sends it over to Alice.
        byte[] bobPubKeyEnc = bobKpair.getPublic().getEncoded();

        ByteString bobKey = ByteString.copyFrom(bobPubKeyEnc);

        //TODO: sent bobPubKeyEnc to Alice

        bobPubKeyProtobufSerialized = PublicKeyEncOuterClass.PublicKeyEnc.newBuilder()
                .addAllEncodedPublicKey(Collections.singleton(bobKey)).build();
        System.out.println(bobKey.toString());

        return bobPubKeyProtobufSerialized;
    }

    public void bobPhase2() throws InvalidKeyException {
        /*
         * Bob uses Alice's public key for the first (and only) phase
         * of his version of the DH
         * protocol.
         */
        System.out.println("BOB: Execute PHASE1 ...");
        bobKeyAgree.doPhase(alicePubKey, true);
    }

    public void generateSharedSecret() throws Exception {
        /*
         * At this stage, both Alice and Bob have completed the DH key
         * agreement protocol.
         * Both generate the (same) shared secret.
         */
        byte[] bobSharedSecret = bobKeyAgree.generateSecret();
        int bobLen;
        bobLen = bobKeyAgree.generateSecret(bobSharedSecret, 0);
        System.out.println("Bob secret: " +
                toHexString(bobSharedSecret));

//        if (!java.util.Arrays.equals(aliceSharedSecret, bobSharedSecret))
//            throw new Exception("Shared secrets differ");
//        System.out.println("Shared secrets are the same");

        bobAesKey = new SecretKeySpec(bobSharedSecret, 0, 16, "AES");

    }

    public void bobEncrypts() throws InvalidKeyException, IOException, NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException {
        /*
         * Bob encrypts, using AES in CBC mode
         */
        Cipher bobCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        bobCipher.init(Cipher.ENCRYPT_MODE, bobAesKey);
        byte[] cleartext = "This is just an example".getBytes();
        byte[] ciphertext = bobCipher.doFinal(cleartext);

        // Retrieve the parameter that was used, and transfer it to Alice in
        // encoded format
        byte[] encodedParams = bobCipher.getParameters().getEncoded();

        //todo: serialize encodedParams and send to alice
    }

    /*
     * Converts a byte to hex digit and writes to the supplied buffer
     */
    private static void byte2hex(byte b, StringBuffer buf) {
        char[] hexChars = { '0', '1', '2', '3', '4', '5', '6', '7', '8',
                '9', 'A', 'B', 'C', 'D', 'E', 'F' };
        int high = ((b & 0xf0) >> 4);
        int low = (b & 0x0f);
        buf.append(hexChars[high]);
        buf.append(hexChars[low]);
    }

    /*
     * Converts a byte array to hex string
     */
    private static String toHexString(byte[] block) {
        StringBuffer buf = new StringBuffer();
        int len = block.length;
        for (int i = 0; i < len; i++) {
            byte2hex(block[i], buf);
            if (i < len-1) {
                buf.append(":");
            }
        }
        return buf.toString();
    }
}
