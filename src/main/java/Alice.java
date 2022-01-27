import com.google.protobuf.ByteString;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Collections;


public class Alice {

    static DHSerializedData.PublicKeyEnc alicePubKeyProtobufSerialized;
    byte[] alicePubKeyEncByteArray;
    ByteString alicePubKeyByteString;

    private KeyAgreement aliceKeyAgree;
    protected byte[] aliceSharedSecret;

    private SecretKeySpec aliceAesKey;
    private Cipher aliceCipher;

    byte[] recovered;

    public Alice() throws NoSuchAlgorithmException {
    }

    public DHSerializedData.PublicKeyEnc generateAlicePublicKey() throws NoSuchAlgorithmException, InvalidKeyException {
        /*
         * Alice creates her own DH key pair with 2048-bit key size
         */
        System.out.println("ALICE: Generate DH keypair ...");
        KeyPairGenerator aliceKpairGen = KeyPairGenerator.getInstance("DH");
        aliceKpairGen.initialize(2048);
        KeyPair aliceKpair = aliceKpairGen.generateKeyPair();

        // Alice creates and initializes her DH KeyAgreement object
        System.out.println("ALICE: Initialization ...");
        aliceKeyAgree = KeyAgreement.getInstance("DH");
        aliceKeyAgree.init(aliceKpair.getPrivate());

        // Alice encodes her public key, and sends it over to Bob.
        alicePubKeyEncByteArray = aliceKpair.getPublic().getEncoded();

        alicePubKeyByteString = ByteString.copyFrom(alicePubKeyEncByteArray);

        //TODO: send alicePubKeyEnc to Bob

        alicePubKeyProtobufSerialized = DHSerializedData.PublicKeyEnc.newBuilder()
                .addAllEncodedPublicKey(Collections.singleton(alicePubKeyByteString)).build();



        return alicePubKeyProtobufSerialized;
    }

    public void alicePhase2(DHSerializedData.PublicKeyEnc bobPubKeyProtobufSerialized) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException {
        //TODO: receive bobPubKeyEnc from Bob

        byte[] bobPubKeyEnc = bobPubKeyProtobufSerialized.getEncodedPublicKeyList().get(0).toByteArray();

        /*
         * Alice uses Bob's public key for the first (and only) phase
         * of her version of the DH
         * protocol.
         * Before she can do so, she has to instantiate a DH public key
         * from Bob's encoded key material.
         */
        KeyFactory aliceKeyFac = KeyFactory.getInstance("DH");
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(bobPubKeyEnc);
        PublicKey bobPubKey = aliceKeyFac.generatePublic(x509KeySpec);
        System.out.println("ALICE: Execute PHASE1 ...");
        aliceKeyAgree.doPhase(bobPubKey, true);

        //*********************************************************


    }

    public void generateSharedSecret() throws Exception {
        /*
         * At this stage, both Alice and Bob have completed the DH key
         * agreement protocol.
         * Both generate the (same) shared secret.
         */
        aliceSharedSecret = aliceKeyAgree.generateSecret();
        int aliceLen = aliceSharedSecret.length;

        System.out.println("Alice secret: " +
                toHexString(aliceSharedSecret));

    }

    public void finalPhase() {
        /*
         * Now let's create a SecretKey object using the shared secret
         * and use it for encryption. First, we generate SecretKeys for the
         * "AES" algorithm (based on the raw shared secret data) and
         * Then we use AES in CBC mode, which requires an initialization
         * vector (IV) parameter. Note that you have to use the same IV
         * for encryption and decryption: If you use a different IV for
         * decryption than you used for encryption, decryption will fail.
         *
         * If you do not specify an IV when you initialize the Cipher
         * object for encryption, the underlying implementation will generate
         * a random one, which you have to retrieve using the
         * javax.crypto.Cipher.getParameters() method, which returns an
         * instance of java.security.AlgorithmParameters. You need to transfer
         * the contents of that object (e.g., in encoded format, obtained via
         * the AlgorithmParameters.getEncoded() method) to the party who will
         * do the decryption. When initializing the Cipher for decryption,
         * the (reinstantiated) AlgorithmParameters object must be explicitly
         * passed to the Cipher.init() method.
         */
        System.out.println("Use shared secret as SecretKey object ...");

        aliceAesKey = new SecretKeySpec(aliceSharedSecret, 0, 16, "AES");
    }

    public void instantiateAlgoParams(DHSerializedData.EncodedParams encodedParams) throws Exception {

        byte[] encodedParamsDeserialized = encodedParams.getEncodedParamsList().get(0).toByteArray();

        /*
         * Alice decrypts, using AES in CBC mode
         */

        // Instantiate AlgorithmParameters object from parameter encoding
        // obtained from Bob
        AlgorithmParameters aesParams = AlgorithmParameters.getInstance("AES");
        aesParams.init(encodedParamsDeserialized);
        aliceCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        aliceCipher.init(Cipher.DECRYPT_MODE, aliceAesKey, aesParams);


    }

    public byte[] decodeCiphertext(DHSerializedData.Ciphertext ciphertextSerialized) throws IllegalBlockSizeException, BadPaddingException {
        byte[] ciphertextDeserialized = ciphertextSerialized.getCiphertextList().get(0).toByteArray();

        recovered = aliceCipher.doFinal(ciphertextDeserialized);

        System.out.println("Decrypted Ciphertext received: "+new String(recovered));

        return recovered;
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
