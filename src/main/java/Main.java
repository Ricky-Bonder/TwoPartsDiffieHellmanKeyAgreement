import com.google.protobuf.ByteString;
import org.apache.commons.io.input.ReversedLinesFileReader;

import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.regex.PatternSyntaxException;


public class Main {

    static PublicKeyEncOuterClass.PublicKeyEnc alicePubKey;
    static PublicKeyEncOuterClass.PublicKeyEnc bobPubKey;

    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException, InvalidKeySpecException {
        alice();


    }

    public static void alice() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException {
        /*
         * Alice creates her own DH key pair with 2048-bit key size
         */
        System.out.println("ALICE: Generate DH keypair ...");
        KeyPairGenerator aliceKpairGen = KeyPairGenerator.getInstance("DH");
        aliceKpairGen.initialize(2048);
        KeyPair aliceKpair = aliceKpairGen.generateKeyPair();

        // Alice creates and initializes her DH KeyAgreement object
        System.out.println("ALICE: Initialization ...");
        KeyAgreement aliceKeyAgree = KeyAgreement.getInstance("DH");
        aliceKeyAgree.init(aliceKpair.getPrivate());

        // Alice encodes her public key, and sends it over to Bob.
        byte[] alicePubKeyEnc = aliceKpair.getPublic().getEncoded();

        ByteString aliceKey = ByteString.copyFrom(alicePubKeyEnc);

        //TODO: send alicePubKeyEnc to Bob

        alicePubKey = PublicKeyEncOuterClass.PublicKeyEnc.newBuilder()
                .addAllEncodedPublicKey(Collections.singleton(aliceKey)).build();
        System.out.println(alicePubKey.toString());


        bob(alicePubKey);
    }

    public static void bob(PublicKeyEncOuterClass.PublicKeyEnc alicePubKeyEncByteString) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, InvalidKeySpecException {
        //TODO: receive alicePubKeyEnc from Alice ---- deserialize protobuffed message

        byte[] alicePubKeyEnc = alicePubKeyEncByteString.toByteArray();

        /*
         * Let's turn over to Bob. Bob has received Alice's public key
         * in encoded format.
         * He instantiates a DH public key from the encoded key material.
         */

        //PROBLEMA: InvalidKeySpecException: Inappropriate key specification
        // causato dalla riconversione di alicePubKeyEncByteString a byte array, da ByteString.
        // La chiave cifrata si può convertire in ByteString? Se sì qual è il problema di conversione qui?
        // se no vuol dire che devo riuscire ad inviare il byte[] così com'è via protobuf, ma non sono riuscito a trovare
        // una struttura dati che lo potesse contere.
        KeyFactory bobKeyFac = KeyFactory.getInstance("DH");
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(alicePubKeyEnc);

        PublicKey alicePubKey = bobKeyFac.generatePublic(x509KeySpec);

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
        KeyAgreement bobKeyAgree = KeyAgreement.getInstance("DH");
        bobKeyAgree.init(bobKpair.getPrivate());

        // Bob encodes his public key, and sends it over to Alice.
        byte[] bobPubKeyEnc = bobKpair.getPublic().getEncoded();

        ByteString bobKey = ByteString.copyFrom(bobPubKeyEnc);

        //TODO: sent bobPubKeyEnc to Alice

        bobPubKey = PublicKeyEncOuterClass.PublicKeyEnc.newBuilder()
                .addAllEncodedPublicKey(Collections.singleton(bobKey)).build();
        System.out.println(bobKey.toString());
    }

}
