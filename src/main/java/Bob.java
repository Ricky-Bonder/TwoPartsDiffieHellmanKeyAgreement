import com.google.protobuf.ByteString;

import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Collections;

public class Bob {
    static PublicKeyEncOuterClass.PublicKeyEnc bobPubKey;

    public Bob() {

    }

    public PublicKeyEncOuterClass.PublicKeyEnc generateBobPublicKey(PublicKeyEncOuterClass.PublicKeyEnc alicePublicKey) throws InvalidKeySpecException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException {
        //TODO: receive alicePubKeyEnc from Alice ---- deserialize protobuffed message

        byte[] alicePubKeyEnc = alicePublicKey.toByteString().toByteArray();

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
        return bobPubKey;
    }
}
