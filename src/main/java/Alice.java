import com.google.protobuf.ByteString;

import javax.crypto.KeyAgreement;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;

public class Alice {
    static PublicKeyEncOuterClass.PublicKeyEnc alicePubKey;

    public Alice() throws NoSuchAlgorithmException {


    }

    public PublicKeyEncOuterClass.PublicKeyEnc generateAlicePublicKey() throws NoSuchAlgorithmException, InvalidKeyException {
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
        return alicePubKey;
    }
}
