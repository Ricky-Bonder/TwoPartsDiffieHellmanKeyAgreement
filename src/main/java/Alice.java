import com.google.protobuf.ByteString;

import javax.crypto.KeyAgreement;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;

public class Alice {

    static PublicKeyEncOuterClass.PublicKeyEnc alicePubKeyProtobufSerialized;
    byte[] alicePubKeyEncByteArray;
    ByteString alicePubKeyByteString;

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
        alicePubKeyEncByteArray = aliceKpair.getPublic().getEncoded();

        alicePubKeyByteString = ByteString.copyFrom(alicePubKeyEncByteArray);

        //TODO: send alicePubKeyEnc to Bob

        alicePubKeyProtobufSerialized = PublicKeyEncOuterClass.PublicKeyEnc.newBuilder()
                .addAllEncodedPublicKey(Collections.singleton(alicePubKeyByteString)).build();

        byte[] bytestringToByte = new byte[alicePubKeyEncByteArray.length];
        alicePubKeyProtobufSerialized.toByteString().copyTo(bytestringToByte, 0);
        System.out.println(alicePubKeyEncByteArray == bytestringToByte);

        return alicePubKeyProtobufSerialized;
    }
}
