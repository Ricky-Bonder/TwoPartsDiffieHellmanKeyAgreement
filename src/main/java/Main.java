public class Main {

    public static void main(String[] args) throws Exception {
        Alice alice = new Alice();
        Bob bob = new Bob();

        PublicKeyEncOuterClass.PublicKeyEnc alicePubKey = alice.generateAlicePublicKey();
        PublicKeyEncOuterClass.PublicKeyEnc bobPubKey = bob.generateBobPublicKey(alicePubKey);

        alice.alicePhase2(bobPubKey);
        bob.bobPhase2();

        SharedLength.sharedSecretLength aliceLen = alice.generateSharedSecret();
        bob.generateSharedSecret(aliceLen);
        alice.finalPhase();

        PublicKeyEncOuterClass.PublicKeyEnc encodedParams = bob.bobSendsEncodedParams();
        alice.instantiateAlgoParams(encodedParams);
        PublicKeyEncOuterClass.PublicKeyEnc ciphertextSerialized = bob.sendCiphertext();
        alice.decodeCiphertext(ciphertextSerialized);

    }


}
