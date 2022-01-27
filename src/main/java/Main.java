public class Main {

    public static void main(String[] args) throws Exception {
        Alice alice = new Alice();
        Bob bob = new Bob();

        DHSerializedData.PublicKeyEnc alicePubKey = alice.generateAlicePublicKey();
        DHSerializedData.PublicKeyEnc bobPubKey = bob.generateBobPublicKey(alicePubKey);

        alice.alicePhase2(bobPubKey);
        bob.bobPhase2();

        DHSerializedData.EncodedParams encodedParams = bob.bobSendsEncodedParams();
        alice.instantiateAlgoParams(encodedParams);
        DHSerializedData.Ciphertext ciphertextSerialized = bob.sendCiphertext();
        alice.decodeCiphertext(ciphertextSerialized);

    }


}
