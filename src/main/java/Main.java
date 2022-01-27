import java.util.Scanner;

public class Main {

    public static void main(String[] args) throws Exception {

        // Setup DH Key Agreement
        Alice alice = new Alice();
        Bob bob = new Bob();

        DHSerializedData.PublicKeyEnc alicePubKey = alice.generateAlicePublicKey();
        DHSerializedData.PublicKeyEnc bobPubKey = bob.generateBobPublicKey(alicePubKey);

        alice.alicePhase2(bobPubKey);
        bob.bobPhase2();

        DHSerializedData.EncodedParams encodedParams = bob.bobSendsEncodedParams();
        alice.instantiateAlgoParams(encodedParams);


        // Read Plaintext from keyboard input
        Scanner keyboard = new Scanner(System.in);
        System.out.println("Enter a PlainText Message:");
        String plaintext = keyboard.nextLine();
        DHSerializedData.Ciphertext ciphertextSerialized = bob.sendCiphertextInputFromKeyboard(plaintext);
        alice.decodeCiphertext(ciphertextSerialized);

    }


}
