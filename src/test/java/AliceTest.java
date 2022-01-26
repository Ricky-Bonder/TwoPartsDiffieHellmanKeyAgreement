import com.google.protobuf.ByteString;
import com.google.protobuf.CodedOutputStream;
import com.google.protobuf.InvalidProtocolBufferException;
import org.junit.Test;

import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class AliceTest {



    @Test
    public void testPublicEncryptedKeyIsWellFormed() throws NoSuchAlgorithmException, InvalidKeyException, IOException {
        Alice alice = new Alice();
        alice.generateAlicePublicKey();
        assertArrayEquals(alice.alicePubKeyEncByteArray, alice.alicePubKeyByteString.toByteArray());
        byte[] bytestringToByte = new byte[alice.alicePubKeyEncByteArray.length];
        alice.alicePubKeyByteString.copyTo(bytestringToByte, 0);
        assertArrayEquals(alice.alicePubKeyEncByteArray, bytestringToByte);
        assertEquals(alice.alicePubKeyEncByteArray.length, bytestringToByte.length);
        System.out.println(Arrays.toString(alice.alicePubKeyEncByteArray));
        System.out.println(Arrays.toString(Alice.alicePubKeyProtobufSerialized.getEncodedPublicKeyList().get(0).toByteArray()));
        assertEquals(alice.alicePubKeyEncByteArray, Alice.alicePubKeyProtobufSerialized.getEncodedPublicKeyList().get(0).toByteArray());
    }

    @Test
    public void sharedSecretsAreEqual() throws Exception {
        Alice alice = new Alice();
        Bob bob = new Bob();
        assertArrayEquals(alice.aliceSharedSecret, bob.bobSharedSecret);
    }

    @Test
    public void decipherTextWorks() throws Exception {
//        byte[] recovered = aliceCipher.doFinal(ciphertext);
//        if (!java.util.Arrays.equals(cleartext, recovered))
//            throw new Exception("AES in CBC mode recovered text is " +
//                    "different from cleartext");
//        System.out.println("AES in CBC mode recovered text is same as cleartext");
    }
}
