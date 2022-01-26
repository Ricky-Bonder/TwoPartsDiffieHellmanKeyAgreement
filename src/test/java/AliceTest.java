import org.junit.Test;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

public class AliceTest {



    @Test
    public void testPublicEncryptedKeyIsWellFormed() throws NoSuchAlgorithmException, InvalidKeyException {
        Alice alice = new Alice();
        alice.generateAlicePublicKey();
        assertArrayEquals(alice.alicePubKeyEncByteArray, alice.alicePubKeyByteString.toByteArray());
        byte[] bytestringToByte = new byte[alice.alicePubKeyEncByteArray.length];
        alice.alicePubKeyByteString.copyTo(bytestringToByte, 0);
        assertArrayEquals(alice.alicePubKeyEncByteArray, bytestringToByte);
    }
}
