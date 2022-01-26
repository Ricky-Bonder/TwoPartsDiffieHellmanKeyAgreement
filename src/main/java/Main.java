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

    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException, InvalidKeySpecException {
        Alice alice = new Alice();
        Bob bob = new Bob();
        PublicKeyEncOuterClass.PublicKeyEnc alicePubKey = alice.generateAlicePublicKey();
        PublicKeyEncOuterClass.PublicKeyEnc bobPubKey = bob.generateBobPublicKey(alicePubKey);
        System.out.println(bobPubKey);


    }


}
