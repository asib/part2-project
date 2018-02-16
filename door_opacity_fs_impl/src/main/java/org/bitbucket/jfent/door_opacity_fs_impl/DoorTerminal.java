package org.bitbucket.jfent.door_opacity_fs_impl;

import static org.bitbucket.jfent.opacity_fs_impl.OpacityForwardSecrecyImplementationApplet.*;
import java.nio.file.Paths;
import java.nio.file.Path;
import java.nio.file.Files;
import java.io.IOException;
import java.io.File;
import java.io.FileInputStream;
import java.io.BufferedInputStream;
import java.io.FileNotFoundException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.KeyPairGenerator;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import javacard.framework.Util;
import org.apache.commons.codec.binary.Hex;
import org.bitbucket.jfent.card_terminal_api.CardTerminalAPI;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;

public class DoorTerminal {
  private static final String DOOR_PRIVATE_KEY_FILENAME = "ecdsa";
  private static final String DOOR_PUBLIC_KEY_FILENAME = "ecdsa_pub";
  private static final String DOOR_SIGNATURE_FILENAME = "ecdsa_sig";
  private static final String KEY_GENERATION_ALGORITHM = "ECDSA";
  private static final String CURVE_NAME = "prime192v1";

  private static final Provider BOUNCY_CASTLE_PROVIDER = new BouncyCastleProvider();

  private static byte[] loadDoorSignature() throws IOException {
    // Get Path object for working directory
    Path wd = Paths.get(".").toAbsolutePath().normalize();
    Path sigFile = wd.resolve(DOOR_SIGNATURE_FILENAME);

    // Read signature from file.
    return Files.readAllBytes(sigFile);
  }

  private static KeyPair loadDoorKeyPair() throws IOException, FileNotFoundException,
          NoSuchAlgorithmException, InvalidKeySpecException {
    // Get Path object for working directory
    Path wd = Paths.get(".").toAbsolutePath().normalize();
    File pubFile = wd.resolve(DOOR_PUBLIC_KEY_FILENAME).toFile();
    File privFile = wd.resolve(DOOR_PRIVATE_KEY_FILENAME).toFile();

    if (!pubFile.exists()) {
      System.out.println("Cannot find public key file named \"ecdsa_pub\" in working directory.");
      return null;
    } else if (!pubFile.isFile()) {
      System.out.println("Cannot read public key - entity in working directory named \"ecdsa_pub\" is not a file.");
      return null;
    } else if (!privFile.exists()) {
      System.out.println("Cannot find private key file named \"ecdsa\" in working directory.");
      return null;
    } else if (!privFile.isFile()) {
      System.out.println("Cannot read private key - entity in working directory named \"ecdsa\" is not a file.");
      return null;
    }

    // Read the keys from file.
    BufferedInputStream pubFIS = null;
    BufferedInputStream privFIS = null;
    byte[] pubBytes;
    byte[] privBytes;

    pubFIS = new BufferedInputStream(new FileInputStream(pubFile));
    privFIS = new BufferedInputStream(new FileInputStream(privFile));

    // Read the length of each file (we encoded the length in the first byte
    // of each file).
    int pubLength = pubFIS.read();
    int privLength = privFIS.read();

    // Create appropriately sized arrays.
    pubBytes = new byte[pubLength];
    privBytes = new byte[privLength];

    // Read the keys into buffers.
    pubFIS.read(pubBytes, 0, pubLength);
    privFIS.read(privBytes, 0, privLength);

    // Now build the key pair.
    KeyFactory kf = KeyFactory.getInstance(KEY_GENERATION_ALGORITHM,
        BOUNCY_CASTLE_PROVIDER);
    PublicKey pubKey = kf.generatePublic(new X509EncodedKeySpec(pubBytes));
    PrivateKey privKey = kf.generatePrivate(new PKCS8EncodedKeySpec(privBytes));
    return (new KeyPair(pubKey, privKey));
  }

  private static KeyPair generateKeyPair() {
    // Now generate the key pair.
    ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec(CURVE_NAME);
    KeyPairGenerator g = null;
    try {
      g = KeyPairGenerator.getInstance(KEY_GENERATION_ALGORITHM,
          BOUNCY_CASTLE_PROVIDER);
      g.initialize(ecSpec, new SecureRandom());
    } catch (Exception e) {
      System.out.println(e.getMessage());
    }

    return g.generateKeyPair();
  }

  public static void main (String[] args) {
    CardTerminalAPI api = null;

    // Load in the signature and permanent key pair from file.
    byte[] doorSignature = null;
    KeyPair doorPermanentKeyPair = null;
    try {
      doorSignature = loadDoorSignature();
      doorPermanentKeyPair = loadDoorKeyPair();
    } catch (Exception e) {
      e.printStackTrace();
    }
    BCECPublicKey doorPermanentKey = (BCECPublicKey)doorPermanentKeyPair.getPublic();
    byte[] doorEncodedPermanentKey = doorPermanentKey.getQ().getEncoded(false);

    // Setup the data array.
    short bOff = 0;
    byte[] initiateAuthData = new byte[SIGNATURE_LENGTH +
      2*(UNCOMPRESSED_W_ENCODED_LENGTH + KEY_PARAM_LENGTH_TAG)];
    System.arraycopy(doorSignature, 0, initiateAuthData, bOff, doorSignature.length);
    bOff += SIGNATURE_LENGTH;
    // Write length tag
    short permKeyLength = (short)doorEncodedPermanentKey.length;
    initiateAuthData[bOff] = (byte)(permKeyLength >> 8);
    initiateAuthData[bOff+1] = (byte)(permKeyLength & 0xff);
    bOff += KEY_PARAM_LENGTH_TAG;
    System.arraycopy(doorEncodedPermanentKey, 0, initiateAuthData, bOff,
        doorEncodedPermanentKey.length);
    bOff += doorEncodedPermanentKey.length;

    short loopInitialBOff = bOff;
    while (true) {
      bOff = loopInitialBOff;
      try {
        // Important to regenerate ephemeral key pair each loop.
        KeyPair doorEphemeralKeyPair = generateKeyPair();
        BCECPublicKey doorEphemeralKey = (BCECPublicKey)doorEphemeralKeyPair.getPublic();

        byte[] doorEncodedEphemeralKey = doorEphemeralKey.getQ().getEncoded(false);
        short ephemKeyLength = (short)doorEncodedEphemeralKey.length;
        initiateAuthData[bOff] = (byte)(ephemKeyLength >> 8);
        initiateAuthData[bOff+1] = (byte)(ephemKeyLength & 0xff);
        bOff += KEY_PARAM_LENGTH_TAG;
        System.arraycopy(doorEncodedEphemeralKey, 0, initiateAuthData, bOff,
            doorEncodedEphemeralKey.length);

        System.out.println(Hex.encodeHexString(initiateAuthData));

        api = new CardTerminalAPI();
        api.selectAuthenticationApplet();
        api.sendInitiateAuthenticationCommand(initiateAuthData);
      } catch (Exception e) {
        e.printStackTrace();
      }

      try {
        System.out.println("Run complete");
        Thread.sleep(1000);
      } catch (InterruptedException e) {}
    }
  }
}
