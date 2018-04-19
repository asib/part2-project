package org.bitbucket.jfent.card_terminal;

import static org.bitbucket.jfent.opacity_fs_impl.OpacityForwardSecrecyImplementationApplet.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.nio.file.Path;
import java.nio.file.Files;
import java.nio.ByteBuffer;
import java.io.IOException;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.util.Arrays;
import java.math.BigInteger;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.KeyPairGenerator;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.KeyFactory;
import java.security.Signature;
import java.security.SignatureException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import javax.smartcardio.CardException;
import javacard.framework.Util;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.DecoderException;
import org.bitbucket.jfent.opacity_fs_impl.Utils;
import org.bitbucket.jfent.card_terminal_api.CardTerminalAPI;
import org.bitbucket.jfent.card_terminal_api.CardCommunicationException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Integer;

public class CardTerminal {
  private static final String PROGRAM_NAME = "card_terminal";
  private static final String HELP_HEADER = "Provision and reprogram smart cards.";
  private static final String TERMINAL_PRIVATE_KEY_FILENAME = "ecdsa";
  private static final String TERMINAL_PUBLIC_KEY_FILENAME = "ecdsa_pub";
  private static final String PROVISION_COMMAND = "provision";
  private static final String LIST_COMMAND = "list";
  private static final String SIGN_COMMAND = "sign";
  private static final String GENERATE_TERMINAL_KEY_PAIR_COMMAND = "genkeypair";
  private static final String CURVE_NAME = "prime192v1";
  private static final String KEY_GENERATION_ALGORITHM = "ECDSA";
  private static final String SIGNATURE_ALGORITHM = "SHA1withECDSA";
  private static final int VR_LENGTH = 25;
  private static final int VS_LENGTH = 25;
  private static final int LENGTH_TAG = (int)KEY_PARAM_LENGTH_TAG;

  private static final Provider BOUNCY_CASTLE_PROVIDER = new BouncyCastleProvider();

  private static final boolean MODE_TEST = false;

  public CardTerminal() {

  }

  private static void printHelp() {
    System.out.println("usage: " + PROGRAM_NAME + " [<flags>] <command> [<args>]");
    System.out.println();
    System.out.println(HELP_HEADER);
    System.out.println();
    System.out.println("Flags:");
    System.out.println("  -h,--help\tShow help.");
    System.out.println();
    System.out.println("Commands:");
    System.out.println("  provision <crsid> <group id> <expiry>");
    System.out.println("    Provision a smart card with the provided CRSID, group ID and certificate expiry.");
    System.out.println();
    System.out.println("  list");
    System.out.println("    List the details stored on the smart card, i.e. CRSID, group ID, certificate expiry.");
    System.out.println();
    System.out.println("  genkeypair");
    System.out.println("    Generate a key pair that the terminal will use when signing card keys.");
    System.out.println();
    System.out.println("  sign <infile> <outfile>");
    System.out.println("    Sign the bytes in <infile> and write the signature to <outfile>.");
    System.out.println();
  }

  /**
   * This will generate a key pair and save each to a separate file. The public
   * key is X509 encoded and the private key is PKCS8 encoded.
   */
  private static void genTerminalKeyPair() {
    // Get Path object for working directory
    Path wd = Paths.get(".").toAbsolutePath().normalize();
    File pubFile = wd.resolve(TERMINAL_PUBLIC_KEY_FILENAME).toFile();
    File privFile = wd.resolve(TERMINAL_PRIVATE_KEY_FILENAME).toFile();

    // Open key files.
    BufferedOutputStream pubFOS = null;
    BufferedOutputStream privFOS = null;
    try {
      pubFile.delete(); // in case there was a pre-existing file.
      pubFile.createNewFile();
      pubFOS = new BufferedOutputStream(new FileOutputStream(pubFile));
      privFile.delete(); // in case there was a pre-existing file.
      privFile.createNewFile();
      privFOS = new BufferedOutputStream(new FileOutputStream(privFile));
    } catch (IOException e) {
      System.out.println(e.getMessage());
    }

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
    KeyPair kp = g.generateKeyPair();

    BCECPrivateKey privateKey = (BCECPrivateKey)kp.getPrivate();
    BCECPublicKey publicKey = (BCECPublicKey)kp.getPublic();

    if (MODE_TEST) {
      System.out.println(Hex.encodeHexString(publicKey.getQ().getEncoded(false)));
      System.out.println(Hex.encodeHexString(privateKey.getD().toByteArray()));
    }

    // Public key is X509 encoded.
    byte[] pubBytes = publicKey.getEncoded();
    // Private key is PKCS8 encoded.
    byte[] privBytes = privateKey.getEncoded();

    // Write to files.
    try {
      // Write length of data first, to simplify reading in the key later on.
      pubFOS.write(pubBytes.length);
      pubFOS.write(pubBytes, 0, pubBytes.length);
      pubFOS.flush();
      pubFOS.close();

      privFOS.write(privBytes.length);
      privFOS.write(privBytes, 0, privBytes.length);
      privFOS.flush();
      privFOS.close();
    } catch (IOException e) {
      System.out.println(e.getMessage());
    }
  }

  /**
   * Load the terminal's public and private keys from file.
   *
   * @return the KeyPair object initialized with the loaded public and private
   * keys.
   */
  private static KeyPair loadTerminalKeyPair() throws IOException,
          NoSuchAlgorithmException, InvalidKeySpecException {
    // Get Path object for working directory
    Path wd = Paths.get(".").toAbsolutePath().normalize();
    File pubFile = wd.resolve(TERMINAL_PUBLIC_KEY_FILENAME).toFile();
    File privFile = wd.resolve(TERMINAL_PRIVATE_KEY_FILENAME).toFile();

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

  private static byte[] sign(KeyPair kp, byte[] data) throws IOException,
          NoSuchAlgorithmException, InvalidKeySpecException, NoKeyPairException,
          SignatureException, InvalidKeyException {
    Signature dsa = Signature.getInstance(SIGNATURE_ALGORITHM, BOUNCY_CASTLE_PROVIDER);
    dsa.initSign(kp.getPrivate());
    dsa.update(data);
    byte[] sig = dsa.sign();

    // Now we have to pad out the signature coordinates so the entire thing is
    // 56 bytes (because javacard does this and without it, the smartcard will
    // fail to verify the signature).
    byte[] finalSig;
    if (sig.length != SIGNATURE_LENGTH) {
      /*
       * The format of the signature should be as follows (ASN1):
       *
       * 0x30 b1 0x02 b2 (vr) 0x02 b3 (vs)
       *
       * where:
       *
       * - b1 is a single byte value, equal to the length, in bytes, of the
       *   remaining list of bytes (from the first 0x02 to the end of the encoding)
       * - b2 is a single byte value, equal to the length, in bytes, of (vr)
       * - b3 is a single byte value, equal to the length, in bytes, of (vs)
       * - (vr) is the signed big-endian encoding of the value "r"
       * - (vs) is the signed big-endian encoding of the value "s"
       */
      ASN1Sequence sequence = (ASN1Sequence)ASN1Primitive.fromByteArray(sig);
      byte[] vr = ((ASN1Integer)sequence.getObjectAt(0).toASN1Primitive()).getValue().toByteArray();
      byte[] vs = ((ASN1Integer)sequence.getObjectAt(1).toASN1Primitive()).getValue().toByteArray();

      int padVR = VR_LENGTH - vr.length;
      int padVS = VS_LENGTH - vs.length;
      if (padVR < 0) padVR = 0;
      if (padVS < 0) padVS = 0;

      // Less confusing to use a ByteArrayOutputStream than trying to calculate
      // array offsets by hand.
      ByteArrayOutputStream sigOS = new ByteArrayOutputStream(SIGNATURE_LENGTH);
      sigOS.write(0x30);
      sigOS.write(0x36); // b1
      sigOS.write(0x02);
      sigOS.write(0x19); // b2
      for (int i = 0; i < padVR; i++) sigOS.write(0x00); // vr
      sigOS.write(vr, 0, vr.length);                     // vr
      sigOS.write(0x02);
      sigOS.write(0x19); // b3
      for (int i = 0; i < padVS; i++) sigOS.write(0x00); // vs
      sigOS.write(vs, 0, vs.length);                     // vs

      finalSig = sigOS.toByteArray();
    } else {
      finalSig = sig;
    }

    return finalSig;
  }

  private static void provision(byte[] crsID, byte[] groupID,
      byte[] certificateExpiry) throws IOException, NoSuchAlgorithmException,
          InvalidKeySpecException, NoKeyPairException, SignatureException,
          InvalidKeyException {
    CardTerminalAPI api = null;
    try {
      api = new CardTerminalAPI();
      api.selectAuthenticationApplet();

      byte[] cardPublicKeyBytes = api.sendGenerateKeyPairCommand();
      // Combine all elements to be signed into one byte array.
      byte[] dataToBeSigned = new byte[crsID.length + groupID.length +
        certificateExpiry.length + cardPublicKeyBytes.length];
      int offset = 0;
      System.arraycopy(crsID, 0, dataToBeSigned, offset, crsID.length);
      offset += crsID.length;
      System.arraycopy(groupID, 0, dataToBeSigned, offset, groupID.length);
      offset += groupID.length;
      System.arraycopy(certificateExpiry, 0, dataToBeSigned, offset, certificateExpiry.length);
      offset += certificateExpiry.length;
      System.arraycopy(cardPublicKeyBytes, 0, dataToBeSigned, offset, cardPublicKeyBytes.length);

      //System.out.println(Hex.encodeHexString(dataToBeSigned));

      KeyPair kp = loadTerminalKeyPair();
      if (kp == null)
        throw new NoKeyPairException();
      byte[] signature = sign(kp, dataToBeSigned);

      byte[] terminalPublicKey = ((BCECPublicKey)kp.getPublic()).getQ().getEncoded(false);

      // OutputStream.write() writes only the lower 8 bits of an int, so in order
      // to write a 2 byte numerical value, we first use write() to output the top
      // 8 bits of the value (by right shifting the int by 8 bits), then again
      // to write the lower 8 bits (no shift needed here, of course).
      ByteArrayOutputStream cardStoredDataOS = new ByteArrayOutputStream(SIGNATURE_LENGTH
          +LENGTH_TAG+UNCOMPRESSED_W_ENCODED_LENGTH
          +LENGTH_TAG+crsID.length
          +LENGTH_TAG+groupID.length
          +certificateExpiry.length);
      cardStoredDataOS.write(signature, 0, signature.length);
      cardStoredDataOS.write(terminalPublicKey.length >> 8);
      cardStoredDataOS.write(terminalPublicKey.length);
      cardStoredDataOS.write(terminalPublicKey, 0, terminalPublicKey.length);
      cardStoredDataOS.write(crsID.length >> 8);
      cardStoredDataOS.write(crsID.length);
      cardStoredDataOS.write(crsID, 0, crsID.length);
      cardStoredDataOS.write(groupID.length >> 8);
      cardStoredDataOS.write(groupID.length);
      cardStoredDataOS.write(groupID, 0, groupID.length);
      cardStoredDataOS.write(certificateExpiry);

      byte[] cardStoredData = cardStoredDataOS.toByteArray();

      if (MODE_TEST) {
        System.out.println(Hex.encodeHexString(cardStoredData));
        System.out.println(Hex.encodeHexString(signature));
        System.out.println(Hex.encodeHexString(terminalPublicKey));
      }

      // Send data to card for storage.
      api.sendStoreSignatureCommand(cardStoredData);

      // Now query the card to check data was stored correctly.
      byte[] queriedStoredData = api.sendCheckStoredDataCommand();
      if (!Arrays.equals(cardStoredData, queriedStoredData)) {
        System.out.println("An error occured whilst attempting to provision the "
            + "card, please try again.");
      }

      // Lock the card to prevent it from responding to any further provisioning
      // commands.
      api.sendLockCardCommand();

      System.out.println("Provisioning successful!");
    } catch (CardException e) {
      System.out.println("Error during communication with card:");
      System.out.println(e.getMessage());
      System.exit(0);
    } catch (CardCommunicationException e) {
      System.out.println(e.getMessage());
    } finally {
      api.close();
    }
  }

  private static void list() {
    CardTerminalAPI api = null;
    byte[] storedData;
    try {
      api = new CardTerminalAPI();
      api.selectAuthenticationApplet();
      storedData = api.sendCheckStoredDataCommand();
    } catch (CardException e) {
      System.out.println("Error during communication with card:");
      System.out.println(e.getMessage());
      return;
    } catch (CardCommunicationException e) {
      System.out.println(e.getMessage());
      return;
    } finally {
      api.close();
    }

    int off = 0;

    // Signature
    byte[] sigBuff = new byte[SIGNATURE_LENGTH];
    System.arraycopy(storedData, off, sigBuff, 0, SIGNATURE_LENGTH);
    System.out.println("Signature: " + Hex.encodeHexString(sigBuff));

    off += SIGNATURE_LENGTH;

    // Terminal public key
    short lenW = Util.getShort(storedData, (short)off);
    off += 2;
    byte[] termPub = new byte[lenW];
    System.arraycopy(storedData, off, termPub, 0, lenW);
    off += lenW;
    System.out.println("Terminal Public Key: " + Hex.encodeHexString(termPub));

    // CRSID
    short lenCRSID = Util.getShort(storedData, (short)off);
    off += 2;
    byte[] crsID = new byte[lenCRSID];
    System.arraycopy(storedData, off, crsID, 0, lenCRSID);
    off += lenCRSID;
    System.out.println("CRSID: " + Hex.encodeHexString(crsID));

    // GroupID
    short lenGroupID = Util.getShort(storedData, (short)off);
    off += 2;
    byte[] groupID = new byte[lenGroupID];
    System.arraycopy(storedData, off, groupID, 0, lenGroupID);
    off += lenGroupID;
    System.out.println("Group ID: " + Hex.encodeHexString(groupID));

    // Certificate expiry
    byte[] expiry = new byte[CERTIFICATE_EXPIRY_LENGTH];
    System.arraycopy(storedData, off, expiry, 0, CERTIFICATE_EXPIRY_LENGTH);
    System.out.println("Certificate Expiry: " + Hex.encodeHexString(expiry));
  }

  private static void signFile(String inPath, String outPath) throws IOException,
          NoKeyPairException, NoSuchAlgorithmException, InvalidKeySpecException,
          SignatureException, InvalidKeyException {
    Path inFile = Paths.get(inPath).toAbsolutePath().normalize();
    Path outFile = Paths.get(outPath).toAbsolutePath().normalize();

    byte[] dataToBeSigned = Files.readAllBytes(inFile);

    KeyPair kp = loadTerminalKeyPair();
    if (kp == null)
      throw new NoKeyPairException();
    byte[] signature = sign(kp, dataToBeSigned);

    Files.write(outFile, signature);
  }

  private static byte[] convertCRSID(String crsID) {
    return crsID.getBytes(StandardCharsets.UTF_8);
  }

  private static byte[] parseGroupID(String rawGrpID) throws DecoderException {
    return Hex.decodeHex(rawGrpID);
  }

  private static byte[] parseCertificateExpiry(String rawExpiry) throws DecoderException {
    return Hex.decodeHex(rawExpiry);
  }

  public static void main(String[] args) {
    if (args.length == 0) {
      printHelp();
      return;
    } else if (args[0].equals(PROVISION_COMMAND)) {
      if (args.length != 4) {
        printHelp();
        return;
      }

      String crsID = args[1];
      byte[] groupID;
      byte[] certificateExpiry;
      try {
        groupID = parseGroupID(args[2]);
      } catch (DecoderException e) {
        System.out.println("Group ID must be a hexadecimal value (without preceding '0x', no spaces).");
        return;
      }
      try {
        certificateExpiry = parseCertificateExpiry(args[3]);
      } catch (DecoderException e) {
        System.out.println("Certificate expiry must be a hexadecimal value (without preceding '0x', no spaces).");
        return;
      }

      try {
        provision(convertCRSID(crsID), groupID, certificateExpiry);
      } catch (Exception e) {
        e.printStackTrace();
        System.out.println(e.getMessage());
        return;
      }
    } else if (args[0].equals(LIST_COMMAND)) {
      if (args.length != 1) {
        printHelp();
        return;
      }

      list();
    } else if (args[0].equals(GENERATE_TERMINAL_KEY_PAIR_COMMAND)) {
      // Use default paths, which are "<WD>/ecdsa" and "<WD>/ecdsa_pub".
      genTerminalKeyPair();
    } else if (args[0].equals(SIGN_COMMAND)) {
      if (args.length != 3) {
        printHelp();
        return;
      }

      try {
        signFile(args[1], args[2]);
      } catch (Exception e) {
        e.printStackTrace();
      }
    } else {
      printHelp();
      return;
    }
  }
}
