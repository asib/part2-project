package org.bitbucket.jfent.card_terminal;

import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.nio.file.Path;
import java.io.IOException;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedInputStream;
import javax.smartcardio.CardException;
import javacard.security.ECPublicKey;
import javacard.security.ECPrivateKey;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.Signature;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.DecoderException;
import org.bitbucket.jfent.opacity_fs_impl.Utils;
import static org.bitbucket.jfent.opacity_fs_impl.OpacityForwardSecrecyImplementationApplet.*;

public class CardTerminal {
  private static final String PROGRAM_NAME = "card_terminal";
  private static final String HELP_HEADER = "Provision and reprogram smart cards.";
  private static final String TERMINAL_PRIVATE_KEY_FILENAME = "ecdsa";
  private static final String TERMINAL_PUBLIC_KEY_FILENAME = "ecdsa_pub";
  private static final String PROVISION_COMMAND = "provision";
  private static final String LIST_COMMAND = "list";
  private static final String GENERATE_TERMINAL_KEY_PAIR_COMMAND = "genkeypair";

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
    System.out.println("    List the details stored on the smart card, i.e. CRSID, group ID, certificate expiry");
    System.out.println();
    System.out.println("  genkeypair");
    System.out.println("    Generate a key pair that the terminal will use when signing card keys");
    System.out.println();
  }

  /**
   * This will generate a key pair and save each to a separate file.
   * The parameters are saved in the following order: W, A, B, G, R, Field.
   *
   * @param rawPubPath  The path to the file in which the public key will be saved.
   * @param rawPrivPath The path to the file in which the private key will be saved.
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
    KeyPair kp = new KeyPair(KEY_PAIR_ALGORITHM, TERMINAL_KEY_LENGTH);
    kp.genKeyPair();

    // Hex-encode pub/priv keys.
    byte[] pubBytes = new byte[TERMINAL_KEY_LENGTH+(Utils.NUM_PARAMS*Utils.LENGTH_TAG)];
    Utils.encodeECPublicKey((ECPublicKey)kp.getPublic(), pubBytes, (short)0);
    byte[] privBytes = new byte[TERMINAL_KEY_LENGTH+(Utils.NUM_PARAMS*Utils.LENGTH_TAG)];
    Utils.encodeECPrivateKey((ECPrivateKey)kp.getPrivate(), pubBytes, (short)0);

    try {
      pubFOS.write(pubBytes, 0, pubBytes.length);
      pubFOS.flush();
      pubFOS.close();

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
  private static KeyPair loadTerminalKeyPair() {
    // Get Path object for working directory
    Path wd = Paths.get(".").toAbsolutePath().normalize();
    File pubFile = wd.resolve(TERMINAL_PUBLIC_KEY_FILENAME).toFile();
    File privFile = wd.resolve(TERMINAL_PRIVATE_KEY_FILENAME).toFile();

    if (!pubFile.exists()) {
      System.out.println("Cannot find public key file named \"ecdsa_pub\" in working directory.");
    } else if (!pubFile.isFile()) {
      System.out.println("Cannot read public key - entity in working directory named \"ecdsa_pub\" is not a file.");
    } else if (!privFile.exists()) {
      System.out.println("Cannot find private key file named \"ecdsa\" in working directory.");
    } else if (!privFile.isFile()) {
      System.out.println("Cannot read private key - entity in working directory named \"ecdsa\" is not a file.");
    }

    BufferedInputStream pubFIS = null;
    BufferedInputStream privFIS = null;
    byte[] pubBytes = new byte[TERMINAL_KEY_LENGTH+(Utils.NUM_PARAMS*Utils.LENGTH_TAG)];
    byte[] privBytes = new byte[TERMINAL_KEY_LENGTH+(Utils.NUM_PARAMS*Utils.LENGTH_TAG)];
    try {
      pubFIS = new BufferedInputStream(new FileInputStream(pubFile));
      privFIS = new BufferedInputStream(new FileInputStream(privFile));

      // Read the keys into buffers.
      pubFIS.read(pubBytes, 0, TERMINAL_KEY_LENGTH+(Utils.NUM_PARAMS*Utils.LENGTH_TAG));
      privFIS.read(privBytes, 0, TERMINAL_KEY_LENGTH+(Utils.NUM_PARAMS*Utils.LENGTH_TAG));
    } catch (IOException e) {
      System.out.println(e.getMessage());
    }

  }

  private static void sign(byte[] data) {
    KeyPair kp = new KeyPair(KEY_PAIR_ALGORITHM, TERMINAL_KEY_LENGTH);
    kp.genKeyPair();
    Signature sig = Signature.getInstance(Signature.ALG_ECDSA_SHA, false);
    sig.init(kp.getPrivate(), Signature.MODE_SIGN);

    byte[] result = new byte[512];
    sig.sign(data, (short)0, (short)data.length, result, (short)0);
    System.out.println(Hex.encodeHexString(result));
  }

  private static void provision(byte[] crsID, byte[] groupID,
      byte[] certificateExpiry) {
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

      sign(dataToBeSigned);
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

      provision(convertCRSID(crsID), groupID, certificateExpiry);
    } else if (args[0].equals(LIST_COMMAND)) {
      if (args.length != 1) {
        printHelp();
        return;
      }

      list();
    } else if (args[0].equals(GENERATE_TERMINAL_KEY_PAIR_COMMAND)) {
      // Use default paths, which are "<WD>/ecdsa" and "<WD>/ecdsa_pub".
      genTerminalKeyPair();
    } else {
      printHelp();
      return;
    }
  }
}
