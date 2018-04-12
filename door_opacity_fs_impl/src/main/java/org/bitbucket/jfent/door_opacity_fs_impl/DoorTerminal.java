package org.bitbucket.jfent.door_opacity_fs_impl;

import static org.bitbucket.jfent.opacity_fs_impl.OpacityForwardSecrecyImplementationApplet.*;
import java.util.Arrays;
import java.nio.file.Paths;
import java.nio.file.Path;
import java.nio.file.Files;
import java.nio.ByteBuffer;
import java.io.IOException;
import java.io.File;
import java.io.FileInputStream;
import java.io.BufferedInputStream;
import java.io.FileNotFoundException;
import java.security.Provider;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.KeyPairGenerator;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.KeyFactory;
import java.security.Signature;
import java.security.SignatureException;
import java.security.NoSuchAlgorithmException;
import java.security.DigestException;
import java.security.interfaces.ECPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.InvalidKeyException;
import java.security.DigestException;
import java.security.InvalidAlgorithmParameterException;
import javax.crypto.KeyAgreement;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.BadPaddingException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javacard.framework.Util;
import org.apache.commons.codec.binary.Hex;
import org.bitbucket.jfent.card_terminal_api.CardTerminalAPI;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.ECPointUtil;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.crypto.macs.CBCBlockCipherMac;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.params.KeyParameter;

public class DoorTerminal {
  private static final String DOOR_PRIVATE_KEY_FILENAME = "ecdsa";
  private static final String DOOR_PUBLIC_KEY_FILENAME = "ecdsa_pub";
  private static final String DOOR_SIGNATURE_FILENAME = "ecdsa_sig";
  private static final String TERMINAL_PUBLIC_KEY_FILENAME = "terminal_ecdsa_pub";
  private static final String KEY_GENERATION_ALGORITHM = "ECDSA";
  private static final String CURVE_NAME = "prime192v1";
  private static final String DOOR_SIGNATURE_ALGORITHM = "SHA1withECDSA";
  private static final String EC_DIFFIE_HELLMAN_ALGORITHM = "ECDH";
  private static final String CIPHER_ALGORITHM = "AES/CBC/NoPadding";
  private static final String CIPHER_KEY_TYPE = "AES";

  private static final Provider BOUNCY_CASTLE_PROVIDER = new BouncyCastleProvider();

  private static final boolean TEST_BASIC_AUTH = false;
  private static final int BASIC_AUTH_NONCE_LENGTH = 100;

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

  private static PublicKey loadTerminalPublicKey() throws IOException,
          NoSuchAlgorithmException, InvalidKeySpecException {
    // Get Path object for working directory
    Path wd = Paths.get(".").toAbsolutePath().normalize();
    File terminalPubKeyFile = wd.resolve(TERMINAL_PUBLIC_KEY_FILENAME).toFile();

    if (!terminalPubKeyFile.exists()) {
      System.out.println("Cannot find terminal public key file named \"terminal_ecdsa_pub\" in working directory.");
      return null;
    } else if (!terminalPubKeyFile.isFile()) {
      System.out.println("Cannot read terminal public key - entity in working directory named \"terminal_ecdsa_pub\" is not a file.");
      return null;
    }

    // Read the keys from file.
    BufferedInputStream pubFIS = null;
    byte[] pubBytes;
    pubFIS = new BufferedInputStream(new FileInputStream(terminalPubKeyFile));
    int pubLength = pubFIS.read();
    pubBytes = new byte[pubLength];
    pubFIS.read(pubBytes, 0, pubLength);

    // Now build key.
    KeyFactory kf = KeyFactory.getInstance(KEY_GENERATION_ALGORITHM,
        BOUNCY_CASTLE_PROVIDER);
    return kf.generatePublic(new X509EncodedKeySpec(pubBytes));
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

  /**
   * Signatures generated by Javacard are always the max possible length, but
   * Bouncy Castle conforms to the spec (signature points must be of minimal
   * length - see https://crypto.stackexchange.com/questions/1795/how-can-i-convert-a-der-ecdsa-signature-to-asn-1
   * for details). This method simply removes erroneously placed 0x00 prefixes.
   *
   * @param sig the byte array containing the signature to be checked for 0x00
   *            prefixes
   * @return the size of the resulting signature byte array
   */
  private static byte[] checkSignature(byte[] sig) {
    // If sig isn't 56 bytes, it won't be incorrectly padded
    if (sig.length != SIGNATURE_LENGTH) return sig;

    final int VR_OFFSET = 4;

    /*
     * For information about the offsets into the signature array, see the
     * encoding of the signature in the sign() method of CardTerminal.java in
     * the piiproj/card_terminal.
     */
    byte vrLength = sig[VR_OFFSET-1];
    // The 4 gets us past the header (0x30 b1 0x02 b2) (and on top of first byte
    // of vr)
    // The b2 gets us past vr (and on top of integer tag 0x02 for vs)
    // The 1 gets us past the ASN1 integer tag (0x02) (and on top of b3)
    byte vsLength = sig[VR_OFFSET + vrLength + 1];
    byte[] vrBytes = new byte[vrLength];
    byte[] vsBytes = new byte[vsLength];

    int vs_offset = VR_OFFSET + vrLength + 2;

    System.arraycopy(sig, VR_OFFSET, vrBytes, 0, vrLength);
    System.arraycopy(sig, vs_offset, vsBytes, 0, vsLength);

    int vrResizeLength = vrLength, vsResizeLength = vsLength;

    // Pads may be more than 1 byte, so we loop over arrays to check pad lengths.
    for (int i = 0; i < vrLength; i++) {
      // if the first 2 bytes are 0x00, remove the first 0x00
      if ((vrBytes[0] & 0xff) == 0x00 && (vrBytes[1] & 0xff) == 0x00) {
          vrResizeLength--;
          System.arraycopy(vrBytes, 1, vrBytes, 0, vrResizeLength);
      }
    }
    for (int i = 0; i < vsLength; i++) {
      // if the first 2 bytes are 0x00, remove the first 0x00
      if ((vsBytes[0] & 0xff) == 0x00 && (vsBytes[1] & 0xff) == 0x00) {
          vsResizeLength--;
          System.arraycopy(vsBytes, 1, vsBytes, 0, vsResizeLength);
      }
    }

    // Now both vsBytes and vrBytes should have a pad of at most 1.
    // Thus, we can proceed to check whether this pad is necessary, as below.

    // See link in method documentation for reasoning behind 0x7f as limit.
    // See https://stackoverflow.com/questions/13392351/compare-byte-values for
    // an explanation of why we AND the byte values before comparison.
    if ((vrBytes[0] & 0xff) == 0x00 && (vrBytes[1] & 0xff) <= 0x7f) {
      System.arraycopy(vrBytes, 1, vrBytes, 0, 0x18);
      vrResizeLength--;
    }
    if ((vsBytes[0] & 0xff) == 0x00 && (vsBytes[1] & 0xff) <= 0x7f) {
      System.arraycopy(vsBytes, 1, vsBytes, 0, 0x18);
      vsResizeLength--;
    }

    // New array will contain:
    // 0x30 b1 0x02 b2 (vr) 0x02 b3 (vs)
    int newSigLength = 4+vrResizeLength+2+vsResizeLength;
    byte[] result = new byte[newSigLength];
    result[0] = 0x30;
    // We subtract 2 because b1 is the length of the REMAINING bytes.
    result[1] = (byte)(newSigLength-2);
    result[2] = 0x02;
    result[3] = (byte)vrResizeLength;
    System.arraycopy(vrBytes, 0, result, VR_OFFSET, vrResizeLength);
    result[VR_OFFSET+vrResizeLength] = 0x02;
    result[VR_OFFSET+vrResizeLength+1] = (byte)vsResizeLength;
    System.arraycopy(vsBytes, 0, result, VR_OFFSET+vrResizeLength+2, vsResizeLength);

    return result;
  }

  /**
   * Turn an encoded EC public key into an actual Java PublicKey object.
   *
   * @param pubBytes the byte array containing the uncompressed encoding of the
   *                 W parameter
   * @return         the PublicKey object generated using the provided W parameter.
   */
  private static PublicKey createECPublicKey(byte[] pubBytes) throws NoSuchAlgorithmException,
          InvalidKeySpecException {
    ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec(CURVE_NAME);
    ECPoint w = ecSpec.getCurve().decodePoint(pubBytes);
    KeyFactory kf = KeyFactory.getInstance(KEY_GENERATION_ALGORITHM,
        BOUNCY_CASTLE_PROVIDER);

    ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(w, ecSpec);
    return kf.generatePublic(pubKeySpec);
  }

  private static boolean validateCardCertificate(byte[] crsID, byte[] groupID,
      byte[] certificateExpiry, byte[] cardPublicKey, PublicKey signingKey,
      byte[] cardSignature) throws InvalidKeyException,
      SignatureException, NoSuchAlgorithmException {
    int dOff = 0;
    byte[] cardSignatureData = new byte[crsID.length+groupID.length
      +CERTIFICATE_EXPIRY_LENGTH
      +UNCOMPRESSED_W_ENCODED_LENGTH+KEY_PARAM_LENGTH_TAG];
    System.arraycopy(crsID, 0, cardSignatureData, dOff, crsID.length);
    dOff += crsID.length;
    System.arraycopy(groupID, 0, cardSignatureData, dOff, groupID.length);
    dOff += groupID.length;
    System.arraycopy(certificateExpiry, 0, cardSignatureData, dOff,
        CERTIFICATE_EXPIRY_LENGTH);
    dOff += CERTIFICATE_EXPIRY_LENGTH;
    cardSignatureData[dOff] = (byte)(cardPublicKey.length >> 8);
    cardSignatureData[dOff+1] = (byte)cardPublicKey.length;
    dOff += 2;
    System.arraycopy(cardPublicKey, 0, cardSignatureData, dOff,
        cardPublicKey.length);

    // Do verification of card signature.
    Signature ecdsaObj = Signature.getInstance(DOOR_SIGNATURE_ALGORITHM,
        BOUNCY_CASTLE_PROVIDER);
    ecdsaObj.initVerify(signingKey);
    ecdsaObj.update(cardSignatureData);
    return ecdsaObj.verify(cardSignature);
  }

  /**
   * This method checks that we can derive the same data that the card has derived
   * (and returned to us), and therefore that the card is authenticated.
   *
   * We take all cryptographic objects as arguments, so that they can be created
   * before the protocol begins, saving protocol execution time.
   *
   * @param responseBuffer the byte array containing all the data returned by the
   * card
   * @param ecDiffieHellman the premade key agreement object for deriving the
   * secrets Z1 and Z
   * @param doorPermanentKeyPair the card reader's permanent key pair
   * @param doorEphemeralKeyPair the card reader's ephemeral key pair (a new one
   * is generated for each protocol execution)
   * @return a boolean indicating whether the card is authenticated
   * or not
   */
  private static boolean authenticateCardResponse(byte[] responseBuffer,
      KeyAgreement ecDiffieHellman, KeyPair doorPermanentKeyPair,
      KeyPair doorEphemeralKeyPair, ConcatenationKDF kdf, Cipher aesCipher,
      MessageDigest sha1Digest, Signature ecdsa, PublicKey terminalPublicKey) throws
      NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException,
      DigestException, IllegalBlockSizeException, BadPaddingException,
      InvalidAlgorithmParameterException, NoSuchAlgorithmException,
      SignatureException, NoSuchPaddingException, ShortBufferException {
    // Get data from the response buffer.
    int opaqueDataLength = Util.getShort(responseBuffer, (short)0);
    byte[] opaqueData = new byte[opaqueDataLength];
    byte[] authCryptogram = new byte[AES_CMAC_OUTPUT_SIZE];
    byte[] otidICC = new byte[UNCOMPRESSED_W_ENCODED_LENGTH];

    System.arraycopy(responseBuffer, 2, opaqueData, 0, opaqueDataLength);
    System.arraycopy(responseBuffer, 2+opaqueDataLength, authCryptogram, 0,
        AES_CMAC_OUTPUT_SIZE);
    System.arraycopy(responseBuffer, 2+opaqueDataLength+AES_CMAC_OUTPUT_SIZE,
        otidICC, 0, UNCOMPRESSED_W_ENCODED_LENGTH);

    /*
     * Validate that OTID_ICC (=Q_eICC) belongs to EC domain. The call to
     * createECPublicKey() below will fail if this is not the case.
     */
    BCECPublicKey cardEphemeralPublicKey = (BCECPublicKey)createECPublicKey(otidICC);

    /*
     * Derive Z1.
     */

    ecDiffieHellman.init(doorPermanentKeyPair.getPrivate());
    ecDiffieHellman.doPhase(cardEphemeralPublicKey, true);
    byte[] ecDHSecret = ecDiffieHellman.generateSecret();

    // Must now perform SHA-1 on the generated secret, to match the operation of
    // Javacard.
    sha1Digest.reset();
    byte[] secretZ1 = sha1Digest.digest(ecDHSecret);

    /*
     * Derive K1, K2.
     */

    // First, setup the otherInfo array.
    byte[] k1k2OtherInfo = new byte[2+UNCOMPRESSED_W_ENCODED_LENGTH];
    k1k2OtherInfo[0] = 0x09;
    k1k2OtherInfo[1] = 0x09;
    System.arraycopy(cardEphemeralPublicKey.getQ().getEncoded(false), 0,
        k1k2OtherInfo, 2, UNCOMPRESSED_W_ENCODED_LENGTH);

    byte[] keysK1K2 = kdf.deriveKey(secretZ1, k1k2OtherInfo, 2*AES_KEY_SIZE);
    byte[] k1 = new byte[AES_KEY_SIZE];
    byte[] k2 = new byte[AES_KEY_SIZE];
    System.arraycopy(keysK1K2, 0, k1, 0, AES_KEY_SIZE);
    System.arraycopy(keysK1K2, AES_KEY_SIZE, k2, 0, AES_KEY_SIZE);

    /*
     * Decrypt OpaqueData_ICC to get card's certificate.
     */

    // First, create the key object.
    SecretKeySpec k1KeySpec = new SecretKeySpec(k1, CIPHER_KEY_TYPE);

    // Now decrypt.
    aesCipher.init(Cipher.DECRYPT_MODE, k1KeySpec,
        new IvParameterSpec(new byte[AES_BLOCK_SIZE]));
    byte[] certificateData = aesCipher.doFinal(opaqueData);

    /*
     * Validate card's certificate.
     */

    short dOff = 0;

    byte[] cardSignature = new byte[SIGNATURE_LENGTH];
    System.arraycopy(certificateData, dOff, cardSignature, 0, SIGNATURE_LENGTH);
    // Remove any incorrect 0x00 pads on points.
    cardSignature = checkSignature(cardSignature);
    dOff += SIGNATURE_LENGTH;

    short cardPubKeyLength = Util.getShort(certificateData, dOff);
    dOff += 2; // Skip over length tag
    byte[] cardPublicKey = new byte[cardPubKeyLength];
    System.arraycopy(certificateData, dOff, cardPublicKey, 0, cardPubKeyLength);
    dOff += cardPubKeyLength;

    short crsIDLength = Util.getShort(certificateData, dOff);
    dOff += 2;
    byte[] crsID = new byte[crsIDLength];
    System.arraycopy(certificateData, dOff, crsID, 0, crsIDLength);
    dOff += crsIDLength;

    short groupIDLength = Util.getShort(certificateData, dOff);
    dOff += 2;
    byte[] groupID = new byte[groupIDLength];
    System.arraycopy(certificateData, dOff, groupID, 0, groupIDLength);
    dOff += groupIDLength;

    byte[] certificateExpiry = new byte[CERTIFICATE_EXPIRY_LENGTH];
    System.arraycopy(certificateData, dOff, certificateExpiry, 0,
        CERTIFICATE_EXPIRY_LENGTH);

    // If the card's certificate isn't valid, then don't authenticate.
    if(!validateCardCertificate(crsID, groupID, certificateExpiry, cardPublicKey,
          terminalPublicKey, cardSignature)) {
      return false;
    }

    // Turn card's encoded permanent public key into a PublicKey object.
    BCECPublicKey cardPermanentPublicKey = (BCECPublicKey)createECPublicKey(cardPublicKey);

    /*
     * Derive Z.
     */

    ecDiffieHellman.init(doorEphemeralKeyPair.getPrivate());
    ecDiffieHellman.doPhase(cardPermanentPublicKey, true);
    ecDHSecret = ecDiffieHellman.generateSecret();

    // Must now perform SHA-1 on the generated secret, to match the operation of
    // Javacard.
    sha1Digest.reset();
    byte[] secretZ = sha1Digest.digest(ecDHSecret);

    /*
     * Derive SK_CFRM.
     */

    // Setup other info byte array.
    // NOTE: We've omitted ID_sH.
    // For further details on otherInfo, see
    // https://www.securetechalliance.org/resources/pdf/OPACITY_Protocol_3.7.pdf,
    // Annex A. Briefly:
    //  - 1 is for the algorithm ID of the derived key, SK_CFRM.
    //  - 8 is for the top 8 bits of OTID_ICC (which is just the card's ephemeral
    //  public key).
    //  - 16 is for the top 16 bits of the door terminal's ephemeral public key.
    //  - AES_KEY_SIZE is for K2.
    byte[] skcfrmOtherInfo = new byte[1+8+16+AES_KEY_SIZE];
    short skcfrmInfoOffset = 1;
    skcfrmOtherInfo[0] = (byte)0x09;

    // Top 8 of OTID_ICC
    System.arraycopy(otidICC, 0, skcfrmOtherInfo, skcfrmInfoOffset, 8);
    skcfrmInfoOffset += 8;

    // Top 16 of door's ephemeral public key.
    byte[] doorEphemeralPubKeyBytes =
      ((BCECPublicKey)doorEphemeralKeyPair.getPublic()).getQ().getEncoded(false);
    System.arraycopy(doorEphemeralPubKeyBytes, 0, skcfrmOtherInfo, skcfrmInfoOffset,
        16);
    skcfrmInfoOffset += 16;

    // K2
    System.arraycopy(k2, 0, skcfrmOtherInfo, skcfrmInfoOffset, AES_KEY_SIZE);

    // Now actually derive the key.
    byte[] keySKCFRM = kdf.deriveKey(secretZ, skcfrmOtherInfo, AES_KEY_SIZE);

    /*
     *System.out.println("SKCFRM_DOOR: " + Hex.encodeHexString(keySKCFRM));
     *System.out.println("SKCFRM_CARD: " + Hex.encodeHexString(authCryptogram));
     */

    /*
     * Zeroize Z, Z1, K1, K2.
     */

    Arrays.fill(secretZ1, (byte)0x00);
    Arrays.fill(keysK1K2, (byte)0x00);
    Arrays.fill(k1, (byte)0x00);
    Arrays.fill(k2, (byte)0x00);
    Arrays.fill(secretZ, (byte)0x00);
    Arrays.fill(ecDHSecret, (byte)0x00);

    /*
     * Check AuthCryptogram_ICC.
     */

    // First need to generate the MAC.
    // Setup input data array.

    // This will hold:
    //  - Top 8 bytes of OTID_ICC
    //  - Top 16 bytes of door's ephemeral public key.
    // However, it's length must also be divisible by AES_BLOCK_SIZE, to avoid
    // the AES CMAC signature object from throwing an error.
    int authCryptogramInputDataSize = 8+16;
    if (authCryptogramInputDataSize % AES_BLOCK_SIZE != 0)
      authCryptogramInputDataSize +=
        AES_BLOCK_SIZE-(authCryptogramInputDataSize % AES_BLOCK_SIZE);
    byte[] authCryptogramInputData = new byte[authCryptogramInputDataSize];

    // Top 8 OTID_ICC
    System.arraycopy(otidICC, 0, authCryptogramInputData, 0, 8);

    // Top 16 of door's ephemeral public key.
    System.arraycopy(doorEphemeralPubKeyBytes, 0, authCryptogramInputData, 8, 16);

    // Declare array to hold CMAC result.
    byte[] authCryptogramRegenerated = new byte[AES_BLOCK_SIZE];
    BlockCipher aes = new AESEngine();
    // Length of MAC is given in bits - 128 bits = 16 bytes.
    CBCBlockCipherMac aesCMAC = new CBCBlockCipherMac(aes, 128);
    KeyParameter key = new KeyParameter(keySKCFRM);
    aesCMAC.init(key);
    aesCMAC.update(authCryptogramInputData, 0, authCryptogramInputData.length);
    aesCMAC.doFinal(authCryptogramRegenerated, 0);

    // Compare the two MACs.
    if (!Arrays.equals(authCryptogram, authCryptogramRegenerated)) {
      System.out.println("AuthCryptogram's didn't match.");
      return false;
    }

    /*
     * Zeroize SK_CFRM.
     */

    Arrays.fill(keySKCFRM, (byte)0x00);

    return true;
  }

  public static void main (String[] args) {
    CardTerminalAPI api = null;

    // Load in the signature and permanent key pair from file.
    byte[] doorSignature = null;
    KeyPair doorPermanentKeyPair = null;
    PublicKey terminalPublicKey = null;
    try {
      doorSignature = loadDoorSignature();
      doorPermanentKeyPair = loadDoorKeyPair();
      terminalPublicKey = loadTerminalPublicKey();
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

    // Pre-instantiate all crypto objects to be used in the mutual auth protocol.
    KeyAgreement ecDH = null;
    ConcatenationKDF kdf = null;
    Cipher aesCipher = null;
    MessageDigest sha1Digest = null;
    Signature ecdsa = null;
    try {
      ecDH = KeyAgreement.getInstance(EC_DIFFIE_HELLMAN_ALGORITHM,
          BOUNCY_CASTLE_PROVIDER);
      kdf = new ConcatenationKDF(BOUNCY_CASTLE_PROVIDER);
      aesCipher = Cipher.getInstance(CIPHER_ALGORITHM, BOUNCY_CASTLE_PROVIDER);
      sha1Digest = MessageDigest.getInstance("SHA-1", BOUNCY_CASTLE_PROVIDER);
      ecdsa = Signature.getInstance(DOOR_SIGNATURE_ALGORITHM, BOUNCY_CASTLE_PROVIDER);
    } catch (Exception e) {
      System.out.println("Failed to instantiate cryto objects.");
      e.printStackTrace();
      return;
    }

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

        api = new CardTerminalAPI();
        api.selectAuthenticationApplet();

        /*
         * This is here just to test the BASIC_AUTH command (specifically, that
         * it runs in under 1 second.
         */
        if (TEST_BASIC_AUTH) {
          long t1 = System.nanoTime();
          // Generate random nonce.
          SecureRandom rand = new SecureRandom();
          byte[] nonce = new byte[BASIC_AUTH_NONCE_LENGTH+KEY_PARAM_LENGTH_TAG];
          rand.nextBytes(nonce);
          nonce[0] = (byte)(BASIC_AUTH_NONCE_LENGTH >> 8);
          nonce[1] = (byte)BASIC_AUTH_NONCE_LENGTH;

          // Send BASIC_AUTH command.
          byte[] response = api.sendBasicAuthenticationCommand(nonce);

          //System.out.println(Hex.encodeHexString(response));

          // Put all response data into separate arrays.
          int rOff = 0;

          short nonceSigLength = Util.getShort(response, (short)rOff);
          rOff += 2;
          byte[] nonceSignature = new byte[nonceSigLength];
          System.arraycopy(response, rOff, nonceSignature, 0, nonceSigLength);
          rOff += nonceSigLength;

          byte[] cardSignature = new byte[SIGNATURE_LENGTH];
          System.arraycopy(response, rOff, cardSignature, 0, SIGNATURE_LENGTH);
          // Remove any incorrect 0x00 pads on points.
          cardSignature = checkSignature(cardSignature);
          System.out.println("SIG: " + Hex.encodeHexString(cardSignature));
          rOff += SIGNATURE_LENGTH;

          rOff += 2; // Skip over length tag.
          byte[] cardPublicKey = new byte[UNCOMPRESSED_W_ENCODED_LENGTH];
          System.arraycopy(response, rOff, cardPublicKey, 0,
              UNCOMPRESSED_W_ENCODED_LENGTH);
          rOff += UNCOMPRESSED_W_ENCODED_LENGTH;

          short crsIDLength = Util.getShort(response, (short)rOff);
          rOff += 2;
          byte[] crsID = new byte[crsIDLength];
          System.arraycopy(response, rOff, crsID, 0, crsIDLength);
          rOff += crsIDLength;

          short groupIDLength = Util.getShort(response, (short)rOff);
          rOff += 2;
          byte[] groupID = new byte[groupIDLength];
          System.arraycopy(response, rOff, groupID, 0, groupIDLength);
          rOff += groupIDLength;

          byte[] certificateExpiry = new byte[CERTIFICATE_EXPIRY_LENGTH];
          System.arraycopy(response, rOff, certificateExpiry, 0,
              CERTIFICATE_EXPIRY_LENGTH);

          // Check card certificate
          int dOff = 0;
          byte[] cardSignatureData = new byte[crsIDLength+groupIDLength
            +CERTIFICATE_EXPIRY_LENGTH
            +UNCOMPRESSED_W_ENCODED_LENGTH+KEY_PARAM_LENGTH_TAG];
          System.arraycopy(crsID, 0, cardSignatureData, dOff, crsIDLength);
          dOff += crsIDLength;
          System.arraycopy(groupID, 0, cardSignatureData, dOff, groupIDLength);
          dOff += groupIDLength;
          System.arraycopy(certificateExpiry, 0, cardSignatureData, dOff,
              CERTIFICATE_EXPIRY_LENGTH);
          dOff += CERTIFICATE_EXPIRY_LENGTH;
          cardSignatureData[dOff] = (byte)(cardPublicKey.length >> 8);
          cardSignatureData[dOff+1] = (byte)cardPublicKey.length;
          dOff += 2;
          System.arraycopy(cardPublicKey, 0, cardSignatureData, dOff,
              cardPublicKey.length);

          // Do verification of card signature.
          Signature ecdsaObj = Signature.getInstance(DOOR_SIGNATURE_ALGORITHM,
              BOUNCY_CASTLE_PROVIDER);
          ecdsaObj.initVerify(terminalPublicKey);
          ecdsaObj.update(cardSignatureData);
          boolean verified = ecdsaObj.verify(cardSignature);
          /*
           *boolean verified = validateCardCertificate(crsID, groupID, certificateExpiry,
           *    cardPublicKey, ecdsa, terminalPublicKey, cardSignature);
           *System.out.println(verified);
           */

          // Now verify nonce signature.
          // First need to turn cardPublicKey byte array into actual PublicKey
          // object.
          PublicKey cardPublicKeyObj = createECPublicKey(cardPublicKey);
          ecdsaObj.initVerify(cardPublicKeyObj);
          // The first 2 bytes of the nonce byte array are a length tag for the card,
          // so we remove those from the signature data.
          ecdsaObj.update(nonce, 2, BASIC_AUTH_NONCE_LENGTH);
          verified = ecdsaObj.verify(nonceSignature);
          System.out.println(verified);

          // TODO: Complete auth by verifying certificate, checking group ID, etc.
          long t2 = System.nanoTime();
          System.out.println((double)(t2-t1)/1000000000.0);

          return;
        }

        /*
         * Otherwise, we do mutual auth, untraceable protocol.
         */
        long t1 = System.nanoTime();
        byte[] resp = api.sendInitiateAuthenticationCommand(initiateAuthData);
        boolean authd = authenticateCardResponse(resp, ecDH, doorPermanentKeyPair,
            doorEphemeralKeyPair, kdf, aesCipher, sha1Digest, ecdsa,
            terminalPublicKey);
        long t2 = System.nanoTime();

        System.out.println("Authenticated: " + authd);
        System.out.println((double)(t2-t1)/1000000000.0);
      } catch (Exception e) {
        e.printStackTrace();
        return;
      }

      try {
        System.out.println("Run complete");
        Thread.sleep(2000);
      } catch (InterruptedException e) {}
    }
  }
}
