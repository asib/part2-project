package org.bitbucket.jfent.opacity_fs_impl;

import javacard.framework.Applet;
import javacard.framework.APDU;
import javacard.framework.Util;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.security.KeyBuilder;
import javacard.security.AESKey;
import javacard.security.ECKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyPair;
import javacard.security.Signature;
import javacard.security.KeyAgreement;
import javacard.security.MessageDigest;
import javacard.security.CryptoException;
import javacard.framework.CardRuntimeException;
import javacard.framework.CardException;
import javacard.framework.SystemException;
import javacardx.crypto.Cipher;

public class OpacityForwardSecrecyImplementationApplet extends Applet {
  /*
   *
   * Constants
   *
   */
  public static final byte CLA_PROPRIETARY = (byte)0x80; // CLA byte for proprietary commands.
  public static final byte GENERATE_KEY_PAIR = (byte)0x01; // INS byte for generating key pair.
  public static final byte STORE_SIGNATURE = (byte)0x02;   // INS byte for storing the terminal's signature.
  public static final byte CHECK_STORED_DATA = (byte)0x03; // INS byte for checking data was stored correctly after STORE_SIGNATURE instruction.
  public static final byte BASIC_AUTH = (byte)0x05; // INS byte for basic auth protocol. See details of protocol in documentation for method processBasicAuth().
  public static final byte INITIATE_AUTH = (byte)0x04; // INS byte for initiating the authentication protocol.
  public static final byte TERMINAL_KEY_TYPE = KeyBuilder.TYPE_EC_FP_PUBLIC;
  public static final short TERMINAL_KEY_LENGTH = KeyBuilder.LENGTH_EC_FP_192;
  public static final byte DOOR_KEY_TYPE = KeyBuilder.TYPE_EC_FP_PUBLIC;
  public static final short DOOR_KEY_LENGTH = KeyBuilder.LENGTH_EC_FP_192;
  public static final byte AUTHENTICATION_DENIED = (byte)0xff;
  /*
   * When we transmit EC keys, we have to transmit a byte array of containing a
   * parameter (W or S, depending on whether the key is public or private).
   * Since the parameter may not necessarily be of fixed length (e.g. if we change
   * the key length), we need to allow for variable length parameters. Thus, each
   * parameter is prefixed by a 2-byte length indicator.
   */
  public static final short KEY_PARAM_LENGTH_TAG = (short)2;
  public static final byte KEY_PAIR_ALGORITHM = KeyPair.ALG_EC_FP;
  public static final byte CARD_PUBLIC_KEY_TYPE = KeyBuilder.TYPE_EC_FP_PUBLIC;
  public static final short KEY_LENGTH = KeyBuilder.LENGTH_EC_FP_192;
  public static final short SIGNATURE_LENGTH = (short)56; // ALG_ECDSA_SHA produces 56 byte signature.
  // Expiry is stored in Unix time (an unsigned 32 bit integer, representing number
  // of seconds after 00:00:00 01/01/1970.
  public static final short CERTIFICATE_EXPIRY_LENGTH = (short)4;
  // When we transmit a public key, we send just the W parameter, which we get
  // by calling key.getW(). This returns W as a byte array, encoded according to
  // ANSI X9.62 section 4.3.6 (briefly, the first byte is 0x04, signifying
  // uncompressed encoding, followed by 24 bytes which encode W_x, and finally
  // 24 bytes which encode W_y, for a total of 49 bytes).
  public static final short UNCOMPRESSED_W_ENCODED_LENGTH = (short)49;
  // As per the OPACITY-FS protocol, we need to define our AES block cipher
  // parameters.
  // 0x10 is 16 bytes, or 128 bits.
  public static final short AES_BLOCK_SIZE = (short)0x10;
  public static final byte AES_BLOCK_CIPHER = Cipher.ALG_AES_BLOCK_128_CBC_NOPAD;
  public static final byte AES_KEY_TYPE = KeyBuilder.TYPE_AES_TRANSIENT_DESELECT;
  public static final short AES_KEY_SIZE = KeyBuilder.LENGTH_AES_128;
  public static final byte ECDH_ALGORITHM = KeyAgreement.ALG_EC_SVDP_DH;
  public static final byte SIGNATURE_ALGORITHM = Signature.ALG_ECDSA_SHA;
  // The signature algorithm used to generate the AuthCryptogram_ICC.
  public static final byte CMAC_ALGORITHM = Signature.ALG_AES_MAC_128_NOPAD;
  // The output of KeyAgreement.generateSecret() is always 20 bytes, since it's
  // a SHA-1 hash.
  public static final short ECDH_SECRET_LENGTH = (short)20;

  public static final byte KDF_HASH_ALGORITHM = MessageDigest.ALG_MD5;
  // MD5 block size is 512 bits, a.k.a. 64 bytes.
  public static final short KDF_HASH_BLOCK_SIZE = (short)64;
  // MD5 digest (output) size is 128 bits, a.k.a. 16 bytes.
  public static final short KDF_HASH_OUTPUT_SIZE = MessageDigest.LENGTH_MD5;

  public static final short AES_CMAC_OUTPUT_SIZE = (short)16;

  /*
   *
   * Instance variables
   *
   */
  private ECPublicKey terminalPublicKey; // Used to verify door's certificate.
  private KeyPair cardKeyPair;
  private final byte[] cardSignature; // The signature of the card's public key,
                                      // produced by the card terminal.
  private byte[] groupID;
  private byte[] crsID;
  private final byte[] certificateExpiry;

  // Used by KDF function named deriveKey().
  private MessageDigest hashDigest;

  // Used for signing nonces/verifying certificates.
  private Signature ecdsaSignature;

  // We define (and allocate/initialize, in constructor) these variables (which
  // are used during the OPACITY-FS protocol) early, to reduce authetication time.
  // For more information about their use, please read the processIniateAuthentication()
  // method.
  private ECPublicKey doorPermanentPublicKey;
  private ECPublicKey doorEphemeralPublicKey;
  private KeyPair cardEphemeralKeyPair;
  private KeyAgreement ecDiffieHellman;
  private AESKey certificateEncryptionKey;
  private Cipher aesCipher;
  private AESKey authCryptogramCMACKey;
  private Signature aesCMACSignature;
  private byte[] certificateData;
  private byte[] encryptedCertificate;
  private byte[] signatureData;
  private byte[] secretZ1;
  private byte[] k1k2OtherInfo;
  private byte[] keysK1K2;
  private byte[] secretZ;
  private byte[] keySKCFRM;
  private byte[] skcfrmOtherInfo;
  private byte[] otidICC;
  private byte[] authCryptogramInputData;

  private OpacityForwardSecrecyImplementationApplet() {
    terminalPublicKey = null;
    cardKeyPair = null;
    // This needs to be persistently stored.
    cardSignature = new byte[SIGNATURE_LENGTH];
    certificateExpiry = new byte[CERTIFICATE_EXPIRY_LENGTH];

    hashDigest = MessageDigest.getInstance(KDF_HASH_ALGORITHM, false);

    ecdsaSignature = Signature.getInstance(SIGNATURE_ALGORITHM, false);

    doorPermanentPublicKey = (ECPublicKey)KeyBuilder.buildKey(DOOR_KEY_TYPE,
        DOOR_KEY_LENGTH, false);
    Prime192v1.setKeyParameters((ECKey)doorPermanentPublicKey);

    doorEphemeralPublicKey = (ECPublicKey)KeyBuilder.buildKey(DOOR_KEY_TYPE,
        DOOR_KEY_LENGTH, false);
    Prime192v1.setKeyParameters((ECKey)doorEphemeralPublicKey);

    cardEphemeralKeyPair = new KeyPair(KEY_PAIR_ALGORITHM, KEY_LENGTH);
    Prime192v1.setKeyPairParameters(cardEphemeralKeyPair);

    ecDiffieHellman = KeyAgreement.getInstance(ECDH_ALGORITHM, false);

    certificateEncryptionKey = (AESKey)KeyBuilder.buildKey(AES_KEY_TYPE,
        AES_KEY_SIZE, false);
    aesCipher = Cipher.getInstance(AES_BLOCK_CIPHER, false);

    authCryptogramCMACKey = (AESKey)KeyBuilder.buildKey(AES_KEY_TYPE,
        AES_KEY_SIZE, false);
    aesCMACSignature = Signature.getInstance(CMAC_ALGORITHM, false);

    signatureData = new byte[UNCOMPRESSED_W_ENCODED_LENGTH];
    secretZ1 = new byte[ECDH_SECRET_LENGTH];

    // See https://www.securetechalliance.org/resources/pdf/OPACITY_Protocol_3.7.pdf,
    // Annex A for details of otherInfo.
    // NOTE: we've omitted ID_sH.
    k1k2OtherInfo = new byte[(short)(2+UNCOMPRESSED_W_ENCODED_LENGTH)];
    k1k2OtherInfo[0] = (byte)0x09;
    k1k2OtherInfo[1] = (byte)0x09;

    keysK1K2 = new byte[(short)(2*AES_KEY_SIZE)];
    secretZ = new byte[ECDH_SECRET_LENGTH];
    keySKCFRM = new byte[AES_KEY_SIZE];
    // NOTE: We've omitted ID_sH.
    // For further details on otherInfo, see
    // https://www.securetechalliance.org/resources/pdf/OPACITY_Protocol_3.7.pdf,
    // Annex A. Briefly:
    //  - 1 is for the algorithm ID of the derived key, SK_CFRM.
    //  - 8 is for the top 8 bits of OTID_ICC (which is just the card's ephemeral
    //  public key).
    //  - 16 is for the top 16 bits of the card terminal's public key.
    //  - AES_KEY_SIZE is for K2.
    skcfrmOtherInfo = new byte[(short)(1+8+16+AES_KEY_SIZE)];
    skcfrmOtherInfo[0] = 0x09;

    otidICC = new byte[UNCOMPRESSED_W_ENCODED_LENGTH];

    // This will hold:
    //  - Top 8 bytes of OTID_ICC
    //  - Top 16 bytes of card terminal's ephemeral public key.
    // However, it's length must also be divisible by AES_BLOCK_SIZE, to avoid
    // the AES CMAC signature object from throwing an error.
    short authCryptogramInputDataSize = (short)(8+16);
    if (authCryptogramInputDataSize % AES_BLOCK_SIZE != 0)
      authCryptogramInputDataSize +=
        AES_BLOCK_SIZE-(authCryptogramInputDataSize % AES_BLOCK_SIZE);
    authCryptogramInputData = new byte[authCryptogramInputDataSize];

    register();
  }

  public static void install(byte[] bArray, short bOffset, byte bLength) {
      new OpacityForwardSecrecyImplementationApplet();
  }

  public void process(APDU apdu) {
    byte[] buffer = apdu.getBuffer();

    if (!apdu.isISOInterindustryCLA()) {
      switch (buffer[ISO7816.OFFSET_INS]) {
        case GENERATE_KEY_PAIR:
          processGenerateKeyPair(apdu);
          break;
        case STORE_SIGNATURE:
          processStoreSignature(apdu);
          break;
        case CHECK_STORED_DATA:
          processCheckStoredData(apdu);
          break;
        case BASIC_AUTH:
          processBasicAuth(apdu);
          break;
        case INITIATE_AUTH:
          processInitiateAuthentication(apdu);
          break;
      }
    }
  }

  private void processGenerateKeyPair(APDU apdu) {
    byte[] buffer = apdu.getBuffer();

    // setOutgoing() will return L_e, the length of the expected response, and
    // should equal UNCOMPRESSED_W_ENCODED_LENGTH+KEY_PARAM_LENGTH_TAG (as we
    // send back our public key after generating a key pair).
    short expectedResponseLength = apdu.setOutgoing();
    if (expectedResponseLength != UNCOMPRESSED_W_ENCODED_LENGTH+KEY_PARAM_LENGTH_TAG)
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

    // Generate card key pair.
    cardKeyPair = new KeyPair(KEY_PAIR_ALGORITHM, KEY_LENGTH);
    Prime192v1.setKeyPairParameters(cardKeyPair);
    cardKeyPair.genKeyPair();

    apdu.setOutgoingLength((short)(UNCOMPRESSED_W_ENCODED_LENGTH+KEY_PARAM_LENGTH_TAG));
    // Fill APDU buffer with public key.
    short dataLen = Utils.encodeECPublicKey((ECPublicKey)cardKeyPair.getPublic(),
        buffer, (short)0);

    apdu.sendBytes((short)0, (short)(UNCOMPRESSED_W_ENCODED_LENGTH+KEY_PARAM_LENGTH_TAG));
  }

  private void processStoreSignature(APDU apdu) {
    byte[] buffer = apdu.getBuffer();
    short bOff = ISO7816.OFFSET_CDATA;

    // The first 56 bytes is the signature.
    Util.arrayCopyNonAtomic(buffer, bOff, cardSignature, (short)0,
        SIGNATURE_LENGTH);
    bOff += SIGNATURE_LENGTH;

    // The next group of bytes are the terminal's public key parameters.
    // First, create key object.
    terminalPublicKey = (ECPublicKey)KeyBuilder.buildKey(TERMINAL_KEY_TYPE,
        TERMINAL_KEY_LENGTH, false);
    Prime192v1.setKeyParameters((ECKey)terminalPublicKey);

    // Now initialize the parameters.
    bOff += Utils.decodeECPublicKey(terminalPublicKey, buffer, bOff);
    // The rest of the buffer contains the following length-encoded data (in this
    // order): CRSID, Group ID, Certificate Expiry (constant length - 4 bytes).
    // Group ID is the ID of the group that the student belongs to, i.e. some
    // combination of college and department.

    // CRSID
    short crsidLen = Util.getShort(buffer, bOff);
    bOff += 2;
    crsID = new byte[crsidLen];
    Util.arrayCopyNonAtomic(buffer, bOff, crsID, (short)0, crsidLen);
    bOff += crsidLen;

    // Group ID
    short groupIDLen = Util.getShort(buffer, bOff);
    bOff += 2;
    groupID = new byte[groupIDLen];
    Util.arrayCopyNonAtomic(buffer, bOff, groupID, (short)0, groupIDLen);
    bOff += groupIDLen;

    // Certificate Expiry
    Util.arrayCopyNonAtomic(buffer, bOff, certificateExpiry, (short)0,
        CERTIFICATE_EXPIRY_LENGTH);

    // We create this array early to speed up OPACITY-FS protocol execution time.
    // This is the certificate data that will be encrypted to produce what the
    // OPACITY spec calls OpaqueData_{ICC}.
    // The length of this array needs to be a multiple of the cipher block size.
    // Padding is just zeros (set implicitly when the array is initialized in
    // memory), since we know the length of the plaintext, so no need to encode
    // length of pad.
    // Will include:
    //  - card signature
    //  - card public key
    //  - CRSID
    //  - group ID
    //  - certificate expiry
    short certDataLen = (short)(SIGNATURE_LENGTH
      +UNCOMPRESSED_W_ENCODED_LENGTH+KEY_PARAM_LENGTH_TAG
      +crsID.length+KEY_PARAM_LENGTH_TAG
      +groupID.length+KEY_PARAM_LENGTH_TAG
      +CERTIFICATE_EXPIRY_LENGTH);
    short encryptedCertificateLength = certDataLen;
    if (certDataLen % AES_BLOCK_SIZE != 0)
      encryptedCertificateLength += AES_BLOCK_SIZE-(certDataLen % AES_BLOCK_SIZE);
    certificateData = new byte[encryptedCertificateLength];
    // Initialize the array to hold the encrypted certificate here as well.
    encryptedCertificate = new byte[encryptedCertificateLength];

    // Reset bOff.
    bOff = 0;

    // Card signature
    Util.arrayCopyNonAtomic(cardSignature, (short)0, certificateData, bOff,
        SIGNATURE_LENGTH);
    bOff += SIGNATURE_LENGTH;

    // Card public key
    bOff += Utils.encodeECPublicKey((ECPublicKey)cardKeyPair.getPublic(),
        buffer, bOff);

    // CRSID
    Util.setShort(certificateData, bOff, (short)crsID.length);
    bOff += 2;
    Util.arrayCopyNonAtomic(crsID, (short)0, certificateData, bOff,
        (short)crsID.length);
    bOff += crsID.length;

    // Group ID
    Util.setShort(certificateData, bOff, (short)groupID.length);
    bOff += 2;
    Util.arrayCopyNonAtomic(groupID, (short)0, certificateData, bOff,
        (short)groupID.length);
    bOff += groupID.length;

    // Certificate expiry
    Util.arrayCopyNonAtomic(certificateExpiry, (short)0, certificateData, bOff,
        CERTIFICATE_EXPIRY_LENGTH);
  }

  private void processCheckStoredData(APDU apdu) {
    // We just need to return all the things we stored during the STORE_SIGNATURE
    // instruction: signature, terminal's public key, CRSID, Group ID and certificate
    // expiry.
    byte[] buffer = apdu.getBuffer();

    apdu.setOutgoing();

    short dataLength = (short)(SIGNATURE_LENGTH +
      UNCOMPRESSED_W_ENCODED_LENGTH + KEY_PARAM_LENGTH_TAG + // terminal public key
      crsID.length + KEY_PARAM_LENGTH_TAG +
      groupID.length + KEY_PARAM_LENGTH_TAG +
      CERTIFICATE_EXPIRY_LENGTH);
    apdu.setOutgoingLength(dataLength);

    // Write signature.
    Util.arrayCopyNonAtomic(cardSignature, (short)0, buffer, (short)0,
        SIGNATURE_LENGTH);

    // Encode terminal's pubkey.
    short bOff = SIGNATURE_LENGTH;
    bOff += Utils.encodeECPublicKey(terminalPublicKey, buffer, bOff);

    // CRSID
    Util.setShort(buffer, bOff, (short)crsID.length);
    bOff += 2;
    Util.arrayCopyNonAtomic(crsID, (short)0, buffer, bOff, (short)crsID.length);
    bOff += (short)crsID.length;

    // Group ID
    Util.setShort(buffer, bOff, (short)groupID.length);
    bOff += 2;
    Util.arrayCopyNonAtomic(groupID, (short)0, buffer, bOff, (short)groupID.length);
    bOff += (short)groupID.length;

    // Certificate Expiry
    Util.arrayCopyNonAtomic(certificateExpiry, (short)0, buffer, bOff,
        CERTIFICATE_EXPIRY_LENGTH);

    apdu.sendBytes((short)0, dataLength);
  }

  /**
   * This is the basic auth protocol that I had to implement in order to satisfy
   * the "will authenticate in under 1 second" part of the project's success
   * criteria.
   *
   * This simple protocol works as follows:
   *  - The door sends a BASIC_AUTH command, with a nonce in the data field.
   *  - The card signs the nonce using its private key.
   *  - The card returns this signature, along with its public key, CRSID, group
   *  ID and certificate expiry and the signature of all this data.
   *  - The door checks the card's public key signature to ensure public key is
   *  valid, as well as checking it's not expired. Then door checks nonce signature,
   *  to ensure card has matching private key. Finally, door checks that the
   *  group ID has the correct bit set to access this specific door.
   */
  private void processBasicAuth(APDU apdu) {
    // In the basic authentication protocol, the data in the buffer is simply
    // a nonce that the card must sign using its EC private key (ECDSA).
    byte[] buffer = apdu.getBuffer();

    // The first 2 bytes in the buffer encode the byte length of the nonce.
    short nonceLength = Util.getShort(buffer, ISO7816.OFFSET_CDATA);

    ecdsaSignature.init(cardKeyPair.getPrivate(), Signature.MODE_SIGN);

    // Create array to hold signature.
    byte[] nonceSignature = new byte[SIGNATURE_LENGTH];

    // We add 2 to the offset here to skip over the 2-byte length parameter.
    ecdsaSignature.sign(buffer, (short)(ISO7816.OFFSET_CDATA+2), nonceLength,
        nonceSignature, (short)0);

    apdu.setOutgoing();

    short outgoingLength = (short)(nonceSignature.length+KEY_PARAM_LENGTH_TAG // signed nonce
        +SIGNATURE_LENGTH // card signature
        +UNCOMPRESSED_W_ENCODED_LENGTH+KEY_PARAM_LENGTH_TAG // card public key
        +crsID.length+KEY_PARAM_LENGTH_TAG // CRSID
        +groupID.length+KEY_PARAM_LENGTH_TAG // group ID
        +CERTIFICATE_EXPIRY_LENGTH);  // certificate expiry
    apdu.setOutgoingLength(outgoingLength);

    // We must return the following:
    // - signed nonce
    // - card signature
    // - card public key
    // - crsid
    // - group id
    // - certificate expiry
    short bOff = 0;

    Util.setShort(buffer, bOff, (short)nonceSignature.length);
    bOff += 2;
    Util.arrayCopyNonAtomic(nonceSignature, (short)0, buffer, bOff,
        SIGNATURE_LENGTH);
    bOff += SIGNATURE_LENGTH;

    Util.arrayCopyNonAtomic(cardSignature, (short)0, buffer, bOff,
        SIGNATURE_LENGTH);
    bOff += SIGNATURE_LENGTH;

    bOff += Utils.encodeECPublicKey((ECPublicKey) cardKeyPair.getPublic(),
        buffer, bOff);

    Util.setShort(buffer, bOff, (short)crsID.length);
    bOff += 2;
    Util.arrayCopyNonAtomic(crsID, (short)0, buffer, bOff,
        (short)crsID.length);
    bOff += crsID.length;

    Util.setShort(buffer, bOff, (short)groupID.length);
    bOff += 2;
    Util.arrayCopyNonAtomic(groupID, (short)0, buffer, bOff,
        (short)groupID.length);
    bOff += groupID.length;

    Util.arrayCopyNonAtomic(certificateExpiry, (short)0, buffer, bOff,
        (short)certificateExpiry.length);
    bOff += certificateExpiry.length;

    apdu.sendBytes((short)0, outgoingLength);
  }

  /**
   * Convenience method for returning the AUTHENTICATION_DENIED byte.
   */
  private void denyAuth(APDU apdu, byte[] buffer) {
    buffer[0] = AUTHENTICATION_DENIED;
    apdu.setOutgoingAndSend((short)0, (short)1);
  }

  /**
   * Derives a key of length ceil(length/h) where h is the length of the output
   * hash function that's used to build the key derivation function (KDF).
   * See https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-56ar.pdf
   * §5.8.1 for details of the concatenation key derivation function.
   *
   * @param keyDerivationKey the key to be used as part of the input message of
   *                         every hash that's computed
   * @param otherInfo        see https://www.securetechalliance.org/resources/pdf/OPACITY_Protocol_3.7.pdf
   *                         §7.0 Annex A (KDF Specifications) for details of what
   *                         "otherInfo" consists.
   * @param length           the desired length of the derived key
   * @param derivedKey       the buffer in which the derived key will be stored
   *                         - it's the job of the caller to ensure this buffer
   *                         is big enough (at least ceil(length/KDF_HASH_OUTPUT_SIZE
   *                         bytes).
   */
  private void deriveKey(byte[] keyDerivationKey, byte[] otherInfo, short length,
      byte[] derivedKey) {
    // SP 800-56A says counter needs to be 32-bit, so we'll just default the
    // first two bytes to 0x00.
    final short COUNTER_LENGTH = (short)4;

    // This is effectively calculating ceil(length / KDF_HASH_OUTPUT_SIZE).
    short remainder = (short)(length % KDF_HASH_OUTPUT_SIZE);
    short numBlocksToGenerate = (short)(length / KDF_HASH_OUTPUT_SIZE);
    if (remainder > 0) numBlocksToGenerate++;

    short offset = (short)0;
    byte[] msg = new byte[(short)(COUNTER_LENGTH+keyDerivationKey.length
        +otherInfo.length)];
    Util.arrayCopyNonAtomic(keyDerivationKey, (short)0, msg, COUNTER_LENGTH,
        (short)keyDerivationKey.length);
    Util.arrayCopyNonAtomic(otherInfo, (short)0, msg,
        (short)(COUNTER_LENGTH+keyDerivationKey.length), (short)otherInfo.length);
    for (short counter = (short)1; counter <= numBlocksToGenerate; counter++) {
      // Change the counter value in the hash input.
      Util.setShort(msg, (short)(COUNTER_LENGTH-2), counter);
      hashDigest.doFinal(msg, (short)0, (short)msg.length, derivedKey, offset);
      offset += KDF_HASH_OUTPUT_SIZE;
    }
  }

  private void processInitiateAuthentication(APDU apdu) {
    // Buffer will contain:
    //  - signature of door's pub key
    //  - door's permanent pub key
    //  - door's ephemeral pub key
    byte[] buffer = apdu.getBuffer();
    short bOff = ISO7816.OFFSET_CDATA + SIGNATURE_LENGTH;

    // First is the door's permanent public key
    bOff += Utils.decodeECPublicKey(doorPermanentPublicKey, buffer, bOff);

    // Lastly, the door's ephemeral public key
    try {
      Utils.decodeECPublicKey(doorEphemeralPublicKey, buffer, bOff);
    } catch (CryptoException e) {
      // This may well be because the provided point doesn't belong to the EC
      // domain, so we'll return AUTHENTICATION_DENIED.
      denyAuth(apdu, buffer);
      return;
    }

    /*
     * First major step is to verify the door's permanent public key/signature.
     */

    // Initialize the signature object.
    // TODO: Could potentially make this an instance variable an initialize it
    // during install if authentication time is an issue.
    ecdsaSignature.init(terminalPublicKey, Signature.MODE_VERIFY);

    // Get the encoding of the door's permanent public key.
    doorPermanentPublicKey.getW(signatureData, (short)0);

    // Rather than copy the door signature into a new byte array, we just get it
    // directly from the buffer - avoids wasting memory.
    boolean verified = ecdsaSignature.verify(signatureData, (short)0,
        (short)signatureData.length, buffer, ISO7816.OFFSET_CDATA,
        SIGNATURE_LENGTH);

    // Return AUTHENTICATION_DENIED byte if the signature failed verification.
    if (!verified) {
      denyAuth(apdu, buffer);
      return;
    }

    /*
     * Generate card key pair.
     */

    cardEphemeralKeyPair.genKeyPair();

    // Put card ephemeral public key into byte array for later use.
    ((ECPublicKey)cardEphemeralKeyPair.getPublic()).getW(otidICC, (short)0);

    /*
     * Derive Z1.
     */

    ecDiffieHellman.init(cardEphemeralKeyPair.getPrivate());
    ecDiffieHellman.generateSecret(buffer, (short)(ISO7816.OFFSET_CDATA
        +SIGNATURE_LENGTH+KEY_PARAM_LENGTH_TAG), UNCOMPRESSED_W_ENCODED_LENGTH,
        secretZ1, (short)0);

    /*
     * Derive K1, K2.
     */

    // See https://www.securetechalliance.org/resources/pdf/OPACITY_Protocol_3.7.pdf
    // Annex A for details of what otherInfo is. Briefly, it's the "algorithm ID"
    // of all the secret keys (this is 0x09 for AES 128-bit keys) concatenated
    // with the values passed to the info() method in the specification.
    // NOTE: we've omitted ID_sH.
    ((ECPublicKey)cardEphemeralKeyPair.getPublic()).getW(k1k2OtherInfo, (short)2);
    deriveKey(secretZ1, k1k2OtherInfo, (short)keysK1K2.length, keysK1K2);

    /*
     * Encrypt OpaqueData_ICC.
     */

    // Use K1 as the encryption key for encrypting OpaqueData_ICC (which is just
    // the card's certificate).
    certificateEncryptionKey.setKey(keysK1K2, (short)0);
    aesCipher.init(certificateEncryptionKey, Cipher.MODE_ENCRYPT);
    aesCipher.doFinal(certificateData, (short)0, (short)certificateData.length,
        encryptedCertificate, (short)0);

    /*
     * Derive Z.
     */

    ecDiffieHellman.init(cardKeyPair.getPrivate());
    ecDiffieHellman.generateSecret(buffer, (short)(ISO7816.OFFSET_CDATA
          +SIGNATURE_LENGTH+KEY_PARAM_LENGTH_TAG+UNCOMPRESSED_W_ENCODED_LENGTH
          +KEY_PARAM_LENGTH_TAG), UNCOMPRESSED_W_ENCODED_LENGTH, secretZ, (short)0);

    // Zeroize Z1,K1
    Util.arrayFillNonAtomic(secretZ1, (short)0, (short)secretZ1.length, (byte)0x00);
    Util.arrayFillNonAtomic(keysK1K2, (short)0, (short)(keysK1K2.length / 2), (byte)0x00);

    /*
     * Derive SK_CFRM.
     */

    // First, let's setup the "otherInfo" byte array.
    short skcfrmInfoOffset = 1;
    Util.arrayCopyNonAtomic(otidICC, (short)0, skcfrmOtherInfo, skcfrmInfoOffset,
        (short)8);
    skcfrmInfoOffset += 8;
    // We take directly from the buffer to avoid any unnecessary copying.
    // We've skipped over (in the buffer):
    //  - signature of door's public key
    //  - door's permanent public key + 2 byte length tag
    //  - 2 byte length tag for door's ephemeral public key
    // This leaves us right at the start of the door's ephemeral public key.
    Util.arrayCopyNonAtomic(buffer, (short)(ISO7816.OFFSET_CDATA
        + SIGNATURE_LENGTH
        + 2 + UNCOMPRESSED_W_ENCODED_LENGTH
        + 2),
        skcfrmOtherInfo, skcfrmInfoOffset, (short)16);
    skcfrmInfoOffset += 16;
    // K1 is from offsets 0 to (AES_KEY_SIZE - 1), so we need to skip over K1
    // to get to K2.
    Util.arrayCopyNonAtomic(keysK1K2, AES_KEY_SIZE, skcfrmOtherInfo, skcfrmInfoOffset,
        AES_KEY_SIZE);

    // Now actually derive the key.
    deriveKey(secretZ, skcfrmOtherInfo, (short)keySKCFRM.length, keySKCFRM);

    /*
     * Generate AuthCryptogram_ICC.
     */

    // Initialize the CMAC key.
    authCryptogramCMACKey.setKey(keySKCFRM, (short)0);

    // Setup the input data byte array.
    Util.arrayCopyNonAtomic(otidICC, (short)0, authCryptogramInputData, (short)0,
        (short)8);
    // We take directly from the buffer to avoid any unnecessary copying.
    // We've skipped over (in the buffer):
    //  - signature of door's public key
    //  - door's permanent public key + 2 byte length tag
    //  - 2 byte length tag for door's ephemeral public key
    // This leaves us right at the start of the door's ephemeral public key.
    Util.arrayCopyNonAtomic(buffer, (short)(ISO7816.OFFSET_CDATA
        + SIGNATURE_LENGTH
        + 2 + UNCOMPRESSED_W_ENCODED_LENGTH
        + 2),
        authCryptogramInputData, (short)8, (short)16);

    // We set the APDU to outgoing at this point, so that we can write the signature
    // directly to the outgoing buffer, in order to avoid an unnecessary copy.
    // The outgoing buffer contains:
    //  - OpaqueData_ICC
    //  - AuthCryptogram_ICC
    //  - OTID_ICC
    apdu.setOutgoing();
    apdu.setOutgoingLength((short)(encryptedCertificate.length
          + AES_CMAC_OUTPUT_SIZE
          + UNCOMPRESSED_W_ENCODED_LENGTH));
    Util.arrayCopyNonAtomic(encryptedCertificate, (short)0, buffer, (short)0,
        (short)encryptedCertificate.length);

    // Initiate CMAC signature object.
    aesCMACSignature.init(authCryptogramCMACKey, Signature.MODE_SIGN);
    aesCMACSignature.sign(authCryptogramInputData, (short)0,
        (short)authCryptogramInputData.length, buffer,
        (short)encryptedCertificate.length);

    ((ECPublicKey)cardEphemeralKeyPair.getPublic()).getW(buffer,
      (short)(encryptedCertificate.length + AES_CMAC_OUTPUT_SIZE));


    apdu.sendBytes((short)0, (short)(encryptedCertificate.length
          + AES_CMAC_OUTPUT_SIZE
          + UNCOMPRESSED_W_ENCODED_LENGTH));

    /*
     *buffer[0] = (byte)0xab;
     *buffer[1] = (byte)0xcd;
     *apdu.setOutgoingAndSend((short)0, (short)2);
     */
  }
}

/*
    apdu.setOutgoing();
    apdu.setOutgoingLength((short)2);

    } catch (CryptoException e) {
			buffer[0] = (byte) 0xE7;
			buffer[1] = (byte) e.getReason();
		} catch (SystemException se) {
			buffer[0] = (byte) 0xEF;
			buffer[1] = (byte) se.getReason();
		} catch (NullPointerException ne) {
			buffer[0] = (byte) 0xEE;
		} catch (CardRuntimeException cre) {
			buffer[0] = (byte) 0xED;
			buffer[1] = (byte) cre.getReason();
		} catch (ArithmeticException ae) {
			buffer[0] = (byte) 0xEC;
		} catch (ArrayIndexOutOfBoundsException aie) {
			buffer[0] = (byte) 0xEB;
		} catch (ArrayStoreException ase) {
			buffer[0] = (byte) 0xEA;
		} catch (ClassCastException cce) {
			buffer[0] = (byte) 0xEA;
		} catch (RuntimeException re) {
			buffer[0] = (byte) 0xE9;
		} catch (Exception ex) {
			buffer[0] = (byte) 0xE8;
		} finally {
			apdu.sendBytesLong(buffer, (short)0, (short)2);
      if (true) return;
		}
*/
