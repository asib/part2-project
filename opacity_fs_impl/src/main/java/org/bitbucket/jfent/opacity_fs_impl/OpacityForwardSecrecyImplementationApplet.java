package org.bitbucket.jfent.opacity_fs_impl;

import javacard.framework.Applet;
import javacard.framework.APDU;
import javacard.framework.Util;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.security.KeyBuilder;
import javacard.security.ECKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyPair;
import javacard.security.Signature;
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
  public static final byte INITIATE_AUTH = (byte)0x04; // INS byte for initiating the authentication protocol.
  public static final byte TERMINAL_KEY_TYPE = KeyBuilder.TYPE_EC_FP_PUBLIC;
  public static final short TERMINAL_KEY_LENGTH = KeyBuilder.LENGTH_EC_FP_192;
  public static final byte DOOR_KEY_TYPE = KeyBuilder.TYPE_EC_FP_PUBLIC;
  public static final short DOOR_KEY_LENGTH = KeyBuilder.LENGTH_EC_FP_192;
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
  // 0x80 is 128 bits.
  public static final short AES_BLOCK_SIZE = (short)0x80;
  public static final byte AES_BLOCK_CIPHER = Cipher.ALG_AES_BLOCK_128_CBC_NOPAD;

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

  private OpacityForwardSecrecyImplementationApplet() {
    terminalPublicKey = null;
    cardKeyPair = null;
    // This needs to be persistently stored.
    cardSignature = new byte[SIGNATURE_LENGTH];
    certificateExpiry = new byte[CERTIFICATE_EXPIRY_LENGTH];

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

  private void processInitiateAuthentication(APDU apdu) {
    // Buffer will contain:
    //  - signature of door's pub key
    //  - door's permanent pub key
    //  - door's ephemeral pub key
    byte[] buffer = apdu.getBuffer();
    short bOff = ISO7816.OFFSET_CDATA + SIGNATURE_LENGTH;

    // Next is the door's permanent public key
    ECPublicKey doorPermanentPublicKey = (ECPublicKey)KeyBuilder.buildKey(
        DOOR_KEY_TYPE, DOOR_KEY_LENGTH, false);
    Prime192v1.setKeyParameters((ECKey)doorPermanentPublicKey);

    // Now initialize the parameters.
    bOff += Utils.decodeECPublicKey(doorPermanentPublicKey, buffer, bOff);

    // Finally, the door's ephemeral public key
    ECPublicKey doorEphemeralPublicKey = (ECPublicKey)KeyBuilder.buildKey(
        DOOR_KEY_TYPE, DOOR_KEY_LENGTH, false);
    Prime192v1.setKeyParameters((ECKey)doorEphemeralPublicKey);

    // Now initialize the parameters.
    Utils.decodeECPublicKey(doorEphemeralPublicKey, buffer, bOff);

    /*
     * First major step is to verify the door's permanent public key/signature.
     */

    // Initialize the signature object.
    // TODO: Could potentially make this an instance variable an initialize it
    // during install if authentication time is an issue.
    Signature verifyDoorKey = Signature.getInstance(Signature.ALG_ECDSA_SHA, false);
    verifyDoorKey.init(terminalPublicKey, Signature.MODE_VERIFY);

    // Get the encoding of the door's permanent public key.
    byte[] signatureData = new byte[UNCOMPRESSED_W_ENCODED_LENGTH];
    doorPermanentPublicKey.getW(signatureData, (short)0);

    // Rather than copy the door signature into a new byte array, we just get it
    // directly from the buffer - avoids wasting memory.
    boolean verified = verifyDoorKey.verify(signatureData, (short)0,
        (short)signatureData.length, buffer, ISO7816.OFFSET_CDATA,
        SIGNATURE_LENGTH);

    if (!verified) {
      ISOException.throwIt((short)0xf);
    }
  }
}
