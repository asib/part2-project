package org.bitbucket.jfent.opacity_fs_impl;

import javacard.framework.Applet;
import javacard.framework.APDU;
import javacard.framework.Util;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.security.KeyBuilder;
import javacard.security.ECPublicKey;
import javacard.security.KeyPair;

public class OpacityForwardSecrecyImplementationApplet extends Applet {
  /*
   *
   * Constants
   *
   */
  public final static byte GENERATE_KEY_PAIR = (byte)0x01; // INS byte for generating key pair.
  public final static byte STORE_SIGNATURE = (byte)0x02;   // INS byte for storing the terminal's signature.
  public final static byte CHECK_STORED_DATA = (byte)0x03; // INS byte for checking data was stored correctly after STORE_SIGNATURE instruction.
  public final static byte TERMINAL_KEY_TYPE = KeyBuilder.TYPE_EC_FP_PUBLIC;
  public final static short TERMINAL_KEY_LENGTH = KeyBuilder.LENGTH_EC_FP_192;
  /*
   * When we transmit EC keys, we have to transmit a byte array of parameters.
   * Since each parameter may not necessarily be of fixed length (e.g. if we change
   * the key length), we need to allow for variable length parameters. Thus, each
   * parameter is prefixed by a 2-byte length parameter.
   */
  public final static short KEY_PARAM_LENGTH_TAG = (short)2;
  /*
   * In order to transmit an EC public key, we have to transmit 6 parameters:
   * W, A, B, G, R, Field.
   */
  public final static short KEY_NUM_PARAMS = (short)6;
  public final static byte KEY_PAIR_ALGORITHM = KeyPair.ALG_EC_FP;
  public final static byte CARD_PUBLIC_KEY_TYPE = KeyBuilder.TYPE_EC_FP_PUBLIC;
  public final static short KEY_LENGTH = KeyBuilder.LENGTH_EC_FP_192;
  public final static short SIGNATURE_LENGTH = (short)20; // ALG_ECDSA_SHA produces 20 byte signature.
  // Expiry is stored in Unix time (an unsigned 32 bit integer, representing number
  // of seconds after 00:00:00 01/01/1970.
  public final static short CERTIFICATE_EXPIRY_LENGTH = (short)4;

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
      }
    }
  }

  private void processGenerateKeyPair(APDU apdu) {
    byte[] buffer = apdu.getBuffer();

    // setOutgoing() will return L_e, the length of the expected response, and
    // should equal KEY_LENGTH (as we send back our public key after generating
    // a key pair).
    short expectedResponseLength = apdu.setOutgoing();
    if (expectedResponseLength != KEY_LENGTH)
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

    // Generate card key pair.
    cardKeyPair = new KeyPair(KEY_PAIR_ALGORITHM, KEY_LENGTH);
    //Prime192v1.setKeyPairParameters(cardKeyPair);
    cardKeyPair.genKeyPair();

    apdu.setOutgoingLength(KEY_LENGTH);
    // Fill APDU buffer with public key.
    short dataLen = Utils.encodeECPublicKey((ECPublicKey)cardKeyPair.getPublic(),
        buffer, (short)0);

    //apdu.setOutgoingAndSend((short)0, dataLen);
    apdu.sendBytes((short)0, KEY_LENGTH);
  }

  private void processStoreSignature(APDU apdu) {
    byte[] buffer = apdu.getBuffer();

    // The first 20 bytes is the signature
    Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CDATA, cardSignature, (short)0,
        SIGNATURE_LENGTH);

    // The next group of bytes are the terminal's public key parameters.
    // First, create key object.
    terminalPublicKey = (ECPublicKey)KeyBuilder.buildKey(TERMINAL_KEY_TYPE,
        TERMINAL_KEY_LENGTH, false);

    // Now initialize the parameters.
    short bytesRead = Utils.decodeECPublicKey(terminalPublicKey, buffer,
        SIGNATURE_LENGTH);


    short bOff = (short)(SIGNATURE_LENGTH+bytesRead);
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
      TERMINAL_KEY_LENGTH + (KEY_PARAM_LENGTH_TAG*KEY_NUM_PARAMS) +
      crsID.length +
      groupID.length +
      CERTIFICATE_EXPIRY_LENGTH);
    apdu.setOutgoingLength(dataLength);

    // Write signature.
    Util.arrayCopyNonAtomic(cardSignature, (short)0, buffer, (short)0,
        SIGNATURE_LENGTH);

    // Encode terminal's pubkey.
    short bOff = 20;
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
}
