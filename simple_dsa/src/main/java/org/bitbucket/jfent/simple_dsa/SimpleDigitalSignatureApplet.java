package org.bitbucket.jfent.simple_dsa;

import javacard.framework.Applet;
import javacard.framework.APDU;
import javacard.framework.Util;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.SystemException;
import javacard.security.KeyBuilder;
import javacard.security.AESKey;
import javacard.security.CryptoException;
import javacardx.crypto.Cipher;

public class SimpleDigitalSignatureApplet extends Applet {
  /*
   *
   * Constants
   *
   */
  final static byte GENERATE_DSA_KEY_PAIR = (byte)0x01; // INS byte for Challenge

  /*
   *
   * Instance variables
   *
   */
  private AESKey key;
  private Cipher cipher;
  // Need somewhere to put the output of encryption/decryption.
  private byte[] cipherOutput;

  private SimpleDigitalSignatureApplet() {
    key = (AESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_AES,
        KeyBuilder.LENGTH_AES_128, false);
    key.setKey(KEY_DATA, (short)0);
    cipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);

    cipherOutput = JCSystem.makeTransientByteArray(EXPECTED_CHALLENGE_LENGTH,
        JCSystem.CLEAR_ON_DESELECT);

    register();
  }

  public static void install(byte[] bArray, short bOffset, byte bLength) {
      new SimpleDigitalSignatureApplet();
  }

  public void process(APDU apdu) {
    byte[] buffer = apdu.getBuffer();

    if (!apdu.isISOInterindustryCLA()) {
      switch (buffer[ISO7816.OFFSET_INS]) {
        case CHALLENGE:
          processChallenge(apdu);
          break;
      }
    }
  }

  private void processChallenge(APDU apdu) {
    byte[] buffer = apdu.getBuffer();

    short unreadChallengeBytes = buffer[ISO7816.OFFSET_LC];
    if (unreadChallengeBytes != EXPECTED_CHALLENGE_LENGTH)
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

    apdu.setIncomingAndReceive();

    // Setup the cipher to be in encryption mode.
    try {
      cipher.init(key, Cipher.MODE_ENCRYPT);
      cipher.doFinal(buffer, ISO7816.OFFSET_CDATA, EXPECTED_CHALLENGE_LENGTH,
          cipherOutput, (short)0);
    } catch (CryptoException e) {
      ISOException.throwIt(e.getReason());
    }
    Util.arrayCopyNonAtomic(cipherOutput, (short)0, buffer, (short)0,
        EXPECTED_CIPHER_LENGTH);

    apdu.setOutgoingAndSend((short)0, EXPECTED_CIPHER_LENGTH);
  }
}
