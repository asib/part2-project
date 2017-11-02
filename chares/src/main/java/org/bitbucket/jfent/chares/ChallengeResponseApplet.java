package org.bitbucket.jfent.chares;

import javacard.framework.Applet;
import javacard.framework.APDU;
import javacard.framework.Util;
import javacard.framework.ISO7816;

public class ChallengeResponseApplet extends Applet {
  /*
   *
   * Constants
   *
   */
  final static byte CHALLENGE = (byte)0x01; // INS byte for Challenge
  final static byte CHALLENGE_LENGTH = (short)8; // Number of bytes in the challenge


  private ChallengeResponseApplet() {
    register();
  }

  public static void install(byte[] bArray, short bOffset, byte bLength) {
    new ChallengeResponseApplet();
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

    // Reverse buffer data
    for (byte i = 0; i < (CHALLENGE_LENGTH/2); i++) {
      // XOR swap algorithm - avoids using a temp local variable.
      buffer[ISO7816.OFFSET_CDATA+i] = (byte)(buffer[ISO7816.OFFSET_CDATA+i] ^ buffer[ISO7816.OFFSET_CDATA+(CHALLENGE_LENGTH-1)-i]);
      buffer[ISO7816.OFFSET_CDATA+(CHALLENGE_LENGTH-1)-i] = (byte)(buffer[ISO7816.OFFSET_CDATA+i] ^ buffer[ISO7816.OFFSET_CDATA+(CHALLENGE_LENGTH-1)-i]);
      buffer[ISO7816.OFFSET_CDATA+i] = (byte)(buffer[ISO7816.OFFSET_CDATA+i] ^ buffer[ISO7816.OFFSET_CDATA+(CHALLENGE_LENGTH-1)-i]);
    }

    apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, (short)CHALLENGE_LENGTH);
  }
}
