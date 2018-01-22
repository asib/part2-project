package org.bitbucket.jfent.opacity_fs_impl;

import javacard.security.ECKey;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.CryptoException;
import javacard.framework.JCSystem;
import javacard.framework.Util;

public class Utils {
  public final static short LENGTH_TAG = OpacityForwardSecrecyImplementationApplet.KEY_PARAM_LENGTH_TAG;

  /**
   * Encodes the W parameter of an ECPublicKey as a byte array.
   *
   * @param pk     the ECPublicKey to be encoded
   * @param buffer the output buffer
   * @param bOff   the offset into the output buffer from which point the encoded data will be written
   * @return       the number of bytes written to buffer
   */
  public static short encodeECPublicKey(ECPublicKey pk, byte[] buffer, short bOff) {
    // W
    short lenW = pk.getW(buffer, (short)(bOff+2));
    Util.setShort(buffer, bOff, lenW);

    return (short)(lenW+LENGTH_TAG);
  }

  /**
   * Encodes the S parameter of an ECPrivateKey as a byte array.
   *
   * @param pk     the ECPrivateKey to be encoded
   * @param buffer the output buffer
   * @param bOff   the offset into the output buffer from which point the encoded data will be written
   * @return       the number of bytes written to buffer
   */
  public static short encodeECPrivateKey(ECPrivateKey pk, byte[] buffer, short bOff) {
    // S
    short lenS = pk.getS(buffer, (short)(bOff+2));
    Util.setShort(buffer, bOff, lenS);

    return (short)(lenS+LENGTH_TAG);
  }

  /**
   * Initializes the W parameter of the ECPublicKey with the value in the buffer,
   * starting from bOff.
   *
   * @param pk     the ECPublicKey to be initialized
   * @param buffer the buffer containing the encoded W parameter
   * @param bOff   the offset into the buffer from which point the W parameter is specified
   * @return       the number of bytes read from buffer
   */
  public static short decodeECPublicKey(ECPublicKey pk, byte[] buffer, short bOff) {
    // W
    short lenW = Util.getShort(buffer, bOff);
    bOff += LENGTH_TAG;
    pk.setW(buffer, bOff, lenW);

    return (short)(lenW+LENGTH_TAG);
  }

  /**
   * Initializes the ECPrivateKey with the parameters found in buffer, starting
   * from bOff.
   *
   * @param pk     the ECPrivateKey to be initialized
   * @param buffer the buffer containing the encoded S parameter
   * @param bOff   the offset into the buffer from which point the S parameter is specified
   * @return       the number of bytes read from buffer
   */
  public static short decodeECPrivateKey(ECPrivateKey pk, byte[] buffer, short bOff) {
    // S
    short lenS = Util.getShort(buffer, bOff);
    bOff += LENGTH_TAG;
    pk.setS(buffer, bOff, lenS);


    return (short)(lenS+LENGTH_TAG);
  }
}
