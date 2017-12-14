package org.bitbucket.jfent.opacity_fs_impl;

import javacard.security.ECPublicKey;
import javacard.framework.JCSystem;
import javacard.framework.Util;

public class Utils {
  /**
   * Encodes the ECPublicKey as a byte array. The format of the array is as follows:
   * <p>
   * The fields appear in the following order: W, A, B, G, R, Field. Each field
   * is preceded by a 2-byte length parameter, which tells the recipient how many
   * bytes long each key parameter will be.
   *
   * @param pk     the ECPublicKey to be encoded
   * @param buffer the output buffer
   * @param bOff   the offset into the output buffer at which point the encoded data will be written from
   * @return       the number of bytes written to buffer
   */

  private final static short LENGTH_TAG = OpacityForwardSecrecyImplementationApplet.KEY_PARAM_LENGTH_TAG;
  private final static short NUM_PARAMS = OpacityForwardSecrecyImplementationApplet.KEY_NUM_PARAMS;
  public static short encodeECPublicKey(ECPublicKey pk, byte[] buffer, short bOff) {
    // W
    short lenW = pk.getW(buffer, (short)(bOff+LENGTH_TAG));
    bOff += lenW;
    Util.setShort(buffer, (short)(bOff-lenW), lenW);
    bOff += LENGTH_TAG;

    // A
    short lenA = pk.getA(buffer, (short)(bOff+LENGTH_TAG));
    bOff += lenA;
    Util.setShort(buffer, (short)(bOff-lenA), lenA);
    bOff += LENGTH_TAG;

    // B
    short lenB = pk.getB(buffer, (short)(bOff+LENGTH_TAG));
    bOff += lenB;
    Util.setShort(buffer, (short)(bOff-lenB), lenB);
    bOff += LENGTH_TAG;

    // G
    short lenG = pk.getG(buffer, (short)(bOff+LENGTH_TAG));
    bOff += lenG;
    Util.setShort(buffer, (short)(bOff-lenG), lenG);
    bOff += LENGTH_TAG;

    // R
    short lenR = pk.getR(buffer, (short)(bOff+LENGTH_TAG));
    bOff += lenR;
    Util.setShort(buffer, (short)(bOff-lenR), lenR);
    bOff += LENGTH_TAG;

    // Field
    short lenField = pk.getField(buffer, (short)(bOff+LENGTH_TAG));
    bOff += lenField;
    Util.setShort(buffer, (short)(bOff-lenField), lenField);
    bOff += LENGTH_TAG;

    return (short)(lenW+lenA+lenB+lenG+lenR+lenField+(LENGTH_TAG*NUM_PARAMS));
  }

  /**
   * Initializes the ECPublicKey with the parameters found in buffer, starting
   * from bOff.
   *
   * @param pk     the ECPublicKey to be initialized
   * @param buffer the buffer containing the parameters for use in initialization
   * @param bOff   the offset into the buffer at which point the parameters are specified
   * @return       the number of bytes read from buffer
   */
  public static short decodeECPublicKey(ECPublicKey pk, byte[] buffer, short bOff) {
    // The params are in the order W, A, B, G, R, Field, within the array.
    // W
    short lenW = Util.getShort(buffer, bOff);
    bOff += LENGTH_TAG;
    pk.setW(buffer, bOff, lenW);
    bOff += lenW;

    // A
    short lenA = Util.getShort(buffer, bOff);
    bOff += LENGTH_TAG;
    pk.setA(buffer, bOff, lenA);
    bOff += lenA;

    // B
    short lenB = Util.getShort(buffer, bOff);
    bOff += LENGTH_TAG;
    pk.setB(buffer, bOff, lenB);
    bOff += lenB;

    // G
    short lenG = Util.getShort(buffer, bOff);
    bOff += LENGTH_TAG;
    pk.setG(buffer, bOff, lenG);
    bOff += lenG;

    // R
    short lenR = Util.getShort(buffer, bOff);
    bOff += LENGTH_TAG;
    pk.setR(buffer, bOff, lenR);
    bOff += lenR;

    // Field
    short lenField = Util.getShort(buffer, bOff);
    bOff += LENGTH_TAG;
    pk.setFieldFP(buffer, bOff, lenField);

    return (short)(lenW+lenA+lenB+lenG+lenR+lenField+(LENGTH_TAG*NUM_PARAMS));
  }
}
