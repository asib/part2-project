package org.bitbucket.jfent.opacity_fs_impl;

import javacard.security.ECKey;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.framework.JCSystem;
import javacard.framework.Util;

public class Utils {
  public final static short LENGTH_TAG = OpacityForwardSecrecyImplementationApplet.KEY_PARAM_LENGTH_TAG;
  public final static short NUM_PARAMS = OpacityForwardSecrecyImplementationApplet.KEY_NUM_PARAMS;

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
  public static short encodeECPublicKey(ECPublicKey pk, byte[] buffer, short bOff) {
    // W
    short lenW = pk.getW(buffer, (short)2);
    Util.setShort(buffer, (short)0, lenW);

    return (short)(lenW+LENGTH_TAG);
  }

  /**
   * Encodes the ECPrivateKey as a byte array. The format of the array is as follows:
   * <p>
   * The fields appear in the following order: S, A, B, G, R, Field. Each field
   * is preceded by a 2-byte length parameter, which tells the recipient how many
   * bytes long each key parameter will be.
   *
   * @param pk     the ECPrivateKey to be encoded
   * @param buffer the output buffer
   * @param bOff   the offset into the output buffer at which point the encoded data will be written from
   * @return       the number of bytes written to buffer
   */
  public static short encodeECPrivateKey(ECPrivateKey pk, byte[] buffer, short bOff) {
    // S
    short lenS = pk.getS(buffer, (short)2);
    Util.setShort(buffer, (short)0, lenS);

    return (short)(lenS+LENGTH_TAG);
  }

  /**
   * Helper method that initializes the parameters of an EC key that are common
   * to both the public and private forms.
   *
   * @param k      the ECKey to be initialized
   * @param buffer the buffer containing the parameters for use in initialization
   * @param bOff   the offset into the buffer at which point the parameters are specified
   * @return       the number of bytes read from buffer
   */
  public static short decodeECKeyCommon(ECKey k, byte[] buffer, short bOff) {
    // A
    short lenA = Util.getShort(buffer, bOff);
    bOff += LENGTH_TAG;
    k.setA(buffer, bOff, lenA);
    bOff += lenA;

    // B
    short lenB = Util.getShort(buffer, bOff);
    bOff += LENGTH_TAG;
    k.setB(buffer, bOff, lenB);
    bOff += lenB;

    // G
    short lenG = Util.getShort(buffer, bOff);
    bOff += LENGTH_TAG;
    k.setG(buffer, bOff, lenG);
    bOff += lenG;

    // R
    short lenR = Util.getShort(buffer, bOff);
    bOff += LENGTH_TAG;
    k.setR(buffer, bOff, lenR);
    bOff += lenR;

    // Field
    short lenField = Util.getShort(buffer, bOff);
    bOff += LENGTH_TAG;
    k.setFieldFP(buffer, bOff, lenField);

    return (short)(lenA+lenB+lenG+lenR+lenField+((NUM_PARAMS-1)*LENGTH_TAG));
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

    short lenCommonDecodedParams = decodeECKeyCommon(pk, buffer, bOff);

    return (short)(lenW+LENGTH_TAG+lenCommonDecodedParams);
  }

  /**
   * Initializes the ECPrivateKey with the parameters found in buffer, starting
   * from bOff.
   *
   * @param pk     the ECPrivateKey to be initialized
   * @param buffer the buffer containing the parameters for use in initialization
   * @param bOff   the offset into the buffer at which point the parameters are specified
   * @return       the number of bytes read from buffer
   */
  public static short decodeECPrivateKey(ECPrivateKey pk, byte[] buffer, short bOff) {
    // The params are in the order S, A, B, G, R, Field, within the array.
    // W
    short lenS = Util.getShort(buffer, bOff);
    bOff += LENGTH_TAG;
    pk.setS(buffer, bOff, lenS);
    bOff += lenS;

    short lenCommonDecodedParams = decodeECKeyCommon(pk, buffer, bOff);

    return (short)(lenS+LENGTH_TAG+lenCommonDecodedParams);
  }
}
