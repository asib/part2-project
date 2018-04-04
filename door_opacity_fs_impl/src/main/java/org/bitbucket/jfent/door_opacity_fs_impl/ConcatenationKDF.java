package org.bitbucket.jfent.door_opacity_fs_impl;

import static org.bitbucket.jfent.opacity_fs_impl.OpacityForwardSecrecyImplementationApplet.*;
import java.security.Provider;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.DigestException;
import java.nio.ByteBuffer;
import org.apache.commons.codec.binary.Hex;

public class ConcatenationKDF {
  final int COUNTER_LENGTH = 4;
  private MessageDigest hashDigest = null;

  public ConcatenationKDF(Provider provider) throws NoSuchAlgorithmException {
    hashDigest = MessageDigest.getInstance("MD5", provider);
  }

  /**
   * Write an integer to a byte array.
   *
   * @param value the value to be written to the byte array
   * @param array the array to which the value will be written
   * @param offset the offset into the array at which to begin writing the value
   */
  private void writeInt(int value, byte[] array, int offset) {
    byte[] valBytes = ByteBuffer.allocate(4).putInt(value).array();
    System.arraycopy(valBytes, 0, array, offset, 4);
  }

  public byte[] deriveKey(byte[] keyDerivationKey, byte[] otherInfo, int length)
    throws DigestException {
    // This is effectively calculating ceil(length / KDF_HASH_OUTPUT_SIZE).
    short remainder = (short)(length % KDF_HASH_OUTPUT_SIZE);
    short numBlocksToGenerate = (short)(length / KDF_HASH_OUTPUT_SIZE);
    if (remainder > 0) numBlocksToGenerate++;

    byte[] output = new byte[length];

    int offset = 0;
    byte[] msg = new byte[COUNTER_LENGTH+keyDerivationKey.length+otherInfo.length];
    System.arraycopy(keyDerivationKey, 0, msg, COUNTER_LENGTH, keyDerivationKey.length);
    System.arraycopy(otherInfo, 0, msg, COUNTER_LENGTH+keyDerivationKey.length,
        otherInfo.length);
    for (int counter = 1; counter <= numBlocksToGenerate; counter++) {
      // Change the counter value in the hash input.
      writeInt(counter, msg, 0);
      hashDigest.reset();
      hashDigest.update(msg);
      /*
       *if (counter == numBlocksToGenerate) {
       *  byte[] temp = new byte[KDF_HASH_OUTPUT_SIZE];
       *  hashDigest.digest(temp, 0, KDF_HASH_OUTPUT_SIZE);
       *  System.out.println(Hex.encodeHexString(temp));
       *  System.arraycopy(temp, 0, output, offset, remainder);
       *} else {
       */
      hashDigest.digest(output, offset, KDF_HASH_OUTPUT_SIZE);
      //}
      offset += KDF_HASH_OUTPUT_SIZE;
    }

    return output;
  }
}
