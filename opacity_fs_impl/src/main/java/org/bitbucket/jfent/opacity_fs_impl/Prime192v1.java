package org.bitbucket.jfent.opacity_fs_impl;

import javacard.security.ECKey;
import javacard.security.ECPublicKey;
import javacard.security.ECPrivateKey;
import javacard.security.KeyPair;
import javacard.security.KeyBuilder;

public class Prime192v1 {
  private static final byte[] field = {(byte)0xff, (byte)0xff, (byte)0xff,
    (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff,
    (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff,
    (byte)0xfe, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff,
    (byte)0xff, (byte)0xff, (byte)0xff};
  private static final byte[] a = {(byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff,
    (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff,
    (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xfe,
    (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff,
    (byte)0xff, (byte)0xfc};
  private static final byte[] b = {(byte)0x64, (byte)0x21, (byte)0x05, (byte)0x19,
    (byte)0xe5, (byte)0x9c, (byte)0x80, (byte)0xe7, (byte)0x0f, (byte)0xa7,
    (byte)0xe9, (byte)0xab, (byte)0x72, (byte)0x24, (byte)0x30, (byte)0x49,
    (byte)0xfe, (byte)0xb8, (byte)0xde, (byte)0xec, (byte)0xc1, (byte)0x46,
    (byte)0xb9, (byte)0xb1};
  private static final byte[] G = {(byte)0x04, (byte)0x18, (byte)0x8d, (byte)0xa8,
    (byte)0x0e, (byte)0xb0, (byte)0x30, (byte)0x90, (byte)0xf6, (byte)0x7c,
    (byte)0xbf, (byte)0x20, (byte)0xeb, (byte)0x43, (byte)0xa1, (byte)0x88,
    (byte)0x00, (byte)0xf4, (byte)0xff, (byte)0x0a, (byte)0xfd, (byte)0x82,
    (byte)0xff, (byte)0x10, (byte)0x12, (byte)0x07, (byte)0x19, (byte)0x2b,
    (byte)0x95, (byte)0xff, (byte)0xc8, (byte)0xda, (byte)0x78, (byte)0x63,
    (byte)0x10, (byte)0x11, (byte)0xed, (byte)0x6b, (byte)0x24, (byte)0xcd,
    (byte)0xd5, (byte)0x73, (byte)0xf9, (byte)0x77, (byte)0xa1, (byte)0x1e,
    (byte)0x79, (byte)0x48, (byte)0x11};
  private static final byte[] r = {(byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff,
    (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff,
    (byte)0xff, (byte)0xff, (byte)0x99, (byte)0xde, (byte)0xf8, (byte)0x36,
    (byte)0x14, (byte)0x6b, (byte)0xc9, (byte)0xb1, (byte)0xb4, (byte)0xd2,
    (byte)0x28, (byte)0x31};
  private static final byte k = (short)0x1;

  public static void setKeyPairParameters(KeyPair kp) {
    ECPrivateKey privKey = (ECPrivateKey)kp.getPrivate();
    ECPublicKey pubKey = (ECPublicKey)kp.getPublic();

    setKeyParameters(privKey);
    setKeyParameters(pubKey);
  }

  public static void setKeyParameters(ECKey key) {
    key.setFieldFP(field, (short)0, (short)field.length);
    key.setA(a, (short)0, (short)a.length);
    key.setB(b, (short)0, (short)b.length);
    key.setG(G, (short)0, (short)G.length);
    key.setR(r, (short)0, (short)r.length);
    key.setK(k);
  }
}
