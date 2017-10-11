// --------------------------------------------------------------------------- 
// Protocol for Lightweight Authentication of Identity (PLAID)
// 
// SAM applet
// 
// Reference Implementation compliant with AS 5185 - Javacard 2.x source code
// 
// --------------------------------------------------------------------------- 
// This implementation: © Copyright Australian Government
// PLAID: © Copyright Australian Government
// 
// A copy of the entire Licence is available upon email request from 
// plaid@humanservices.gov.au or by download from https://www.plaid.gov.au 
// 
// Subject to the terms of the Licence, the Australian Government grants to 
// the User a perpetual, irrevocable, world-wide, non-exclusive, royalty free and 
// no-charge licence to use, reproduce, adapt, modify, enhance, communicate, 
// sub-license and distribute PLAID and/or its source code. Clause 2.1 includes 
// the right to incorporate PLAID into any Product developed by the User.
// 
// By using PLAID and/or its source code you agree to be bound by the Licence.
// 
// ---------------------------------------------------------------------------
// Status: Prototype 0.804
// Issue Date: October 2011
// 
// Author: Glenn Mitchell (Australian Government)

package sam804;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*; 

public class SAM804 extends Applet
{
  //INS constants
  static final byte INS_INITIAL_AUTHENTICATE  =(byte)0x8A;
  static final byte INS_FINAL_AUTHENTICATE    =(byte)0x8C;
  static final byte INS_SET_DATA              =(byte)0xDB;
  
  //P1 constants
  static final byte P1_P        = (byte)0x01;
  static final byte P1_Q        = (byte)0x02;
  static final byte P1_DP1      = (byte)0x03;
  static final byte P1_DQ1      = (byte)0x04;
  static final byte P1_PQ       = (byte)0x05;
  static final byte P1_FAKEY    = (byte)0x06;
  static final byte P1_KEYSETID = (byte)0x10;
  
  //Offsets
  static final short OFFSET_KEYSETID             =(short)0;
  static final short OFFSET_KEYSET_INDEX         =(short)1;
  static final short OFFSET_VALUE                =(short)5;
  static final short OFFSET_DIVERSIFICATION_DATA =(short)2;
  static final short OFFSET_OPMODE               =(short)8;
  static final short OFFSET_DIVERSIFIED_KEY      =(short)42;
  
  //Length Constants
  static final short LENGTH_P                =(short)64;
  static final short LENGTH_Q                =(short)64;
  static final short LENGTH_DP1              =(short)64;
  static final short LENGTH_DQ1              =(short)64;
  static final short LENGTH_PQ               =(short)64;
  static final short LENGTH_CURRENT_SESSION  =(short)2;
  static final short LENGTH_KEYSETID         =(short)2;
  static final short LENGTH_BUFFER16         =(short)16;
  static final short LENGTH_BUFFER128        =(short)128;
  static final short LENGTH_RSA1024          =(short)128;
  static final short LENGTH_OPMODE           =(short)2;
  static final short LENGTH_DIVERSIFICATION_DATA =(short)8;
  static final short LENGTH_AES_BLOCK        =(short)16;
  static final short LENGTH_AES_KEY          =(short)16;
  
  //Misc      
  static final short TOTAL_KEYSETS          = (short)8;
  static final byte NULL_VALUE              = (byte)0x00;
  static final byte[] NULL_ARRAY            = {0x00,0x00};
  static final byte[] OPMODE                = {0x00,0x00};
  static final byte COMMAND_VALUE   = (byte)0x80;
  
  //Persistant objects
  private final byte[] keyData               = new byte[(short)(TOTAL_KEYSETS*2)];
  private final RSAPrivateCrtKey[] IAKey     = new RSAPrivateCrtKey[TOTAL_KEYSETS];
  private final AESKey[] FAKey               = new AESKey[TOTAL_KEYSETS];
  private final Cipher AESCipher;
  private final Cipher RSACipher;
  private final MessageDigest SHA1;
  private final RandomData rnd;
  
  //Transient objects
  private final byte[] currentSession;
  private final byte[] Buffer16;
  private final byte[] Buffer128;
  private final AESKey transientKey;
  
  private SAM804() 
  { 
    currentSession=JCSystem.makeTransientByteArray(LENGTH_CURRENT_SESSION,
      JCSystem.CLEAR_ON_RESET);
    Buffer16=JCSystem.makeTransientByteArray(LENGTH_BUFFER16,
      JCSystem.CLEAR_ON_RESET);
    Buffer128=JCSystem.makeTransientByteArray(LENGTH_BUFFER128,
      JCSystem.CLEAR_ON_RESET);
    Util.arrayFillNonAtomic(keyData,(short)0,(short)(TOTAL_KEYSETS*2),
      NULL_VALUE);
    AESCipher=Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD,false);
    RSACipher=Cipher.getInstance(Cipher.ALG_RSA_PKCS1,false);
    for (short Index=0;Index<TOTAL_KEYSETS;Index++)
    {
      IAKey[Index]=(RSAPrivateCrtKey)KeyBuilder.buildKey(
        KeyBuilder.TYPE_RSA_CRT_PRIVATE,KeyBuilder.LENGTH_RSA_1024,false);
      FAKey[Index]=(AESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_AES, 
        KeyBuilder.LENGTH_AES_128,false);
    }
    transientKey=(AESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_AES, 
      KeyBuilder.LENGTH_AES_128,false);
    SHA1 = MessageDigest.getInstance(MessageDigest.ALG_SHA,false);
    rnd=RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
    
  }
 
  /**
  * <b>Description</b><p>
  * This method registers this applet instance with ICC's JCRE.
  */
  public static void install(byte[] params, short offset, byte length) 
    throws ISOException
  {
    (new SAM804()).register(params,(short)(offset+1),params[offset]);
  }
  
  
  public void process(APDU apdu)
  {
    if (selectingApplet())
      return;  
    
    byte[] APDUBuffer=apdu.getBuffer(); 
    short length = apdu.setIncomingAndReceive();
    switch (APDUBuffer[ISO7816.OFFSET_INS])
    {
      case INS_INITIAL_AUTHENTICATE:
        short keysToTry = (short)((short)(length-LENGTH_RSA1024)/LENGTH_KEYSETID);
        short ciphertextStart = (short)(OFFSET_VALUE+(keysToTry*2));
        for (short i=0;i<keysToTry;i++)
        {
          Util.arrayCopyNonAtomic(APDUBuffer,(short)(OFFSET_VALUE+(short)(i*2)),
            currentSession,OFFSET_KEYSETID,LENGTH_KEYSETID);
          for (short j=0;j<TOTAL_KEYSETS;j++)
          {
            if (Util.arrayCompare(currentSession,OFFSET_KEYSETID,keyData,
              (short)(j*2),LENGTH_KEYSETID)==0)
            {
              try
              {
                RSACipher.init(IAKey[j],Cipher.MODE_DECRYPT);  
                RSACipher.doFinal(APDUBuffer,ciphertextStart,LENGTH_RSA1024,
                  Buffer128,(short)0);
                if (Util.arrayCompare(Buffer128,(short)(LENGTH_OPMODE+
                  LENGTH_DIVERSIFICATION_DATA),Buffer128,(short)(LENGTH_OPMODE+
                  LENGTH_DIVERSIFICATION_DATA+LENGTH_AES_KEY),LENGTH_AES_KEY)==0)
                {
                  Util.arrayFillNonAtomic(Buffer128,(short)(short)(LENGTH_OPMODE+
                    LENGTH_DIVERSIFICATION_DATA),LENGTH_DIVERSIFICATION_DATA,
                    NULL_VALUE);
                  AESCipher.init(FAKey[j],Cipher.MODE_ENCRYPT);
                  AESCipher.doFinal(Buffer128,OFFSET_DIVERSIFICATION_DATA,
                    LENGTH_AES_BLOCK,Buffer128,OFFSET_DIVERSIFIED_KEY);
                  transientKey.setKey(Buffer128,OFFSET_DIVERSIFIED_KEY);
                  AESCipher.init(transientKey,Cipher.MODE_ENCRYPT);
                  rnd.generateData(Buffer128,(short)((short)(LENGTH_AES_KEY*2)+
                    LENGTH_DIVERSIFICATION_DATA+LENGTH_OPMODE),LENGTH_AES_KEY);
                  SHA1.doFinal(Buffer128,(short)(LENGTH_OPMODE+
                    LENGTH_DIVERSIFICATION_DATA+LENGTH_AES_KEY),(short)
                    (LENGTH_AES_KEY*2),Buffer128,(short)((LENGTH_AES_KEY*3)+
                    LENGTH_DIVERSIFICATION_DATA+LENGTH_OPMODE));
                  Util.arrayCopyNonAtomic(Buffer128,(short)((LENGTH_AES_KEY*3)+
                    LENGTH_DIVERSIFICATION_DATA+LENGTH_OPMODE),Buffer16,
                    (short)0,LENGTH_AES_BLOCK);
                  Util.arrayCopyNonAtomic(OPMODE,(short)0,Buffer128,(short)
                    (LENGTH_DIVERSIFICATION_DATA+((short)LENGTH_AES_KEY*2)),
                    LENGTH_OPMODE);
                  AESCipher.doFinal(Buffer128,(short)(LENGTH_DIVERSIFICATION_DATA+
                    ((short)LENGTH_AES_KEY*2)),(short)(LENGTH_AES_BLOCK*3),
                    APDUBuffer,(short)0);
                  apdu.setOutgoingAndSend((short)0,(short)(LENGTH_AES_BLOCK*3));
                  return;
                }
                else
                  ISOException.throwIt(ISO7816.SW_DATA_INVALID);//RND1s mismatch 
              }
              catch (CryptoException ex)
              {
              }
            }
          }
        }
        ISOException.throwIt(ISO7816.SW_FILE_INVALID);
      case INS_FINAL_AUTHENTICATE:
        transientKey.setKey(Buffer16,(short)0);
        AESCipher.init(transientKey,Cipher.MODE_DECRYPT);
        AESCipher.doFinal(APDUBuffer,ISO7816.OFFSET_CDATA,LENGTH_AES_BLOCK,
          APDUBuffer,LENGTH_AES_BLOCK);
        if (Util.arrayCompare(Buffer128,(short)2,APDUBuffer,(short)16,
          LENGTH_DIVERSIFICATION_DATA)==0)
        {
          APDUBuffer[23] = COMMAND_VALUE; 
          apdu.setOutgoingAndSend((short)23,(short)9);
          return;
        }
        else
          ISOException.throwIt(ISO7816.SW_DATA_INVALID);
      case INS_SET_DATA: 
        switch (APDUBuffer[ISO7816.OFFSET_P1])
        {
          case P1_KEYSETID:
            Util.arrayCopyNonAtomic(APDUBuffer,OFFSET_VALUE,currentSession,
              OFFSET_KEYSETID,LENGTH_KEYSETID);
            for (short i=0;i<TOTAL_KEYSETS;i++)
            {
              if ((Util.arrayCompare(currentSession,OFFSET_KEYSETID,keyData,
                (short)(i*2),LENGTH_KEYSETID)==0)||(Util.arrayCompare(keyData,
                (short)(i*2),NULL_ARRAY,(short)0,LENGTH_KEYSETID)==0))
              {
                Util.arrayCopy(currentSession,OFFSET_KEYSETID,keyData,
                  (short)(i*2),LENGTH_KEYSETID);
                currentSession[OFFSET_KEYSET_INDEX] = (byte)i; 
                return;  
              }
            }
            ISOException.throwIt(ISO7816.SW_FILE_FULL);
          case P1_P:
            IAKey[currentSession[OFFSET_KEYSET_INDEX]].setP(APDUBuffer,
              OFFSET_VALUE,LENGTH_P);
            return;
          case P1_Q:
            IAKey[currentSession[OFFSET_KEYSET_INDEX]].setQ(APDUBuffer,
              OFFSET_VALUE,LENGTH_Q);
            return;
          case P1_PQ:
            IAKey[currentSession[OFFSET_KEYSET_INDEX]].setPQ(APDUBuffer,
              OFFSET_VALUE,LENGTH_PQ);
            return;
          case P1_DP1:
            IAKey[currentSession[OFFSET_KEYSET_INDEX]].setDP1(APDUBuffer,
              OFFSET_VALUE,LENGTH_DP1);
            return;
          case P1_DQ1:
            IAKey[currentSession[OFFSET_KEYSET_INDEX]].setDQ1(APDUBuffer,
              OFFSET_VALUE,LENGTH_DQ1);
            return;
          case P1_FAKEY:
            Util.arrayCopy(APDUBuffer,OFFSET_VALUE,Buffer16,(short)0,
              LENGTH_BUFFER16);
            FAKey[currentSession[OFFSET_KEYSET_INDEX]].setKey(Buffer16,
              (short)0);
            return;
          default:
            ISOException.throwIt(ISO7816.SW_FILE_INVALID);
          
        }
      default: 
        ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
    }
  }
  
}