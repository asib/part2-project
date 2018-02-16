package org.bitbucket.jfent.card_terminal_api;

import javax.smartcardio.TerminalFactory;
import javax.smartcardio.CardTerminals;
import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import static org.bitbucket.jfent.opacity_fs_impl.OpacityForwardSecrecyImplementationApplet.*;

public class CardTerminalAPI {
  public enum Command {
    SELECT, GENERATE_KEY_PAIR, STORE_SIGNATURE, CHECK_STORED_DATA, INITIATE_AUTH
  }

  private static final byte[] AUTHENTICATION_APPLET_AID = {(byte)0xf2, (byte)0x34,
    (byte)0x12, (byte)0x34, (byte)0x56, (byte)0x10, (byte)0x10, (byte)0x00};

  private static final int MAX_EXPECTED_CRSID_LENGTH = 0xf; // total guess
  private static final int MAX_EXPECTED_GROUPID_LENGTH = 0xf; // total guess

  private Card card;
  private CardChannel channel;

  /**
   * Connect to the card via the reader.
   */
  private CardChannel connect() throws CardException {
    TerminalFactory terminalFactory = TerminalFactory.getDefault();
    CardTerminals terminals = terminalFactory.terminals();
    javax.smartcardio.CardTerminal terminal = terminals.list().get(0);
    card = terminal.connect("T=0");
    return card.getBasicChannel();
  }

  public void close() {
    try {
      card.disconnect(true);
    } catch (CardException e) {
      System.out.println("Error when attempting to disconnect card:");
      System.out.println(e.getMessage());
    }
  }


  /**
   * Create a new CardTerminalAPI object, and establish a communication channel
   * with the card.
   */
  public CardTerminalAPI() throws CardException {
    channel = connect();
  }

  /**
   *  Send the SELECT command APDU in order to select the authentication applet.
   */
  public void selectAuthenticationApplet() throws CardException,
         CardCommunicationException {
    ResponseAPDU resp = channel.transmit(new CommandAPDU(ISO7816.CLA_ISO7816,
          ISO7816.INS_SELECT, 0x04, 0x00,
          AUTHENTICATION_APPLET_AID));

    short sw = (short)resp.getSW();
    if (sw != ISO7816.SW_NO_ERROR)
      throw new CardCommunicationException(sw, Command.SELECT);
  }

  public byte[] sendGenerateKeyPairCommand() throws CardException,
         CardCommunicationException {
    ResponseAPDU resp = channel.transmit(new CommandAPDU(CLA_PROPRIETARY,
          GENERATE_KEY_PAIR, 0x00, 0x00,
          UNCOMPRESSED_W_ENCODED_LENGTH+KEY_PARAM_LENGTH_TAG));

    short sw = (short)resp.getSW();
    if (sw != ISO7816.SW_NO_ERROR)
      throw new CardCommunicationException(sw, Command.GENERATE_KEY_PAIR);

    // If all went well, return the public key to be signed by the card terminal
    // application.
    return resp.getData();
  }

  public void sendStoreSignatureCommand(byte[] data) throws CardException,
         CardCommunicationException {
    ResponseAPDU resp = channel.transmit(new CommandAPDU(CLA_PROPRIETARY,
          STORE_SIGNATURE, 0x00, 0x00, data));

    short sw = (short)resp.getSW();
    if (sw != ISO7816.SW_NO_ERROR)
      throw new CardCommunicationException(sw, Command.STORE_SIGNATURE);
  }

  public byte[] sendCheckStoredDataCommand() throws CardException,
         CardCommunicationException {
    ResponseAPDU resp = channel.transmit(new CommandAPDU(CLA_PROPRIETARY,
          CHECK_STORED_DATA, 0x00, 0x00, SIGNATURE_LENGTH
          +UNCOMPRESSED_W_ENCODED_LENGTH+KEY_PARAM_LENGTH_TAG
          +MAX_EXPECTED_CRSID_LENGTH+KEY_PARAM_LENGTH_TAG
          +MAX_EXPECTED_GROUPID_LENGTH+KEY_PARAM_LENGTH_TAG
          +CERTIFICATE_EXPIRY_LENGTH));

    short sw = (short)resp.getSW();
    if (sw != ISO7816.SW_NO_ERROR)
      throw new CardCommunicationException(sw, Command.CHECK_STORED_DATA);

    return resp.getData();
  }

  public byte[] sendInitiateAuthenticationCommand(byte[] data) throws CardException,
         CardCommunicationException {
    // Response will contain:
    //  - card ephemeral public key
    //  - AES-encrypted card public key + signature
    //
    //  The length of the AES-encrypted chunk will be a multiple of the block
    //  size, according to the following calculation:
    final int EXPECTED_UNENCRYPTED_CHUNK_LENGTH = SIGNATURE_LENGTH
      +UNCOMPRESSED_W_ENCODED_LENGTH+KEY_PARAM_LENGTH_TAG;
    final int EXPECTED_ENCRYPTED_CHUNK_LENGTH = EXPECTED_UNENCRYPTED_CHUNK_LENGTH
      +(AES_BLOCK_SIZE-(EXPECTED_UNENCRYPTED_CHUNK_LENGTH % AES_BLOCK_SIZE));
    final int EXPECTED_INITIATE_AUTH_RESPONSE_LENGTH =
       UNCOMPRESSED_W_ENCODED_LENGTH+KEY_PARAM_LENGTH_TAG
      +EXPECTED_ENCRYPTED_CHUNK_LENGTH;

    ResponseAPDU resp = channel.transmit(new CommandAPDU(CLA_PROPRIETARY,
          INITIATE_AUTH, 0x00, 0x00, data, EXPECTED_INITIATE_AUTH_RESPONSE_LENGTH));

    short sw = (short)resp.getSW();
    if (sw != ISO7816.SW_NO_ERROR)
      throw new CardCommunicationException(sw, Command.INITIATE_AUTH);

    return resp.getData();
  }
}
