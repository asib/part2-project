package org.bitbucket.jfent.card_terminal;

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
    SELECT, GENERATE_KEY_PAIR
  }

  private static final byte[] AUTHENTICATION_APPLET_AID = {(byte)0xf2, (byte)0x34,
    (byte)0x12, (byte)0x34, (byte)0x56, (byte)0x10, (byte)0x10, (byte)0x00};

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
    ResponseAPDU resp = channel.transmit(new CommandAPDU(0x00, 0xa4, 0x04, 0x00,
          AUTHENTICATION_APPLET_AID));

    short sw = (short)resp.getSW();
    if (sw != ISO7816.SW_NO_ERROR)
      throw new CardCommunicationException(sw, Command.SELECT);
  }

  public byte[] sendGenerateKeyPairCommand() throws CardException,
         CardCommunicationException {
    ResponseAPDU resp = channel.transmit(new CommandAPDU(0x80, GENERATE_KEY_PAIR,
          0x00, 0x00, KEY_LENGTH));

    short sw = (short)resp.getSW();
    if (sw != ISO7816.SW_NO_ERROR)
      throw new CardCommunicationException(sw, Command.GENERATE_KEY_PAIR);

    // If all went well, return the public key to be signed by the card terminal
    // application.
    return resp.getData();
  }
}
