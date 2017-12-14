package org.bitbucket.jfent.card_terminal;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.DecoderException;
import javax.smartcardio.TerminalFactory;
import javax.smartcardio.CardTerminals;
import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;

public class CardTerminal {
  private static final String PROGRAM_NAME = "card_terminal";
  private static final String HELP_HEADER = "Provision and reprogram smart cards.";
  private static final String PROVISION_COMMAND = "provision";
  private static final String LIST_COMMAND = "list";
  private static final String ALLOWED_HEX_CHARS = "0123456789abcdef";

  private static class InvalidGroupIDLengthException extends Exception {}
  private static class InvalidGroupIDContentException extends Exception {}

  public CardTerminal() {

  }

  private static void printHelp() {
    System.out.println("usage: " + PROGRAM_NAME + " [<flags>] <command> [<args>]");
    System.out.println();
    System.out.println(HELP_HEADER);
    System.out.println();
    System.out.println("Flags:");
    System.out.println("  -h,--help\tShow help.");
    System.out.println();
    System.out.println("Commands:");
    System.out.println("  provision <crsid> <group id> <expiry>");
    System.out.println("    Provision a smart card with the provided CRSID, group ID and certificate expiry.");
    System.out.println();
    System.out.println("  list");
    System.out.println("    List the details stored on the smart card, i.e. CRSID, group ID, certificate expiry");
    System.out.println();
  }

  private static CardChannel connect() throws CardException {
    TerminalFactory terminalFactory = TerminalFactory.getDefault();
    CardTerminals terminals = terminalFactory.terminals();
    javax.smartcardio.CardTerminal terminal = terminals.list().get(0);
    Card card = terminal.connect("T=0");
    return card.getBasicChannel();
  }

  private static void provision(String crsID, byte[] groupID,
      byte[] certificateExpiry) throws CardException {
    CardChannel channel = connect();
  }

  private static void list() {
  }

  private static byte[] parseGroupID(String rawGrpID) throws DecoderException {
    return Hex.decodeHex(rawGrpID);
  }

  private static byte[] parseCertificateExpiry(String rawExpiry) throws DecoderException {
    return Hex.decodeHex(rawExpiry);
  }

  public static void main(String[] args) {
    if (args.length == 0) {
      printHelp();
      return;
    } else if (args[0].equals(PROVISION_COMMAND)) {
      if (args.length != 4) {
        printHelp();
        return;
      }

      String crsID = args[1];
      byte[] groupID;
      byte[] certificateExpiry;
      try {
        groupID = parseGroupID(args[2]);
      } catch (DecoderException e) {
        System.out.println("Group ID must be a hexadecimal value (without preceding '0x', no spaces).");
        return;
      }
      try {
        certificateExpiry = parseCertificateExpiry(args[3]);
      } catch (DecoderException e) {
        System.out.println("Certificate expiry must be a hexadecimal value (without preceding '0x', no spaces).");
        return;
      }

      try {
      provision(crsID, groupID, certificateExpiry);
      } catch (CardException e) {
        System.out.println("Couldn't connect to card.");
        System.out.println("Please ensure that a reader is connected, and that a card is within range of the reader.");
        return;
      }
    } else if (args[0].equals(LIST_COMMAND)) {
      if (args.length != 1) {
        printHelp();
        return;
      }

      list();
    } else {
      printHelp();
      return;
    }
  }
}
