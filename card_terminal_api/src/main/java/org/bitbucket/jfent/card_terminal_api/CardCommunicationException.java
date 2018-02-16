package org.bitbucket.jfent.card_terminal_api;

public class CardCommunicationException extends Exception {
  public CardCommunicationException(int sw, CardTerminalAPI.Command c) {
    super("Received status word '" + sw + "' during command " + c.name());
  }
}
