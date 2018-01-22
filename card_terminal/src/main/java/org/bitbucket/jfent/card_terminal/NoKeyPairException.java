package org.bitbucket.jfent.card_terminal;

public class NoKeyPairException extends Exception {
  public NoKeyPairException() {
    super("Couldn't load keys from file.");
  }
}
