package org.bitbucket.jfent.card_terminal;

import org.apache.commons.cli.*;

public class CardTerminal {
  private static final String PROGRAM_NAME = "card_terminal";
  private static final String HELP_HEADER = "Provision and reprogram smart cards.";
  private static final boolean GENERATE_USAGE = true;

  public CardTerminal() {

  }

  public static void main(String[] args) {
    Options options = new Options();
    options.addOption(OptionBuilder.withLongOpt("help")
                                   .create("h"));
    options.addOption(OptionBuilder.withLongOpt("hello")
                                   .withDescription("Print hello")
                                   .create("he"));

    CommandLineParser parser = new DefaultParser();
    HelpFormatter formatter = new HelpFormatter();
    CommandLine cmd;

    try {
      cmd = parser.parse(options, args);
    } catch (ParseException e) {
      System.out.println(e.getMessage() + "\n");
      formatter.printHelp(PROGRAM_NAME, HELP_HEADER, options, null, GENERATE_USAGE);
      return;
    }

    if (cmd.hasOption("help"))
      formatter.printHelp(PROGRAM_NAME, HELP_HEADER, options, null, GENERATE_USAGE);
    else if (cmd.hasOption("hello"))
      System.out.println("Hello!");
  }
}
