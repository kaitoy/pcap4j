/*_##########################################################################
  _##
  _##  Copyright (C) 2012-2014  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.11
 */
public final class IllegalRawDataException extends Exception {

  /** */
  private static final long serialVersionUID = -6426401494142677707L;

  /** */
  public IllegalRawDataException() {
    super();
  }

  /** @param message message */
  public IllegalRawDataException(String message) {
    super(message);
  }

  /**
   * @param message message
   * @param cause cause
   */
  public IllegalRawDataException(String message, Throwable cause) {
    super(message, cause);
  }

  /** @param cause cause */
  public IllegalRawDataException(Throwable cause) {
    super(cause);
  }
}
