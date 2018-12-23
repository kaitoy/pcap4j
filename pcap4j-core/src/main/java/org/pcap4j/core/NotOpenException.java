/*_##########################################################################
  _##
  _##  Copyright (C) 2013  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.core;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.16
 */
public final class NotOpenException extends Exception {

  /** */
  private static final long serialVersionUID = -3852491522682861395L;

  /** */
  public NotOpenException() {
    super();
  }

  /** @param message message */
  public NotOpenException(String message) {
    super(message);
  }
}
