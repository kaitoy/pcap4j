/*_##########################################################################
  _##
  _##  Copyright (C) 2013  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.core;

/**
 * @author Luca Barze
 * @since pcap4j 1.7.2
 */
public final class LengthZeroException extends RuntimeException {

  /**
   *
   */
  private static final long serialVersionUID = -3228133427989686165L;

  /**
   *
   */
  public LengthZeroException() {
    super();
  }

  /**
   *
   * @param message message
   */
  public LengthZeroException(String message){
    super(message);
  }

}
