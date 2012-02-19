/*_##########################################################################
  _##
  _##  Copyright (C) 2012  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.5
 */
public final class IllegalPacketDataException extends RuntimeException {


  /**
   *
   */
  private static final long serialVersionUID = -765629349654704179L;

  /**
   *
   */
  public IllegalPacketDataException() {
    super();
  }

  /**
   *
   * @param message
   */
  public IllegalPacketDataException(String message){
    super(message);
  }

  /**
   *
   * @param message
   * @param cause
   */
  public IllegalPacketDataException(String message, Throwable cause){
      super(message, cause);
  }

  /**
   *
   * @param cause
   */
  public IllegalPacketDataException(Throwable cause){
      super(cause);
  }

}
