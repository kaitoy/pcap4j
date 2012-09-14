/*_##########################################################################
  _##
  _##  Copyright (C) 2012  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.11
 */
public final class IllegalRawDataException extends RuntimeException {


  /**
   *
   */
  private static final long serialVersionUID = -765629349654704179L;

  /**
   *
   */
  public IllegalRawDataException() {
    super();
  }

  /**
   *
   * @param message
   */
  public IllegalRawDataException(String message){
    super(message);
  }

  /**
   *
   * @param message
   * @param cause
   */
  public IllegalRawDataException(String message, Throwable cause){
      super(message, cause);
  }

  /**
   *
   * @param cause
   */
  public IllegalRawDataException(Throwable cause){
      super(cause);
  }

}
