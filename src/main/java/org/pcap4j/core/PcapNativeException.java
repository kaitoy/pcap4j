/*_##########################################################################
  _##
  _##  Copyright (C) 2011  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.core;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.1
 */
public final class PcapNativeException extends Exception {

  private static final long serialVersionUID = -6458526492950674556L;

  /**
   *
   */
  public PcapNativeException() {
    super();
  }

  /**
   *
   * @param message
   */
  public PcapNativeException(String message){
    super(message);
  }

  /**
   *
   * @param message
   * @param cause
   */
  public PcapNativeException(String message, Throwable cause){
      super(message, cause);
  }

  /**
   *
   * @param cause
   */
  public PcapNativeException(Throwable cause){
      super(cause);
  }

}
