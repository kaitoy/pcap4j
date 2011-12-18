/*_##########################################################################
  _##
  _##  Copyright (C) 2011  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.core;

public final class PcapNativeException extends Exception {

  private static final long serialVersionUID = -6458526492950674556L;

  public PcapNativeException(String message){
    super(message);
  }

  public PcapNativeException(String message, Throwable cause){
      super(message, cause);
  }

  public PcapNativeException(Throwable cause){
      super(cause);
  }

  public PcapNativeException() {
    super();
  }

}
