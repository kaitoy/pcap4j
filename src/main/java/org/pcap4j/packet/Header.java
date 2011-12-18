/*_##########################################################################
  _##
  _##  Copyright (C) 2011  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

public interface Header {

  public void validate();
  public boolean isValid();
  public int length();
  public byte[] getRawData();
  public String toHexString();

}
