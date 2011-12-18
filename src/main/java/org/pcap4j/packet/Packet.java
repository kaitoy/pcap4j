/*_##########################################################################
  _##
  _##  Copyright (C) 2011  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

public interface Packet extends Iterable<Packet> {

  // public Packet(byte[] rawData);
  public Header getHeader();
  public void setHeader();
  public Packet getPayload();
  public void setPayload(Packet payload);
  public void validate();
  public boolean isValid();
  public int length();
  public byte[] getRawData();
  public <T extends Packet> T get(Class<T> clazz);
  public <T extends Packet> boolean contains(Class<T> clazz);

}
