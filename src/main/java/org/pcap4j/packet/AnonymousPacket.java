/*_##########################################################################
  _##
  _##  Copyright (C) 2011  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import org.pcap4j.util.ByteArrays;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.1
 */
public final class AnonymousPacket extends AbstractPacket {

  private final byte[] rawData;

  /**
   *
   * @param rawData
   */
  public AnonymousPacket(byte[] rawData) {
    if (rawData == null) {
      throw new NullPointerException();
    }
    byte[] copy = new byte[rawData.length];
    System.arraycopy(rawData, 0, copy, 0, copy.length);
    this.rawData = rawData;
  }

  @Override
  public Header getHeader() { return null; }

  @Override
  public Packet getPayload() { return null; }

  @Override
  public boolean isValid() { return true; }

  @Override
  public int length() { return rawData.length; }

  @Override
  public byte[] getRawData() {
    byte[] copy = new byte[rawData.length];
    System.arraycopy(rawData, 0, copy, 0, copy.length);
    return copy;
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();

    sb.append("[data (")
      .append(length())
      .append(" bytes)]\n");

    sb.append("  Hex stream: ")
      .append(ByteArrays.toHexString(rawData, " "))
      .append("\n");

    return sb.toString();
  }
}
