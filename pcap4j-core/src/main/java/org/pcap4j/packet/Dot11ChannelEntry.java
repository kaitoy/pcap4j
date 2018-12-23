/*_##########################################################################
  _##
  _##  Copyright (C) 2016  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import java.io.Serializable;

/**
 * IEEE802.11 Channel Entry field
 *
 * <pre style="white-space: pre;">
 *         1               1
 * +---------------+---------------+
 * |Operating Class|    Channel    |
 * +---------------+---------------+
 * </pre>
 *
 * @see <a href="http://standards.ieee.org/getieee802/download/802.11-2012.pdf">IEEE802.11</a>
 * @author Kaito Yamada
 * @since pcap4j 1.7.0
 */
public final class Dot11ChannelEntry implements Serializable {

  /** */
  private static final long serialVersionUID = -1866907693281185049L;

  private final byte operatingClass;
  private final byte channel;

  /**
   * @param operatingClass operatingClass
   * @param channel channel
   */
  public Dot11ChannelEntry(byte operatingClass, byte channel) {
    this.operatingClass = operatingClass;
    this.channel = channel;
  }

  /** @return operatingClass */
  public byte getOperatingClass() {
    return operatingClass;
  }

  /** @return operatingClass */
  public int getOperatingClassAsInt() {
    return operatingClass & 0xFF;
  }

  /** @return channel */
  public byte getChannel() {
    return channel;
  }

  /** @return channel */
  public int getChannelAsInt() {
    return channel & 0xFF;
  }

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + channel;
    result = prime * result + operatingClass;
    return result;
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) return true;
    if (obj == null) return false;
    if (getClass() != obj.getClass()) return false;
    Dot11ChannelEntry other = (Dot11ChannelEntry) obj;
    if (channel != other.channel) return false;
    if (operatingClass != other.operatingClass) return false;
    return true;
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();

    sb.append("[Operating Class: ")
        .append(getOperatingClassAsInt())
        .append(", Channel: ")
        .append(getChannelAsInt())
        .append("]");

    return sb.toString();
  }
}
