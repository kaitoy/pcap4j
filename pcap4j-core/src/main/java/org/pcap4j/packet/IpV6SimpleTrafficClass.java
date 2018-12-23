/*_##########################################################################
  _##
  _##  Copyright (C) 2011-2012  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import org.pcap4j.packet.IpV6Packet.IpV6TrafficClass;
import org.pcap4j.util.ByteArrays;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.1
 */
public final class IpV6SimpleTrafficClass implements IpV6TrafficClass {

  /** */
  private static final long serialVersionUID = -5076935770045999373L;

  private final byte value;

  /**
   * @param value value
   * @return a new IpV6SimpleTrafficClass object.
   */
  public static IpV6SimpleTrafficClass newInstance(byte value) {
    return new IpV6SimpleTrafficClass(value);
  }

  private IpV6SimpleTrafficClass(byte value) {
    this.value = value;
  }

  public byte value() {
    return value;
  }

  @Override
  public String toString() {
    return "0x" + ByteArrays.toHexString(value, "");
  }

  @Override
  public boolean equals(Object obj) {
    if (obj == this) {
      return true;
    }
    if (!this.getClass().isInstance(obj)) {
      return false;
    }
    return (getClass().cast(obj)).value() == this.value;
  }

  @Override
  public int hashCode() {
    return value;
  }
}
