/*_##########################################################################
  _##
  _##  Copyright (C) 2011-2014  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import org.pcap4j.packet.IpV6Packet.IpV6FlowLabel;
import org.pcap4j.util.ByteArrays;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.1
 */
public final class IpV6SimpleFlowLabel implements IpV6FlowLabel {

  /** */
  private static final long serialVersionUID = -5076935770045999373L;

  private final int value;

  /**
   * @param value value
   * @return a new IpV6SimpleFlowLabel object.
   */
  public static IpV6SimpleFlowLabel newInstance(int value) {
    return new IpV6SimpleFlowLabel(value);
  }

  private IpV6SimpleFlowLabel(int value) {
    this.value = value & 0x000FFFFF;
  }

  @Override
  public int value() {
    return value;
  }

  @Override
  public String toString() {
    return "0x" + ByteArrays.toHexString(value, "").substring(3);
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
