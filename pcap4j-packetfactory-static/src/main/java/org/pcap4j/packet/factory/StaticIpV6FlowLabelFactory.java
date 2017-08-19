/*_##########################################################################
  _##
  _##  Copyright (C) 2013-2017  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory;

import org.pcap4j.packet.IpV6Packet.IpV6FlowLabel;
import org.pcap4j.packet.IpV6SimpleFlowLabel;
import org.pcap4j.packet.namednumber.NotApplicable;
import org.pcap4j.util.ByteArrays;

import static org.pcap4j.util.ByteArrays.INT_SIZE_IN_BYTES;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.16
 */
public final class StaticIpV6FlowLabelFactory
implements PacketFactory<IpV6FlowLabel, NotApplicable> {

  private static final StaticIpV6FlowLabelFactory INSTANCE = new StaticIpV6FlowLabelFactory();

  private StaticIpV6FlowLabelFactory() {}

  /**
   * @return the singleton instance of StaticIpV6FlowLabelFactory.
   */
  public static StaticIpV6FlowLabelFactory getInstance() {
    return INSTANCE;
  }

  /**
   * This method is a variant of {@link #newInstance(byte[], int, int, NotApplicable...)}
   * and exists only for performance reason.
   *
   * @param rawData see {@link PacketFactory#newInstance}.
   * @param offset see {@link PacketFactory#newInstance}.
   * @param length see {@link PacketFactory#newInstance}.
   * @return see {@link PacketFactory#newInstance}.
   */
  public IpV6FlowLabel newInstance(byte[] rawData, int offset, int length) {
    ByteArrays.validateBounds(rawData, offset, length);
    if (length < INT_SIZE_IN_BYTES) {
      StringBuilder sb = new StringBuilder(100);
      sb.append("rawData is too short: ")
        .append(ByteArrays.toHexString(rawData, " "))
        .append(", offset: ")
        .append(offset)
        .append(", length: ")
        .append(length);
      throw new IllegalArgumentException(sb.toString());
    }

    return IpV6SimpleFlowLabel.newInstance(ByteArrays.getInt(rawData, offset));
  }

  @Override
  public IpV6FlowLabel newInstance(
    byte[] rawData, int offset, int length, NotApplicable... numbers
  ) {
    ByteArrays.validateBounds(rawData, offset, length);
    if (length < INT_SIZE_IN_BYTES) {
      StringBuilder sb = new StringBuilder(100);
      sb.append("rawData is too short: ")
        .append(ByteArrays.toHexString(rawData, " "))
        .append(", offset: ")
        .append(offset)
        .append(", length: ")
        .append(length);
      throw new IllegalArgumentException(sb.toString());
    }

    return IpV6SimpleFlowLabel.newInstance(ByteArrays.getInt(rawData, offset));
  }

}
