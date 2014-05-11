/*_##########################################################################
  _##
  _##  Copyright (C) 2013-2014  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory;

import static org.pcap4j.util.ByteArrays.*;
import org.pcap4j.packet.IpV6Packet.IpV6FlowLabel;
import org.pcap4j.packet.IpV6SimpleFlowLabel;
import org.pcap4j.packet.namednumber.NA;
import org.pcap4j.util.ByteArrays;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.16
 */
public final class StaticIpV6FlowLabelFactory
implements PacketFactory<IpV6FlowLabel, NA> {

  private static final StaticIpV6FlowLabelFactory INSTANCE
    = new StaticIpV6FlowLabelFactory();

  /**
   *
   * @return the singleton instance of StaticIpV6FlowLabelFactory.
   */
  public static StaticIpV6FlowLabelFactory getInstance() {
    return INSTANCE;
  }

  public IpV6FlowLabel newInstance(byte[] rawData, NA number) {
    return newInstance(rawData);
  }

  public IpV6FlowLabel newInstance(byte[] rawData) {
    if (rawData == null) {
      StringBuilder sb = new StringBuilder(40);
      sb.append("rawData: ")
        .append(rawData);
      throw new NullPointerException(sb.toString());
    }
    if (rawData.length < INT_SIZE_IN_BYTES) {
      throw new IllegalArgumentException(
              "rawData is too short: " + ByteArrays.toHexString(rawData, " ")
            );
    }

    return IpV6SimpleFlowLabel.newInstance(ByteArrays.getInt(rawData, 0));
  }

}
