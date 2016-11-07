/*_##########################################################################
  _##
  _##  Copyright (C) 2013-2016  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory;

import java.io.ObjectStreamException;

import org.pcap4j.packet.IllegalIpV6Option;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.IpV6ExtOptionsPacket.IpV6Option;
import org.pcap4j.packet.IpV6Pad1Option;
import org.pcap4j.packet.IpV6PadNOption;
import org.pcap4j.packet.UnknownIpV6Option;
import org.pcap4j.packet.namednumber.IpV6OptionType;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.16
 */
public final class StaticIpV6OptionFactory implements PacketFactory<IpV6Option, IpV6OptionType> {

  private static final StaticIpV6OptionFactory INSTANCE = new StaticIpV6OptionFactory();

  private StaticIpV6OptionFactory() {}

  /**
   * @return the singleton instance of StaticIpV6OptionFactory.
   */
  public static StaticIpV6OptionFactory getInstance() {
    return INSTANCE;
  }

  @Override
  public IpV6Option newInstance(
    byte[] rawData, int offset, int length, IpV6OptionType... numbers
  ) {
    if (rawData == null) {
      throw new NullPointerException("rawData is null.");
    }

    try {
      for (IpV6OptionType num: numbers) {
        switch (Byte.toUnsignedInt(num.value())) {
          case 0:
            return IpV6Pad1Option.newInstance(rawData, offset, length);
          case 1:
            return IpV6PadNOption.newInstance(rawData, offset, length);
        }
      }
      return UnknownIpV6Option.newInstance(rawData, offset, length);
    } catch (IllegalRawDataException e) {
      return IllegalIpV6Option.newInstance(rawData, offset, length, e);
    }
  }

  // Override deserializer to keep singleton
  @SuppressWarnings("static-method")
  private Object readResolve() throws ObjectStreamException {
    return INSTANCE;
  }

}
