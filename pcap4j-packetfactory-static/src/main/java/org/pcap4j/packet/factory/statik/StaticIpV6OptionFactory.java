/*_##########################################################################
  _##
  _##  Copyright (C) 2013-2019 Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory.statik;

import java.util.HashMap;
import java.util.Map;
import org.pcap4j.packet.IllegalIpV6Option;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.IpV6ExtOptionsPacket.IpV6Option;
import org.pcap4j.packet.IpV6Pad1Option;
import org.pcap4j.packet.IpV6PadNOption;
import org.pcap4j.packet.UnknownIpV6Option;
import org.pcap4j.packet.factory.PacketFactory;
import org.pcap4j.packet.namednumber.IpV6OptionType;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.16
 */
public final class StaticIpV6OptionFactory implements PacketFactory<IpV6Option, IpV6OptionType> {

  private static final StaticIpV6OptionFactory INSTANCE = new StaticIpV6OptionFactory();
  private final Map<IpV6OptionType, Instantiater> instantiaters =
      new HashMap<IpV6OptionType, Instantiater>();

  private StaticIpV6OptionFactory() {
    instantiaters.put(
        IpV6OptionType.PAD1,
        new Instantiater() {
          @Override
          public IpV6Option newInstance(byte[] rawData, int offset, int length)
              throws IllegalRawDataException {
            return IpV6Pad1Option.newInstance(rawData, offset, length);
          }

          @Override
          public Class<IpV6Pad1Option> getTargetClass() {
            return IpV6Pad1Option.class;
          }
        });
    instantiaters.put(
        IpV6OptionType.PADN,
        new Instantiater() {
          @Override
          public IpV6Option newInstance(byte[] rawData, int offset, int length)
              throws IllegalRawDataException {
            return IpV6PadNOption.newInstance(rawData, offset, length);
          }

          @Override
          public Class<IpV6PadNOption> getTargetClass() {
            return IpV6PadNOption.class;
          }
        });
  };

  /** @return the singleton instance of StaticIpV6OptionFactory. */
  public static StaticIpV6OptionFactory getInstance() {
    return INSTANCE;
  }

  @Override
  public IpV6Option newInstance(byte[] rawData, int offset, int length, IpV6OptionType number) {
    if (rawData == null || number == null) {
      StringBuilder sb = new StringBuilder(40);
      sb.append("rawData: ").append(rawData).append(" number: ").append(number);
      throw new NullPointerException(sb.toString());
    }

    try {
      Instantiater instantiater = instantiaters.get(number);
      if (instantiater != null) {
        return instantiater.newInstance(rawData, offset, length);
      }
    } catch (IllegalRawDataException e) {
      return IllegalIpV6Option.newInstance(rawData, offset, length);
    }

    return newInstance(rawData, offset, length);
  }

  @Override
  public IpV6Option newInstance(byte[] rawData, int offset, int length) {
    try {
      return UnknownIpV6Option.newInstance(rawData, offset, length);
    } catch (IllegalRawDataException e) {
      return IllegalIpV6Option.newInstance(rawData, offset, length);
    }
  }

  @Override
  public Class<? extends IpV6Option> getTargetClass(IpV6OptionType number) {
    if (number == null) {
      throw new NullPointerException("number must not be null.");
    }
    Instantiater instantiater = instantiaters.get(number);
    return instantiater != null ? instantiater.getTargetClass() : getTargetClass();
  }

  @Override
  public Class<? extends IpV6Option> getTargetClass() {
    return UnknownIpV6Option.class;
  }

  private static interface Instantiater {

    public IpV6Option newInstance(byte[] rawData, int offset, int length)
        throws IllegalRawDataException;

    public Class<? extends IpV6Option> getTargetClass();
  }
}
