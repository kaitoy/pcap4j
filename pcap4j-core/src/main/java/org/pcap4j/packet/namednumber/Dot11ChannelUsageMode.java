/*_##########################################################################
  _##
  _##  Copyright (C) 2016  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.namednumber;

import java.util.HashMap;
import java.util.Map;

/**
 * IEEE802.11 Channel Usage Mode
 *
 * @see <a href="http://standards.ieee.org/getieee802/download/802.11-2012.pdf">IEEE802.11</a>
 * @author Kaito Yamada
 * @since pcap4j 1.7.0
 */
public final class Dot11ChannelUsageMode extends NamedNumber<Byte, Dot11ChannelUsageMode> {

  /** */
  private static final long serialVersionUID = -8113989723106251697L;

  /** Noninfrastructure IEEE 802.11 network: 0 */
  public static final Dot11ChannelUsageMode NONINFRASTRUCTURE_DOT_11 =
      new Dot11ChannelUsageMode((byte) 0, "Noninfrastructure IEEE 802.11 network");

  /** Off-channel TDLS direct link: 1 */
  public static final Dot11ChannelUsageMode OFF_CHANNEL_TDLS_DIRECT_LINK =
      new Dot11ChannelUsageMode((byte) 1, "Off-channel TDLS direct link");

  private static final Map<Byte, Dot11ChannelUsageMode> registry =
      new HashMap<Byte, Dot11ChannelUsageMode>();

  static {
    registry.put(NONINFRASTRUCTURE_DOT_11.value(), NONINFRASTRUCTURE_DOT_11);
    registry.put(OFF_CHANNEL_TDLS_DIRECT_LINK.value(), OFF_CHANNEL_TDLS_DIRECT_LINK);
  }

  /**
   * @param value value
   * @param name name
   */
  public Dot11ChannelUsageMode(Byte value, String name) {
    super(value, name);
  }

  /**
   * @param value value
   * @return a Dot11ChannelUsageMode object.
   */
  public static Dot11ChannelUsageMode getInstance(Byte value) {
    if (registry.containsKey(value)) {
      return registry.get(value);
    } else {
      return new Dot11ChannelUsageMode(value, "unknown");
    }
  }

  /**
   * @param number number
   * @return a Dot11ChannelUsageMode object.
   */
  public static Dot11ChannelUsageMode register(Dot11ChannelUsageMode number) {
    return registry.put(number.value(), number);
  }

  @Override
  public int compareTo(Dot11ChannelUsageMode o) {
    return value().compareTo(o.value());
  }

  /** */
  @Override
  public String valueAsString() {
    return String.valueOf(value() & 0xFF);
  }
}
