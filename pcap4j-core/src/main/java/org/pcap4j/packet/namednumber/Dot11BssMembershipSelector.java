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
 * IEEE802.11 BSS membership selector
 *
 * @see <a href="http://standards.ieee.org/getieee802/download/802.11-2012.pdf">IEEE802.11</a>
 * @author Kaito Yamada
 * @since pcap4j 1.7.0
 */
public final class Dot11BssMembershipSelector
    extends NamedNumber<Byte, Dot11BssMembershipSelector> {

  /** */
  private static final long serialVersionUID = -8967573178793261461L;

  /** HT PHY: 127 */
  public static final Dot11BssMembershipSelector HT_PHY =
      new Dot11BssMembershipSelector((byte) 127, "HT PHY");

  private static final Map<Byte, Dot11BssMembershipSelector> registry =
      new HashMap<Byte, Dot11BssMembershipSelector>();

  static {
    registry.put(HT_PHY.value(), HT_PHY);
  }

  /**
   * @param value value
   * @param name name
   */
  public Dot11BssMembershipSelector(Byte value, String name) {
    super(value, name);

    if (value < 0) {
      throw new IllegalArgumentException(
          "The value must be between 0 to 127 but actually is: " + value);
    }
  }

  /**
   * @param value value
   * @return a Dot11BssMembershipSelector object.
   */
  public static Dot11BssMembershipSelector getInstance(Byte value) {
    if (registry.containsKey(value)) {
      return registry.get(value);
    } else {
      return new Dot11BssMembershipSelector(value, "unknown");
    }
  }

  /**
   * @param value value
   * @return true if given value is registered; false otherwise.
   */
  public static boolean isRegistered(Byte value) {
    return registry.containsKey(value);
  }

  /**
   * @param number number
   * @return a Dot11BssMembershipSelector object.
   */
  public static Dot11BssMembershipSelector register(Dot11BssMembershipSelector number) {
    return registry.put(number.value(), number);
  }

  @Override
  public int compareTo(Dot11BssMembershipSelector o) {
    return value().compareTo(o.value());
  }

  /** */
  @Override
  public String valueAsString() {
    return String.valueOf(value() & 0xFF);
  }
}
