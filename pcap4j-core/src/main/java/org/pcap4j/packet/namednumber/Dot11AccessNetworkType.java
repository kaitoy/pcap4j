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
 * IEEE802.11 Access network type
 *
 * @see <a href="http://standards.ieee.org/getieee802/download/802.11-2012.pdf">IEEE802.11</a>
 * @author Kaito Yamada
 * @since pcap4j 1.7.0
 */
public final class Dot11AccessNetworkType extends NamedNumber<Byte, Dot11AccessNetworkType> {

  /** */
  private static final long serialVersionUID = 446760220104978318L;

  /** Private network: 0 */
  public static final Dot11AccessNetworkType PRIVATE_NETWORK =
      new Dot11AccessNetworkType((byte) 0, "Private network");

  /** Private network with guest access: 1 */
  public static final Dot11AccessNetworkType PRIVATE_NETWORK_WITH_GUEST_ACCESS =
      new Dot11AccessNetworkType((byte) 1, "Private network with guest access");

  /** Chargeable public network: 2 */
  public static final Dot11AccessNetworkType CHARGEABLE_PUBLIC_NETWORK =
      new Dot11AccessNetworkType((byte) 2, "Chargeable public network");

  /** Free public network: 3 */
  public static final Dot11AccessNetworkType FREE_PUBLIC_NETWORK =
      new Dot11AccessNetworkType((byte) 3, "Free public network");

  /** Personal device network: 4 */
  public static final Dot11AccessNetworkType PERSONAL_DEVICE_NETWORK =
      new Dot11AccessNetworkType((byte) 4, "Personal device network");

  /** Emergency services only network: 5 */
  public static final Dot11AccessNetworkType EMERGENCY_SERVICES_ONLY_NETWORK =
      new Dot11AccessNetworkType((byte) 5, "Emergency services only network");

  /** Test or experimental: 14 */
  public static final Dot11AccessNetworkType TEST_OR_EXPERIMENTAL =
      new Dot11AccessNetworkType((byte) 14, "Test or experimental");

  /** Wildcard: 15 */
  public static final Dot11AccessNetworkType WILDCARD =
      new Dot11AccessNetworkType((byte) 15, "Wildcard");

  private static final Map<Byte, Dot11AccessNetworkType> registry =
      new HashMap<Byte, Dot11AccessNetworkType>();

  static {
    registry.put(PRIVATE_NETWORK.value(), PRIVATE_NETWORK);
    registry.put(PRIVATE_NETWORK_WITH_GUEST_ACCESS.value(), PRIVATE_NETWORK_WITH_GUEST_ACCESS);
    registry.put(CHARGEABLE_PUBLIC_NETWORK.value(), CHARGEABLE_PUBLIC_NETWORK);
    registry.put(FREE_PUBLIC_NETWORK.value(), FREE_PUBLIC_NETWORK);
    registry.put(PERSONAL_DEVICE_NETWORK.value(), PERSONAL_DEVICE_NETWORK);
    registry.put(EMERGENCY_SERVICES_ONLY_NETWORK.value(), EMERGENCY_SERVICES_ONLY_NETWORK);
    registry.put(TEST_OR_EXPERIMENTAL.value(), TEST_OR_EXPERIMENTAL);
    registry.put(WILDCARD.value(), WILDCARD);
  }

  /**
   * @param value value
   * @param name name
   */
  public Dot11AccessNetworkType(Byte value, String name) {
    super(value, name);

    if ((value & 0xF0) != 0) {
      throw new IllegalArgumentException("(value & 0xF0) must be 0. value: " + value);
    }
  }

  /**
   * @param value value
   * @return a Dot11AccessNetworkType object.
   */
  public static Dot11AccessNetworkType getInstance(Byte value) {
    if (registry.containsKey(value)) {
      return registry.get(value);
    } else {
      return new Dot11AccessNetworkType(value, "unknown");
    }
  }

  /**
   * @param number number
   * @return a Dot11AccessNetworkType object.
   */
  public static Dot11AccessNetworkType register(Dot11AccessNetworkType number) {
    return registry.put(number.value(), number);
  }

  @Override
  public int compareTo(Dot11AccessNetworkType o) {
    return value().compareTo(o.value());
  }

  /** */
  @Override
  public String valueAsString() {
    return String.valueOf(value() & 0xFF);
  }
}
