/*_##########################################################################
  _##
  _##  Copyright (C) 2011-2015  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.namednumber;

import java.util.HashMap;
import java.util.Map;
import org.pcap4j.util.ByteArrays;

/**
 * Compartments of IPv4 Security Option
 *
 * @see <a href="https://tools.ietf.org/html/rfc791">RFC 791</a>
 * @author Kaito Yamada
 * @since pcap4j 0.9.11
 */
public final class IpV4SecurityOptionCompartments
    extends NamedNumber<Short, IpV4SecurityOptionCompartments> {

  /** */
  private static final long serialVersionUID = -420949071267484565L;

  /** not compartmented: 0x0000 */
  public static final IpV4SecurityOptionCompartments NOT_COMPARTMENTED =
      new IpV4SecurityOptionCompartments((short) 0x0000, "not compartmented");

  private static final Map<Short, IpV4SecurityOptionCompartments> registry =
      new HashMap<Short, IpV4SecurityOptionCompartments>();

  static {
    registry.put(NOT_COMPARTMENTED.value(), NOT_COMPARTMENTED);
  }

  /**
   * @param value value
   * @param name name
   */
  public IpV4SecurityOptionCompartments(Short value, String name) {
    super(value, name);
  }

  /**
   * @param value value
   * @return a IpV4SecurityOptionCompartments object.
   */
  public static IpV4SecurityOptionCompartments getInstance(Short value) {
    if (registry.containsKey(value)) {
      return registry.get(value);
    } else {
      return new IpV4SecurityOptionCompartments(value, "unknown");
    }
  }

  /**
   * @param number number
   * @return a IpV4SecurityOptionCompartments object.
   */
  public static IpV4SecurityOptionCompartments register(IpV4SecurityOptionCompartments number) {
    return registry.put(number.value(), number);
  }

  @Override
  public String valueAsString() {
    return "0x" + ByteArrays.toHexString(value(), "");
  }

  @Override
  public int compareTo(IpV4SecurityOptionCompartments o) {
    return value().compareTo(o.value());
  }
}
