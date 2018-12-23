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
 * Transmission Control Code of IPv4 Security Option
 *
 * @see <a href="https://tools.ietf.org/html/rfc791">RFC 791</a>
 * @author Kaito Yamada
 * @since pcap4j 0.9.11
 */
public final class IpV4SecurityOptionTransmissionControlCode
    extends NamedNumber<Integer, IpV4SecurityOptionTransmissionControlCode> {

  /** */
  private static final long serialVersionUID = 3041825811304706489L;

  private static final Map<Integer, IpV4SecurityOptionTransmissionControlCode> registry =
      new HashMap<Integer, IpV4SecurityOptionTransmissionControlCode>();

  static {
  }

  /**
   * @param value value
   * @param name name
   */
  public IpV4SecurityOptionTransmissionControlCode(Integer value, String name) {
    super(value, name);
    if ((value & 0xFF000000) != 0) {
      throw new IllegalArgumentException(
          value + " is invalid value. " + "The value must be between 0 and 16777215");
    }
  }

  /**
   * @param value value
   * @return a IpV4SecurityOptionTransmissionControlCode object.
   */
  public static IpV4SecurityOptionTransmissionControlCode getInstance(Integer value) {
    if (registry.containsKey(value)) {
      return registry.get(value);
    } else {
      return new IpV4SecurityOptionTransmissionControlCode(value, "unknown");
    }
  }

  /**
   * @param number number
   * @return a IpV4SecurityOptionTransmissionControlCode object.
   */
  public static IpV4SecurityOptionTransmissionControlCode register(
      IpV4SecurityOptionTransmissionControlCode number) {
    return registry.put(number.value(), number);
  }

  @Override
  public String valueAsString() {
    return "0x" + ByteArrays.toHexString(value(), "");
  }

  @Override
  public int compareTo(IpV4SecurityOptionTransmissionControlCode o) {
    return value().compareTo(o.value());
  }
}
