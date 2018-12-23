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
 * Handling Restrictions of IPv4 Security Option
 *
 * @see <a href="https://tools.ietf.org/html/rfc791">RFC 791</a>
 * @author Kaito Yamada
 * @since pcap4j 0.9.11
 */
public final class IpV4SecurityOptionHandlingRestrictions
    extends NamedNumber<Short, IpV4SecurityOptionHandlingRestrictions> {

  /** */
  private static final long serialVersionUID = 3041825811304706489L;

  private static final Map<Short, IpV4SecurityOptionHandlingRestrictions> registry =
      new HashMap<Short, IpV4SecurityOptionHandlingRestrictions>();

  static {
  }

  /**
   * @param value value
   * @param name name
   */
  public IpV4SecurityOptionHandlingRestrictions(Short value, String name) {
    super(value, name);
  }

  /**
   * @param value value
   * @return a IpV4SecurityOptionHandlingRestrictions object.
   */
  public static IpV4SecurityOptionHandlingRestrictions getInstance(Short value) {
    if (registry.containsKey(value)) {
      return registry.get(value);
    } else {
      return new IpV4SecurityOptionHandlingRestrictions(value, "unknown");
    }
  }

  /**
   * @param number number
   * @return a IpV4SecurityOptionHandlingRestrictions object.
   */
  public static IpV4SecurityOptionHandlingRestrictions register(
      IpV4SecurityOptionHandlingRestrictions number) {
    return registry.put(number.value(), number);
  }

  @Override
  public String valueAsString() {
    return "0x" + ByteArrays.toHexString(value(), "");
  }

  @Override
  public int compareTo(IpV4SecurityOptionHandlingRestrictions o) {
    return value().compareTo(o.value());
  }
}
