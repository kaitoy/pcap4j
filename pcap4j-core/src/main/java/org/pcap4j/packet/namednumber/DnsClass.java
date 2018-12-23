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
 * DNS Class
 *
 * @see <a
 *     href="http://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-2">IANA
 *     Registry</a>
 * @author Kaito Yamada
 * @since pcap4j 1.7.1
 */
public final class DnsClass extends NamedNumber<Short, DnsClass> {

  /** */
  private static final long serialVersionUID = -8563135157139346618L;

  /** Internet (IN): 1 */
  public static final DnsClass IN = new DnsClass((short) 1, "Internet (IN)");

  /** Chaos (CH): 3 */
  public static final DnsClass CH = new DnsClass((short) 3, "Chaos (CH)");

  /** Hesiod (HS): 4 */
  public static final DnsClass HS = new DnsClass((short) 4, "Hesiod (HS)");

  /** NONE: 254 */
  public static final DnsClass NONE = new DnsClass((short) 254, "NONE");

  /** ANY: 255 */
  public static final DnsClass ANY = new DnsClass((short) 255, "ANY");

  private static final Map<Short, DnsClass> registry = new HashMap<Short, DnsClass>();

  static {
    registry.put(IN.value(), IN);
    registry.put(CH.value(), CH);
    registry.put(HS.value(), HS);
    registry.put(NONE.value(), NONE);
    registry.put(ANY.value(), ANY);
  }

  /**
   * @param value value
   * @param name name
   */
  public DnsClass(Short value, String name) {
    super(value, name);
  }

  /**
   * @param value value
   * @return a DnsClass object.
   */
  public static DnsClass getInstance(Short value) {
    if (registry.containsKey(value)) {
      return registry.get(value);
    } else {
      return new DnsClass(value, "unknown");
    }
  }

  /**
   * @param cls class
   * @return a DnsClass object.
   */
  public static DnsClass register(DnsClass cls) {
    return registry.put(cls.value(), cls);
  }

  @Override
  public String valueAsString() {
    return String.valueOf(value() & 0xFFFF);
  }

  @Override
  public int compareTo(DnsClass o) {
    return value().compareTo(o.value());
  }
}
