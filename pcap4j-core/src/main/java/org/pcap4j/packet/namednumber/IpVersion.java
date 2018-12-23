/*_##########################################################################
  _##
  _##  Copyright (C) 2011-2015  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.namednumber;

import java.util.HashMap;
import java.util.Map;

/**
 * @see <a href="http://www.iana.org/assignments/version-numbers/version-numbers.xml">IANA
 *     Registry</a>
 * @author Kaito Yamada
 * @since pcap4j 0.9.1
 */
public final class IpVersion extends NamedNumber<Byte, IpVersion> {

  /** */
  private static final long serialVersionUID = 3155818580398801532L;

  /** IPv4: 4 */
  public static final IpVersion IPV4 = new IpVersion((byte) 4, "IPv4");

  /** ST: 5 */
  public static final IpVersion ST = new IpVersion((byte) 5, "ST");

  /** IPv6: 6 */
  public static final IpVersion IPV6 = new IpVersion((byte) 6, "IPv6");

  /** TP/IX: 7 */
  public static final IpVersion TP_IX = new IpVersion((byte) 7, "TP/IX");

  /** PIP: 8 */
  public static final IpVersion PIP = new IpVersion((byte) 8, "PIP");

  /** TUBA: 9 */
  public static final IpVersion TUBA = new IpVersion((byte) 9, "TUBA");

  private static final Map<Byte, IpVersion> registry = new HashMap<Byte, IpVersion>();

  static {
    registry.put(IPV4.value(), IPV4);
    registry.put(ST.value(), ST);
    registry.put(IPV6.value(), IPV6);
    registry.put(TP_IX.value(), TP_IX);
    registry.put(PIP.value(), PIP);
    registry.put(TUBA.value(), TUBA);
  }

  /**
   * @param value value
   * @param name name
   */
  public IpVersion(Byte value, String name) {
    super(value, name);
    if ((value & 0xF0) != 0) {
      throw new IllegalArgumentException(
          value + " is invalid value. " + "Version field of IP header must be between 0 and 15");
    }
  }

  /**
   * @param value value
   * @return a IpVersion object.
   */
  public static IpVersion getInstance(Byte value) {
    if (registry.containsKey(value)) {
      return registry.get(value);
    } else {
      return new IpVersion(value, "unknown");
    }
  }

  /**
   * @param version version
   * @return a IpVersion object.
   */
  public static IpVersion register(IpVersion version) {
    return registry.put(version.value(), version);
  }

  @Override
  public int compareTo(IpVersion o) {
    return value().compareTo(o.value());
  }
}
