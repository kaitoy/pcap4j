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
 * TOS of IPv4 TOS
 *
 * @see <a
 *     href="http://www.iana.org/assignments/ip-parameters/ip-parameters.xhtml#ip-parameters-3">IANA
 *     Registry</a>
 * @author Kaito Yamada
 * @since pcap4j 0.9.11
 */
public final class IpV4TosTos extends NamedNumber<Byte, IpV4TosTos> {

  /** */
  private static final long serialVersionUID = -7507790549660176346L;

  /** Default: 0x0 */
  public static final IpV4TosTos DEFAULT = new IpV4TosTos((byte) 0x0, "Default");

  /** Minimize Monetary Cost: 0x1 */
  public static final IpV4TosTos MINIMIZE_MONETARY_COST =
      new IpV4TosTos((byte) 0x1, "Minimize Monetary Cost");

  /** Maximize Reliability: 0x2 */
  public static final IpV4TosTos MAXIMIZE_RELIABILITY =
      new IpV4TosTos((byte) 0x2, "Maximize Reliability");

  /** Maximize Throughput: 0x4 */
  public static final IpV4TosTos MAXIMIZE_THROUGHPUT =
      new IpV4TosTos((byte) 0x4, "Maximize Throughput");

  /** Minimize Delay: 0x8 */
  public static final IpV4TosTos MINIMIZE_DELAY = new IpV4TosTos((byte) 0x8, "Minimize Delay");

  /** Maximize Security: 0xF */
  public static final IpV4TosTos MAXIMIZE_SECURITY =
      new IpV4TosTos((byte) 0xF, "Maximize Security");

  private static final Map<Byte, IpV4TosTos> registry = new HashMap<Byte, IpV4TosTos>();

  static {
    registry.put(DEFAULT.value(), DEFAULT);
    registry.put(MINIMIZE_MONETARY_COST.value(), MINIMIZE_MONETARY_COST);
    registry.put(MAXIMIZE_RELIABILITY.value(), MAXIMIZE_RELIABILITY);
    registry.put(MAXIMIZE_THROUGHPUT.value(), MAXIMIZE_THROUGHPUT);
    registry.put(MINIMIZE_DELAY.value(), MINIMIZE_DELAY);
    registry.put(MAXIMIZE_SECURITY.value(), MAXIMIZE_SECURITY);
  }

  /**
   * @param value value
   * @param name name
   */
  public IpV4TosTos(Byte value, String name) {
    super(value, name);
    if ((value & 0xF0) != 0) {
      throw new IllegalArgumentException(
          value + " is invalid value. " + "TOS field of IPv4 TOS must be between 0 and 15");
    }
  }

  /**
   * @param value value
   * @return a IpV4TosTos object.
   */
  public static IpV4TosTos getInstance(Byte value) {
    if (registry.containsKey(value)) {
      return registry.get(value);
    } else {
      return new IpV4TosTos(value, "unknown");
    }
  }

  /**
   * @param tos tos
   * @return a IpV4TosTos object.
   */
  public static IpV4TosTos register(IpV4TosTos tos) {
    return registry.put(tos.value(), tos);
  }

  @Override
  public int compareTo(IpV4TosTos o) {
    return value().compareTo(o.value());
  }
}
