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
 * Precedence of IPv4 TOS
 *
 * @see <a href="https://tools.ietf.org/html/rfc791">RFC 791</a>
 * @author Kaito Yamada
 * @since pcap4j 0.9.11
 */
public final class IpV4TosPrecedence extends NamedNumber<Byte, IpV4TosPrecedence> {

  /** */
  private static final long serialVersionUID = 3155818580398801532L;

  /** Routine: 0 */
  public static final IpV4TosPrecedence ROUTINE = new IpV4TosPrecedence((byte) 0, "Routine");

  /** Priority: 1 */
  public static final IpV4TosPrecedence PRIORITY = new IpV4TosPrecedence((byte) 1, "Priority");

  /** Immediate: 2 */
  public static final IpV4TosPrecedence IMMEDIATE = new IpV4TosPrecedence((byte) 2, "Immediate");

  /** Flash: 3 */
  public static final IpV4TosPrecedence FLASH = new IpV4TosPrecedence((byte) 3, "Flash");

  /** Flash Override: 4 */
  public static final IpV4TosPrecedence FLASH_OVERRIDE =
      new IpV4TosPrecedence((byte) 4, "Flash Override");

  /** CRITIC/ECP: 5 */
  public static final IpV4TosPrecedence CRITIC_ECP = new IpV4TosPrecedence((byte) 5, "CRITIC/ECP");

  /** Internetwork Control/ECP: 6 */
  public static final IpV4TosPrecedence INTERNETWORK_CONTROL =
      new IpV4TosPrecedence((byte) 6, "Internetwork Control/ECP");

  /** Network Control: 7 */
  public static final IpV4TosPrecedence NETWORK_CONTROL =
      new IpV4TosPrecedence((byte) 7, "Network Control");

  private static final Map<Byte, IpV4TosPrecedence> registry =
      new HashMap<Byte, IpV4TosPrecedence>();

  static {
    registry.put(ROUTINE.value(), ROUTINE);
    registry.put(PRIORITY.value(), PRIORITY);
    registry.put(IMMEDIATE.value(), IMMEDIATE);
    registry.put(FLASH.value(), FLASH);
    registry.put(FLASH_OVERRIDE.value(), FLASH_OVERRIDE);
    registry.put(CRITIC_ECP.value(), CRITIC_ECP);
    registry.put(INTERNETWORK_CONTROL.value(), INTERNETWORK_CONTROL);
    registry.put(NETWORK_CONTROL.value(), NETWORK_CONTROL);
  }

  /**
   * @param value value
   * @param name name
   */
  public IpV4TosPrecedence(Byte value, String name) {
    super(value, name);
    if ((value & 0xF8) != 0) {
      throw new IllegalArgumentException(
          value + " is invalid value. " + "Precedence field of IPv4 TOS must be between 0 and 7");
    }
  }

  /**
   * @param value value
   * @return a IpV4TosPrecedence object.
   */
  public static IpV4TosPrecedence getInstance(Byte value) {
    if (registry.containsKey(value)) {
      return registry.get(value);
    } else {
      return new IpV4TosPrecedence(value, "unknown");
    }
  }

  /**
   * @param precedence precedence
   * @return a IpV4TosPrecedence object.
   */
  public static IpV4TosPrecedence register(IpV4TosPrecedence precedence) {
    return registry.put(precedence.value(), precedence);
  }

  @Override
  public int compareTo(IpV4TosPrecedence o) {
    return value().compareTo(o.value());
  }
}
