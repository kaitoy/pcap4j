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
 * Security of IPv4 Security Option
 *
 * @see <a href="https://tools.ietf.org/html/rfc791">RFC 791</a>
 * @author Kaito Yamada
 * @since pcap4j 0.9.11
 */
public final class IpV4SecurityOptionSecurity
    extends NamedNumber<Short, IpV4SecurityOptionSecurity> {

  /** */
  private static final long serialVersionUID = -5609708606668323329L;

  /** Unclassified: 0x0000 */
  public static final IpV4SecurityOptionSecurity UNCLASSIFIED =
      new IpV4SecurityOptionSecurity((short) 0x0000, "Unclassified");

  /** Confidential: 0xF135 */
  public static final IpV4SecurityOptionSecurity CONFIDENTIAL =
      new IpV4SecurityOptionSecurity((short) 0xF135, "Confidential");

  /** EFTO: 0x789A */
  public static final IpV4SecurityOptionSecurity EFTO =
      new IpV4SecurityOptionSecurity((short) 0x789A, "EFTO");

  /** MMMM: 0xBC4D */
  public static final IpV4SecurityOptionSecurity MMMM =
      new IpV4SecurityOptionSecurity((short) 0xBC4D, "MMMM");

  /** PROG: 0x5E26 */
  public static final IpV4SecurityOptionSecurity PROG =
      new IpV4SecurityOptionSecurity((short) 0x5E26, "PROG");

  /** Restricted: 0xAF13 */
  public static final IpV4SecurityOptionSecurity RESTRICTED =
      new IpV4SecurityOptionSecurity((short) 0xAF13, "Restricted");

  /** Secret: 0xD788 */
  public static final IpV4SecurityOptionSecurity SECRET =
      new IpV4SecurityOptionSecurity((short) 0xD788, "Secret");

  /** Top Secret: 0x6BC5 */
  public static final IpV4SecurityOptionSecurity TOP_SECRET =
      new IpV4SecurityOptionSecurity((short) 0x6BC5, "Top Secret");

  private static final Map<Short, IpV4SecurityOptionSecurity> registry =
      new HashMap<Short, IpV4SecurityOptionSecurity>();

  static {
    registry.put(UNCLASSIFIED.value(), UNCLASSIFIED);
    registry.put(CONFIDENTIAL.value(), CONFIDENTIAL);
    registry.put(EFTO.value(), EFTO);
    registry.put(MMMM.value(), MMMM);
    registry.put(PROG.value(), PROG);
    registry.put(RESTRICTED.value(), RESTRICTED);
    registry.put(SECRET.value(), SECRET);
    registry.put(TOP_SECRET.value(), TOP_SECRET);
  }

  /**
   * @param value value
   * @param name name
   */
  public IpV4SecurityOptionSecurity(Short value, String name) {
    super(value, name);
  }

  /**
   * @param value value
   * @return a IpV4SecurityOptionSecurity object.
   */
  public static IpV4SecurityOptionSecurity getInstance(Short value) {
    if (registry.containsKey(value)) {
      return registry.get(value);
    } else {
      return new IpV4SecurityOptionSecurity(value, "unknown");
    }
  }

  /**
   * @param number number
   * @return a IpV4SecurityOptionSecurity object.
   */
  public static IpV4SecurityOptionSecurity register(IpV4SecurityOptionSecurity number) {
    return registry.put(number.value(), number);
  }

  @Override
  public String valueAsString() {
    return "0x" + ByteArrays.toHexString(value(), "");
  }

  @Override
  public int compareTo(IpV4SecurityOptionSecurity o) {
    return value().compareTo(o.value());
  }
}
