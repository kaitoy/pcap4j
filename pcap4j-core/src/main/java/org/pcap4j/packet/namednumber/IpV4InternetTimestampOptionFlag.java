/*_##########################################################################
  _##
  _##  Copyright (C) 2012-2015  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.namednumber;

import java.util.HashMap;
import java.util.Map;

/**
 * Flag of IPv4 Internet Timestamp Option
 *
 * @see <a href="http://www.ietf.org/rfc/rfc791.txt">RFC 791</a>
 * @author Kaito Yamada
 * @since pcap4j 0.9.11
 */
public final class IpV4InternetTimestampOptionFlag
    extends NamedNumber<Byte, IpV4InternetTimestampOptionFlag> {

  /** */
  private static final long serialVersionUID = -8701646393814443788L;

  /** timestamps only: 0 */
  public static final IpV4InternetTimestampOptionFlag TIMESTAMPS_ONLY =
      new IpV4InternetTimestampOptionFlag((byte) 0, "timestamps only");

  /** each timestamp is preceded with internet address of the registering entity: 1 */
  public static final IpV4InternetTimestampOptionFlag EACH_TIMESTAMP_PRECEDED_WITH_ADDRESS =
      new IpV4InternetTimestampOptionFlag(
          (byte) 1, "each timestamp is preceded with internet address of the registering entity");

  /** the internet address fields are prespecified: 3 */
  public static final IpV4InternetTimestampOptionFlag ADDRESS_PRESPECIFIED =
      new IpV4InternetTimestampOptionFlag((byte) 3, "the internet address fields are prespecified");

  private static final Map<Byte, IpV4InternetTimestampOptionFlag> registry =
      new HashMap<Byte, IpV4InternetTimestampOptionFlag>();

  static {
    registry.put(TIMESTAMPS_ONLY.value(), TIMESTAMPS_ONLY);
    registry.put(
        EACH_TIMESTAMP_PRECEDED_WITH_ADDRESS.value(), EACH_TIMESTAMP_PRECEDED_WITH_ADDRESS);
    registry.put(ADDRESS_PRESPECIFIED.value(), ADDRESS_PRESPECIFIED);
  }

  /**
   * @param value value
   * @param name name
   */
  public IpV4InternetTimestampOptionFlag(Byte value, String name) {
    super(value, name);
    if ((value & 0xF0) != 0) {
      throw new IllegalArgumentException(value + " is invalid value. It must be between 0 and 15");
    }
  }

  /**
   * @param value value
   * @return a IpV4InternetTimestampOptionFlag object.
   */
  public static IpV4InternetTimestampOptionFlag getInstance(Byte value) {
    if (registry.containsKey(value)) {
      return registry.get(value);
    } else {
      return new IpV4InternetTimestampOptionFlag(value, "unknown");
    }
  }

  /**
   * @param flag flag
   * @return a IpV4InternetTimestampOptionFlag object.
   */
  public static IpV4InternetTimestampOptionFlag register(IpV4InternetTimestampOptionFlag flag) {
    return registry.put(flag.value(), flag);
  }

  @Override
  public int compareTo(IpV4InternetTimestampOptionFlag o) {
    return value().compareTo(o.value());
  }
}
