/*_##########################################################################
  _##
  _##  Copyright (C) 2015  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.namednumber;

import java.util.HashMap;
import java.util.Map;
import org.pcap4j.core.Inets;

/**
 * Protocol Family
 *
 * @see <a href="http://fxr.watson.org/fxr/source/sys/socket.h">sys/socket.h</a>
 * @author Kaito Yamada
 * @since pcap4j 1.5.0
 */
public final class ProtocolFamily extends NamedNumber<Integer, ProtocolFamily> {

  /** */
  private static final long serialVersionUID = 2803732603678906217L;

  /** PF_UNSPEC (unspecified): 0 */
  public static final ProtocolFamily PF_UNSPEC = new ProtocolFamily(0, "PF_UNSPEC");

  /** PF_INET (IPv4). This value is set to 0xFFFF &amp; {@link Inets#AF_INET}. */
  public static final ProtocolFamily PF_INET =
      new ProtocolFamily(0xFFFF & Inets.AF_INET, "PF_INET");

  /** PF_LINK (Link layer interface). This value is set to 0xFFFF &amp; {@link Inets#AF_LINK}. */
  public static final ProtocolFamily PF_LINK =
      new ProtocolFamily(0xFFFF & Inets.AF_LINK, "PF_LINK");

  /** PF_INET6 (IPv6). This value is set to 0xFFFF &amp; {@link Inets#AF_INET6}. */
  public static final ProtocolFamily PF_INET6 =
      new ProtocolFamily(0xFFFF & Inets.AF_INET6, "PF_INET6");

  private static final Map<Integer, ProtocolFamily> registry =
      new HashMap<Integer, ProtocolFamily>(10);

  static {
    registry.put(PF_UNSPEC.value(), PF_UNSPEC);
    registry.put(PF_INET.value(), PF_INET);
    registry.put(PF_LINK.value(), PF_LINK);
    registry.put(PF_INET6.value(), PF_INET6);
  }

  /**
   * @param value value
   * @param name name
   */
  public ProtocolFamily(Integer value, String name) {
    super(value, name);
  }

  /**
   * @param value value
   * @return a ProtocolFamily object.
   */
  public static ProtocolFamily getInstance(Integer value) {
    if (registry.containsKey(value)) {
      return registry.get(value);
    } else {
      return new ProtocolFamily(value, "unknown");
    }
  }

  /**
   * @param type type
   * @return a ProtocolFamily object.
   */
  public static ProtocolFamily register(ProtocolFamily type) {
    return registry.put(type.value(), type);
  }

  /** */
  @Override
  public String valueAsString() {
    return String.valueOf(value() & 0xFFFF);
  }

  @Override
  public int compareTo(ProtocolFamily o) {
    return value().compareTo(o.value());
  }
}
