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
 * IPv6 Routing Type
 *
 * @see <a
 *     href="http://www.iana.org/assignments/ipv6-parameters/ipv6-parameters.xml#ipv6-parameters-3">IANA
 *     Registry</a>
 * @author Kaito Yamada
 * @since pcap4j 1.4.0
 */
public final class IpV6RoutingType extends NamedNumber<Byte, IpV6RoutingType> {

  /** */
  private static final long serialVersionUID = 3229438606992762639L;

  /** Source Route: 0 */
  public static final IpV6RoutingType SOURCE_ROUTE = new IpV6RoutingType((byte) 0, "Source Route");

  /** Nimrod: 1 */
  public static final IpV6RoutingType NIMROD = new IpV6RoutingType((byte) 1, "Nimrod");

  /** Type 2 Routing Header: 2 */
  public static final IpV6RoutingType TYPE2_ROUTING_HEADER =
      new IpV6RoutingType((byte) 2, "Type 2 Routing Header");

  /** RPL Source Route Header: 3 */
  public static final IpV6RoutingType RPL_SOURCE_ROUTE_HEADER =
      new IpV6RoutingType((byte) 3, "RPL Source Route Header");

  private static final Map<Byte, IpV6RoutingType> registry = new HashMap<Byte, IpV6RoutingType>();

  static {
    registry.put(SOURCE_ROUTE.value(), SOURCE_ROUTE);
    registry.put(NIMROD.value(), NIMROD);
    registry.put(TYPE2_ROUTING_HEADER.value(), TYPE2_ROUTING_HEADER);
    registry.put(RPL_SOURCE_ROUTE_HEADER.value(), RPL_SOURCE_ROUTE_HEADER);
  }

  /**
   * @param value value
   * @param name name
   */
  public IpV6RoutingType(Byte value, String name) {
    super(value, name);
  }

  /**
   * @param value value
   * @return a IpV6RoutingHeaderType object.
   */
  public static IpV6RoutingType getInstance(Byte value) {
    if (registry.containsKey(value)) {
      return registry.get(value);
    } else {
      return new IpV6RoutingType(value, "unknown");
    }
  }

  /**
   * @param number number
   * @return a IpV6RoutingHeaderType object.
   */
  public static IpV6RoutingType register(IpV6RoutingType number) {
    return registry.put(number.value(), number);
  }

  @Override
  public String valueAsString() {
    return String.valueOf(value() & 0xFF);
  }

  @Override
  public int compareTo(IpV6RoutingType o) {
    return value().compareTo(o.value());
  }
}
