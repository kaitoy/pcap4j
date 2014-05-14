/*_##########################################################################
  _##
  _##  Copyright (C) 2011-2014  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet.namednumber;

import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Map;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.11
 */
public final class IpV6RoutingHeaderType extends NamedNumber<Byte, IpV6RoutingHeaderType> {

  // http://www.iana.org/assignments/ipv6-parameters/ipv6-parameters.xml#ipv6-parameters-3
  // http://www.ietf.org/rfc/rfc2460.txt

  /**
   *
   */
  private static final long serialVersionUID = -6648259162603151846L;

  /**
   *
   */
  public static final IpV6RoutingHeaderType SOURCE_ROUTE
    = new IpV6RoutingHeaderType((byte)0, "Source Route");

  /**
   *
   */
  public static final IpV6RoutingHeaderType TYPE2_ROUTING_HEADER
    = new IpV6RoutingHeaderType((byte)2, "Type 2 Routing Header");

  /**
   *
   */
  public static final IpV6RoutingHeaderType RPL_SOURCE_ROUTE_HEADER
    = new IpV6RoutingHeaderType((byte)3, "RPL Source Route Header");

  private static final Map<Byte, IpV6RoutingHeaderType> registry
    = new HashMap<Byte, IpV6RoutingHeaderType>();

  static {
    for (Field field: IpV6RoutingHeaderType.class.getFields()) {
      if (IpV6RoutingHeaderType.class.isAssignableFrom(field.getType())) {
        try {
          IpV6RoutingHeaderType f = (IpV6RoutingHeaderType)field.get(null);
          registry.put(f.value(), f);
        } catch (IllegalArgumentException e) {
          throw new AssertionError(e);
        } catch (IllegalAccessException e) {
          throw new AssertionError(e);
        } catch (NullPointerException e) {
          continue;
        }
      }
    }
  }

  /**
   *
   * @param value
   * @param name
   */
  public IpV6RoutingHeaderType(Byte value, String name) {
    super(value, name);
  }

  /**
   *
   * @param value
   * @return a IpV6RoutingHeaderType object.
   */
  public static IpV6RoutingHeaderType getInstance(Byte value) {
    if (registry.containsKey(value)) {
      return registry.get(value);
    }
    else {
      return new IpV6RoutingHeaderType(value, "unknown");
    }
  }

  /**
   *
   * @param number
   * @return a IpV6RoutingHeaderType object.
   */
  public static IpV6RoutingHeaderType register(IpV6RoutingHeaderType number) {
    return registry.put(number.value(), number);
  }

  @Override
  public String valueAsString() {
    return String.valueOf(value() & 0xFF);
  }

  @Override
  public int compareTo(IpV6RoutingHeaderType o) {
    return value().compareTo(o.value());
  }

}