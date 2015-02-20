/*_##########################################################################
  _##
  _##  Copyright (C) 2011-2015  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet.namednumber;

import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Map;

/**
 * @author Kaito Yamada
 * @since pcap4j 1.3.1
 */
public final class IpV6RoutingType extends NamedNumber<Byte, IpV6RoutingType> {

  // http://www.iana.org/assignments/ipv6-parameters/ipv6-parameters.xml#ipv6-parameters-3
  // http://www.ietf.org/rfc/rfc2460.txt

  /**
   *
   */
  private static final long serialVersionUID = 3229438606992762639L;

  /**
   *
   */
  public static final IpV6RoutingType SOURCE_ROUTE
    = new IpV6RoutingType((byte)0, "Source Route");

  /**
   *
   */
  public static final IpV6RoutingType TYPE2_ROUTING_HEADER
    = new IpV6RoutingType((byte)2, "Type 2 Routing Header");

  /**
   *
   */
  public static final IpV6RoutingType RPL_SOURCE_ROUTE_HEADER
    = new IpV6RoutingType((byte)3, "RPL Source Route Header");

  private static final Map<Byte, IpV6RoutingType> registry
    = new HashMap<Byte, IpV6RoutingType>();

  static {
    for (Field field: IpV6RoutingType.class.getFields()) {
      if (IpV6RoutingType.class.isAssignableFrom(field.getType())) {
        try {
          IpV6RoutingType f = (IpV6RoutingType)field.get(null);
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
  public IpV6RoutingType(Byte value, String name) {
    super(value, name);
  }

  /**
   *
   * @param value
   * @return a IpV6RoutingHeaderType object.
   */
  public static IpV6RoutingType getInstance(Byte value) {
    if (registry.containsKey(value)) {
      return registry.get(value);
    }
    else {
      return new IpV6RoutingType(value, "unknown");
    }
  }

  /**
   *
   * @param number
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