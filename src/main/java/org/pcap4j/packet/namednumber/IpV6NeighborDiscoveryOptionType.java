/*_##########################################################################
  _##
  _##  Copyright (C) 2013  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet.namednumber;

import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Map;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.15
 */
public final class IpV6NeighborDiscoveryOptionType extends NamedNumber<Byte> {

  // http://www.iana.org/assignments/icmpv6-parameters/icmpv6-parameters.xml#icmpv6-parameters-5

  /**
   *
   */
  private static final long serialVersionUID = -4894881455029294238L;

  /**
   *
   */
  public static final IpV6NeighborDiscoveryOptionType SOURCE_LINK_LAYER_ADDRESS
    = new IpV6NeighborDiscoveryOptionType((byte)1, "Source Link-Layer Address");

  /**
   *
   */
  public static final IpV6NeighborDiscoveryOptionType TARGET_LINK_LAYER_ADDRESS
    = new IpV6NeighborDiscoveryOptionType((byte)2, "Target Link-Layer Address");

  /**
   *
   */
  public static final IpV6NeighborDiscoveryOptionType PREFIX_INFORMATION
    = new IpV6NeighborDiscoveryOptionType((byte)3, "Prefix Information");

  /**
   *
   */
  public static final IpV6NeighborDiscoveryOptionType REDIRECTED_HEADER
    = new IpV6NeighborDiscoveryOptionType((byte)4, "Redirected Header");

  /**
   *
   */
  public static final IpV6NeighborDiscoveryOptionType MTU
    = new IpV6NeighborDiscoveryOptionType((byte)5, "MTU");

  private static final Map<Byte, IpV6NeighborDiscoveryOptionType> registry
    = new HashMap<Byte, IpV6NeighborDiscoveryOptionType>();

  static {
    for (Field field: IpV6NeighborDiscoveryOptionType.class.getFields()) {
      if (IpV6NeighborDiscoveryOptionType.class.isAssignableFrom(field.getType())) {
        try {
          IpV6NeighborDiscoveryOptionType f = (IpV6NeighborDiscoveryOptionType)field.get(null);
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
  public IpV6NeighborDiscoveryOptionType(Byte value, String name) {
    super(value, name);
  }

  /**
   *
   * @param value
   * @return a IpV6NeighborDiscoveryOptionType object.
   */
  public static IpV6NeighborDiscoveryOptionType getInstance(Byte value) {
    if (registry.containsKey(value)) {
      return registry.get(value);
    }
    else {
      return new IpV6NeighborDiscoveryOptionType(value, "unknown");
    }
  }

  /**
   *
   * @param type
   * @return a IpV6NeighborDiscoveryOptionType object.
   */
  public static IpV6NeighborDiscoveryOptionType register(IpV6NeighborDiscoveryOptionType type) {
    return registry.put(type.value(), type);
  }

  @Override
  public int compareTo(Byte o) { return value().compareTo(o); }

  /**
   *
   */
  @Override
  public String valueAsString() {
    return String.valueOf(value() & 0xFF);
  }

}