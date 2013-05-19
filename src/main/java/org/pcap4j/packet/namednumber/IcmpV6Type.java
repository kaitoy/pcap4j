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
public final class IcmpV6Type extends NamedNumber<Byte> {

  // http://www.iana.org/assignments/icmpv6-parameters/icmpv6-parameters.xml

  /**
   *
   */
  private static final long serialVersionUID = 9190204239119018362L;

  /**
   *
   */
  public static final IcmpV6Type DESTINATION_UNREACHABLE
    = new IcmpV6Type((byte)0x01, "Destination Unreachable");

  /**
   *
   */
  public static final IcmpV6Type PACKET_TOO_BIG
    = new IcmpV6Type((byte)0x02, "Packet Too Big");

  /**
   *
   */
  public static final IcmpV6Type TIME_EXCEEDED
    = new IcmpV6Type((byte)0x03, "Time Exceeded");

  /**
   *
   */
  public static final IcmpV6Type PARAMETER_PROBLEM
    = new IcmpV6Type((byte)0x04, "Parameter Problem");

  /**
   *
   */
  public static final IcmpV6Type ECHO_REQUEST
    = new IcmpV6Type((byte)0x80, "Echo Request");

  /**
   *
   */
  public static final IcmpV6Type ECHO_REPLY
    = new IcmpV6Type((byte)0x81, "Echo Reply");

  /**
   *
   */
  public static final IcmpV6Type ROUTER_SOLICITATION
    = new IcmpV6Type((byte)0x85, "Router Solicitation");

  /**
   *
   */
  public static final IcmpV6Type ROUTER_ADVERTISEMENT
    = new IcmpV6Type((byte)0x86, "Router Advertisement");

  /**
   *
   */
  public static final IcmpV6Type NEIGHBOR_SOLICITATION
    = new IcmpV6Type((byte)0x87, "Neighbor Solicitation");

  /**
   *
   */
  public static final IcmpV6Type NEIGHBOR_ADVERTISEMENT
    = new IcmpV6Type((byte)0x88, "Neighbor Advertisement");

  /**
   *
   */
  public static final IcmpV6Type REDIRECT
    = new IcmpV6Type((byte)0x89, "Redirect");

  private static final Map<Byte, IcmpV6Type> registry
    = new HashMap<Byte, IcmpV6Type>();

  static {
    for (Field field: IcmpV6Type.class.getFields()) {
      if (IcmpV6Type.class.isAssignableFrom(field.getType())) {
        try {
          IcmpV6Type f = (IcmpV6Type)field.get(null);
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
  public IcmpV6Type(Byte value, String name) {
    super(value, name);
  }

  /**
   *
   * @param value
   * @return a IcmpV6Type object.
   */
  public static IcmpV6Type getInstance(Byte value) {
    if (registry.containsKey(value)) {
      return registry.get(value);
    }
    else {
      return new IcmpV6Type(value, "unknown");
    }
  }

  /**
   *
   * @param type
   * @return a IcmpV6Type object.
   */
  public static IcmpV6Type register(IcmpV6Type type) {
    return registry.put(type.value(), type);
  }

  @Override
  public String valueAsString() {
    return String.valueOf(value() & 0xFF);
  }

  @Override
  public int compareTo(Byte o) {
    return value().compareTo(o);
  }

}