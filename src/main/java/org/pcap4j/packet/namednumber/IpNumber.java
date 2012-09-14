/*_##########################################################################
  _##
  _##  Copyright (C) 2011-2012  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet.namednumber;

import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Map;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.1
 */
public final class IpNumber extends NamedNumber<Byte> {

  /**
   *
   */
  private static final long serialVersionUID = -3109332132272568136L;

  // http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xml

  /**
   *
   */
  public static final IpNumber IPV6_HOPOPT
    = new IpNumber((byte)0, "IPv6 Hop-by-Hop Option");

  /**
   *
   */
  public static final IpNumber ICMPV4
    = new IpNumber((byte)1, "ICMPv4");

  /**
   *
   */
  public static final IpNumber IGMP
    = new IpNumber((byte)2, "IGMP");

  /**
   *
   */
  public static final IpNumber IPV4
    = new IpNumber((byte)4, "IPv4 encapsulation");

  /**
   *
   */
  public static final IpNumber TCP
    = new IpNumber((byte)6, "TCP");

  /**
   *
   */
  public static final IpNumber EGP
    = new IpNumber((byte)8, "EGP");

  /**
   *
   */
  public static final IpNumber IGP
    = new IpNumber((byte)9, "IGP(any private interior gateway)");

  /**
   *
   */
  public static final IpNumber UDP
    = new IpNumber((byte)17, "UDP");

  /**
   *
   */
  public static final IpNumber IPV6
    = new IpNumber((byte)41, "IPv6 encapsulation");

  /**
   *
   */
  public static final IpNumber IPV6_ROUTE
    = new IpNumber((byte)43, "Routing Header for IPv6");

  /**
   *
   */
  public static final IpNumber IPV6_FRAG
    = new IpNumber((byte)44, "Fragment Header for IPv6");

  /**
   *
   */
  public static final IpNumber RSVP
    = new IpNumber((byte)46, "RSVP");

  /**
   *
   */
  public static final IpNumber AH
    = new IpNumber((byte)51, "Authentication Header");

  /**
   *
   */
  public static final IpNumber ICMPV6
    = new IpNumber((byte)58, "ICMPv6");

  /**
   *
   */
  public static final IpNumber IPV6_NONXT
    = new IpNumber((byte)59, "No Next Header for IPv6");

  /**
   *
   */
  public static final IpNumber IPV6_DST_OPTS
    = new IpNumber((byte)60, "Destination Options for IPv6");

  /**
   *
   */
  public static final IpNumber VRRP
    = new IpNumber((byte)112, "VRRP");

  /**
   *
   */
  public static final IpNumber L2TP
    = new IpNumber((byte)115, "L2TP");

  private static final Map<Byte, IpNumber> registry
    = new HashMap<Byte, IpNumber>();

  static {
    for (Field field: IpNumber.class.getFields()) {
      if (IpNumber.class.isAssignableFrom(field.getType())) {
        try {
          IpNumber f = (IpNumber)field.get(null);
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
  public IpNumber(Byte value, String name) {
    super(value, name);
  }

  /**
   *
   * @param value
   * @return
   */
  public static IpNumber getInstance(Byte value) {
    if (registry.containsKey(value)) {
      return registry.get(value);
    }
    else {
      return new IpNumber(value, "unknown");
    }
  }

  /**
   *
   * @param number
   * @return
   */
  public static IpNumber register(IpNumber number) {
    return registry.put(number.value(), number);
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