/*_##########################################################################
  _##
  _##  Copyright (C) 2011  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet.namedvalue;

import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Map;
import org.pcap4j.packet.IcmpV4Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.UdpPacket;

public
final class IpNumber
extends NamedNumber<Byte> implements Comparable<Byte> {

  // http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xml
  public static final IpNumber HOPOPT
    = new IpNumber((byte)0, "IPv6 Hop-by-Hop Option");
  public static final IpNumber ICMP_V4
    = new IpNumber((byte)1, "ICMPv4");
  public static final IpNumber IGMP
    = new IpNumber((byte)2, "IGMP");
  public static final IpNumber IP_V4
    = new IpNumber((byte)4, "IPv4 encapsulation");
  public static final IpNumber TCP
    = new IpNumber((byte)6, "TCP");
  public static final IpNumber EGP
    = new IpNumber((byte)8, "EGP");
  public static final IpNumber IGP
    = new IpNumber((byte)9, "IGP(any private interior gateway)");
  public static final IpNumber UDP
    = new IpNumber((byte)17, "UDP");
  public static final IpNumber IP_V6
    = new IpNumber((byte)41, "IPv6 encapsulation");
  public static final IpNumber IP_V6_ROUTE
    = new IpNumber((byte)43, "Routing Header for IPv6");
  public static final IpNumber IP_V6_FRAG
    = new IpNumber((byte)44, "Fragment Header for IPv6");
  public static final IpNumber RSVP
    = new IpNumber((byte)46, "RSVP");
  public static final IpNumber AH
    = new IpNumber((byte)51, "Authentication Header");
  public static final IpNumber ICMP_V6
    = new IpNumber((byte)58, "ICMPv6");
  public static final IpNumber IP_V6_NONXT
    = new IpNumber((byte)59, "No Next Header for IPv6");
  public static final IpNumber IP_V6_OPTS
    = new IpNumber((byte)60, "Destination Options for IPv6");
  public static final IpNumber VRRP
    = new IpNumber((byte)112, "VRRP");
  public static final IpNumber L2TP
    = new IpNumber((byte)115, "L2TP");

  private static Map<Byte, IpNumber> registry
    = new HashMap<Byte, IpNumber>();
  private static Map<Class<? extends Packet>, IpNumber> IpNumberOfPacket
    = new HashMap<Class<? extends Packet>, IpNumber>();

  static {
    for (Field field: IpNumber.class.getFields()) {
      if (field.getType().isAssignableFrom(IpNumber.class)) {
        try {
          IpNumber typeCode = (IpNumber)field.get(null);
          registry.put(typeCode.value(), typeCode);
        } catch (IllegalArgumentException e) {
          throw new AssertionError(e);
        } catch (IllegalAccessException e) {
          throw new AssertionError(e);
        } catch (NullPointerException e) {
          continue;
        }
      }
    }

    IpNumberOfPacket.put(IcmpV4Packet.class, ICMP_V4);
    IpNumberOfPacket.put(UdpPacket.class, UDP);
  }

  private IpNumber(Byte value, String name) {
    super(value, name);
  }

  public static IpNumber getInstance(Byte value) {
    if (registry.containsKey(value)) {
      return registry.get(value);
    }
    else {
      return new IpNumber(value, "unknown");
    }
  }

  public static IpNumber getInstance(Class<? extends Packet> clazz) {
    return IpNumberOfPacket.get(clazz);
  }

  @Override
  public String valueAsString() {
    return String.valueOf(value() & 0xFF);
  }

  public int compareTo(Byte o) {
    return value().compareTo(o);
  }

}