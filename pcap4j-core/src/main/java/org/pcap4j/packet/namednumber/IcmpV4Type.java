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
 * ICMPv4 Type
 *
 * @see <a
 *     href="http://www.iana.org/assignments/icmp-parameters/icmp-parameters.xml#icmp-parameters-types">IANA
 *     Registry</a>
 * @author Kaito Yamada
 * @since pcap4j 0.9.11
 */
public final class IcmpV4Type extends NamedNumber<Byte, IcmpV4Type> {

  /** */
  private static final long serialVersionUID = -6737808159892354431L;

  /** Echo Reply: 0 */
  public static final IcmpV4Type ECHO_REPLY = new IcmpV4Type((byte) 0, "Echo Reply");

  /** Destination Unreachable: 3 */
  public static final IcmpV4Type DESTINATION_UNREACHABLE =
      new IcmpV4Type((byte) 3, "Destination Unreachable");

  /** Source Quench: 4 */
  public static final IcmpV4Type SOURCE_QUENCH = new IcmpV4Type((byte) 4, "Source Quench");

  /** Redirect: 5 */
  public static final IcmpV4Type REDIRECT = new IcmpV4Type((byte) 5, "Redirect");

  /** Alternate Host Address: 6 */
  public static final IcmpV4Type ALTERNATE_HOST_ADDRESS =
      new IcmpV4Type((byte) 6, "Alternate Host Address");

  /** Echo: 8 */
  public static final IcmpV4Type ECHO = new IcmpV4Type((byte) 8, "Echo");

  /** Router Advertisement: 9 */
  public static final IcmpV4Type ROUTER_ADVERTISEMENT =
      new IcmpV4Type((byte) 9, "Router Advertisement");

  /** Router Solicitation: 10 */
  public static final IcmpV4Type ROUTER_SOLICITATION =
      new IcmpV4Type((byte) 10, "Router Solicitation");

  /** Time Exceeded: 11 */
  public static final IcmpV4Type TIME_EXCEEDED = new IcmpV4Type((byte) 11, "Time Exceeded");

  /** Parameter Problem: 12 */
  public static final IcmpV4Type PARAMETER_PROBLEM = new IcmpV4Type((byte) 12, "Parameter Problem");

  /** Timestamp: 13 */
  public static final IcmpV4Type TIMESTAMP = new IcmpV4Type((byte) 13, "Timestamp");

  /** Timestamp Reply: 14 */
  public static final IcmpV4Type TIMESTAMP_REPLY = new IcmpV4Type((byte) 14, "Timestamp Reply");

  /** Information Request: 15 */
  public static final IcmpV4Type INFORMATION_REQUEST =
      new IcmpV4Type((byte) 15, "Information Request");

  /** Information Reply: 16 */
  public static final IcmpV4Type INFORMATION_REPLY = new IcmpV4Type((byte) 16, "Information Reply");

  /** Address Mask Request: 17 */
  public static final IcmpV4Type ADDRESS_MASK_REQUEST =
      new IcmpV4Type((byte) 17, "Address Mask Request");

  /** Address Mask Reply: 18 */
  public static final IcmpV4Type ADDRESS_MASK_REPLY =
      new IcmpV4Type((byte) 18, "Address Mask Reply");

  /** Traceroute: 30 */
  public static final IcmpV4Type TRACEROUTE = new IcmpV4Type((byte) 30, "Traceroute");

  /** Datagram Conversion Error: 31 */
  public static final IcmpV4Type DATAGRAM_CONVERSION_ERROR =
      new IcmpV4Type((byte) 31, "Datagram Conversion Error");

  /** Mobile Host Redirect: 32 */
  public static final IcmpV4Type MOBILE_HOST_REDIRECT =
      new IcmpV4Type((byte) 32, "Mobile Host Redirect");

  /** IPv6 Where-Are-You: 33 */
  public static final IcmpV4Type IPV6_WHERE_ARE_YOU =
      new IcmpV4Type((byte) 33, "IPv6 Where-Are-You");

  /** IPv6 I-Am-Here: 34 */
  public static final IcmpV4Type IPV6_I_AM_HERE = new IcmpV4Type((byte) 34, "IPv6 I-Am-Here");

  /** Mobile Registration Request: 35 */
  public static final IcmpV4Type MOBILE_REGISTRATION_REQUEST =
      new IcmpV4Type((byte) 35, "Mobile Registration Request");

  /** Mobile Registration Reply: 36 */
  public static final IcmpV4Type MOBILE_REGISTRATION_REPLY =
      new IcmpV4Type((byte) 36, "Mobile Registration Reply");

  /** Domain Name Request: 37 */
  public static final IcmpV4Type DOMAIN_NAME_REQUEST =
      new IcmpV4Type((byte) 37, "Domain Name Request");

  /** Domain Name Reply: 38 */
  public static final IcmpV4Type DOMAIN_NAME_REPLY = new IcmpV4Type((byte) 38, "Domain Name Reply");

  /** SKIP: 39 */
  public static final IcmpV4Type SKIP = new IcmpV4Type((byte) 39, "SKIP");

  /** Photuris: 40 */
  public static final IcmpV4Type PHOTURIS = new IcmpV4Type((byte) 40, "Photuris");

  private static final Map<Byte, IcmpV4Type> registry = new HashMap<Byte, IcmpV4Type>();

  static {
    registry.put(ECHO_REPLY.value(), ECHO_REPLY);
    registry.put(DESTINATION_UNREACHABLE.value(), DESTINATION_UNREACHABLE);
    registry.put(SOURCE_QUENCH.value(), SOURCE_QUENCH);
    registry.put(REDIRECT.value(), REDIRECT);
    registry.put(ALTERNATE_HOST_ADDRESS.value(), ALTERNATE_HOST_ADDRESS);
    registry.put(ECHO.value(), ECHO);
    registry.put(ROUTER_ADVERTISEMENT.value(), ROUTER_ADVERTISEMENT);
    registry.put(ROUTER_SOLICITATION.value(), ROUTER_SOLICITATION);
    registry.put(TIME_EXCEEDED.value(), TIME_EXCEEDED);
    registry.put(PARAMETER_PROBLEM.value(), PARAMETER_PROBLEM);
    registry.put(TIMESTAMP.value(), TIMESTAMP);
    registry.put(TIMESTAMP_REPLY.value(), TIMESTAMP_REPLY);
    registry.put(INFORMATION_REQUEST.value(), INFORMATION_REQUEST);
    registry.put(INFORMATION_REPLY.value(), INFORMATION_REPLY);
    registry.put(ADDRESS_MASK_REQUEST.value(), ADDRESS_MASK_REQUEST);
    registry.put(ADDRESS_MASK_REPLY.value(), ADDRESS_MASK_REPLY);
    registry.put(TRACEROUTE.value(), TRACEROUTE);
    registry.put(DATAGRAM_CONVERSION_ERROR.value(), DATAGRAM_CONVERSION_ERROR);
    registry.put(MOBILE_HOST_REDIRECT.value(), MOBILE_HOST_REDIRECT);
    registry.put(IPV6_WHERE_ARE_YOU.value(), IPV6_WHERE_ARE_YOU);
    registry.put(IPV6_I_AM_HERE.value(), IPV6_I_AM_HERE);
    registry.put(MOBILE_REGISTRATION_REQUEST.value(), MOBILE_REGISTRATION_REQUEST);
    registry.put(MOBILE_REGISTRATION_REPLY.value(), MOBILE_REGISTRATION_REPLY);
    registry.put(DOMAIN_NAME_REQUEST.value(), DOMAIN_NAME_REQUEST);
    registry.put(DOMAIN_NAME_REPLY.value(), DOMAIN_NAME_REPLY);
    registry.put(SKIP.value(), SKIP);
    registry.put(PHOTURIS.value(), PHOTURIS);
  }

  /**
   * @param value value
   * @param name name
   */
  public IcmpV4Type(Byte value, String name) {
    super(value, name);
  }

  /**
   * @param value value
   * @return a IcmpV4Type object.
   */
  public static IcmpV4Type getInstance(Byte value) {
    if (registry.containsKey(value)) {
      return registry.get(value);
    } else {
      return new IcmpV4Type(value, "unknown");
    }
  }

  /**
   * @param type type
   * @return a IcmpV4Type object.
   */
  public static IcmpV4Type register(IcmpV4Type type) {
    return registry.put(type.value(), type);
  }

  @Override
  public String valueAsString() {
    return String.valueOf(value() & 0xFF);
  }

  @Override
  public int compareTo(IcmpV4Type o) {
    return value().compareTo(o.value());
  }
}
