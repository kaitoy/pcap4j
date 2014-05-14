/*_##########################################################################
  _##
  _##  Copyright (C) 2013-2014  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet.namednumber;

import java.util.HashMap;
import java.util.Map;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.15
 */
public final class IcmpV6Code extends NamedNumber<Byte, IcmpV6Code> {

  // http://www.iana.org/assignments/icmpv6-parameters/icmpv6-parameters.xml#icmpv6-parameters-3

  /**
   *
   */
  private static final long serialVersionUID = 1442278011840551830L;

  /**
   *
   */
  public static final IcmpV6Code NO_CODE
    = new IcmpV6Code((byte)0x00, "No Code");

  //**** Type 1 — Destination Unreachable ****//

  /**
   *
   */
  public static final IcmpV6Code NO_ROUTE_TO_DST
    = new IcmpV6Code((byte)0x00, "no route to destination");

  /**
   *
   */
  public static final IcmpV6Code COMMUNICATION_WITH_DST_PROHIBITED
    = new IcmpV6Code(
        (byte)0x01,
        "communication with destination administratively prohibited"
      );

  /**
   *
   */
  public static final IcmpV6Code BEYOND_SCOPE_OF_SRC_ADDR
    = new IcmpV6Code((byte)0x02, "beyond scope of source address");

  /**
   *
   */
  public static final IcmpV6Code ADDR_UNREACHABLE
    = new IcmpV6Code((byte)0x03, "address unreachable");

  /**
   *
   */
  public static final IcmpV6Code PORT_UNREACHABLE
    = new IcmpV6Code((byte)0x04, "port unreachable");

  /**
   *
   */
  public static final IcmpV6Code SRC_ADDR_FAILED_POLICY
    = new IcmpV6Code((byte)0x05, "source address failed ingress/egress policy");

  /**
   *
   */
  public static final IcmpV6Code REJECT_ROUTE_TO_DST
    = new IcmpV6Code((byte)0x06, "reject route to destination");

  /**
   *
   */
  public static final IcmpV6Code ERROR_IN_SRC_ROUTING_HEADER
    = new IcmpV6Code((byte)0x07, "Error in Source Routing Header");

  //**** Type 3 — Time Exceeded ****//

  /**
   *
   */
  public static final IcmpV6Code HOP_LIMIT_EXCEEDED
    = new IcmpV6Code((byte)0x00, "hop limit exceeded in transit");

  /**
   *
   */
  public static final IcmpV6Code FRAGMENT_REASSEMBLY_TIME_EXCEEDED
    = new IcmpV6Code((byte)0x01, "fragment reassembly time exceeded");

  //**** Type 4 - Parameter Problem ****//

  /**
   *
   */
  public static final IcmpV6Code ERRONEOUS_HEADER_FIELD
    = new IcmpV6Code((byte)0x00, "erroneous header field encountered");

  /**
   *
   */
  public static final IcmpV6Code UNRECOGNIZED_NEXT_HEADER_TYPE
    = new IcmpV6Code((byte)0x01, "unrecognized Next Header type encountered");

  /**
   *
   */
  public static final IcmpV6Code UNRECOGNIZED_IP_V6_OPT
    = new IcmpV6Code((byte)0x02, "unrecognized IPv6 option encountered");

  private static final Map<Byte, Map<Byte, IcmpV6Code>> registry
    = new HashMap<Byte, Map<Byte, IcmpV6Code>>();

  static {
    Map<Byte, IcmpV6Code> map;

    map = new HashMap<Byte, IcmpV6Code>();
    map.put(NO_ROUTE_TO_DST.value(), NO_ROUTE_TO_DST);
    map.put(
      COMMUNICATION_WITH_DST_PROHIBITED.value(),
      COMMUNICATION_WITH_DST_PROHIBITED
    );
    map.put(BEYOND_SCOPE_OF_SRC_ADDR.value(), BEYOND_SCOPE_OF_SRC_ADDR);
    map.put(ADDR_UNREACHABLE.value(), ADDR_UNREACHABLE);
    map.put(PORT_UNREACHABLE.value(), PORT_UNREACHABLE);
    map.put(SRC_ADDR_FAILED_POLICY.value(), SRC_ADDR_FAILED_POLICY);
    map.put(REJECT_ROUTE_TO_DST.value(), REJECT_ROUTE_TO_DST);
    map.put(ERROR_IN_SRC_ROUTING_HEADER.value(), ERROR_IN_SRC_ROUTING_HEADER);
    registry.put(IcmpV6Type.DESTINATION_UNREACHABLE.value(), map);

    map = new HashMap<Byte, IcmpV6Code>();
    map.put(NO_CODE.value(), NO_CODE);
    registry.put(IcmpV6Type.PACKET_TOO_BIG.value(), map);

    map = new HashMap<Byte, IcmpV6Code>();
    map.put(HOP_LIMIT_EXCEEDED.value(), HOP_LIMIT_EXCEEDED);
    map.put(
      FRAGMENT_REASSEMBLY_TIME_EXCEEDED.value(),
      FRAGMENT_REASSEMBLY_TIME_EXCEEDED
    );
    registry.put(IcmpV6Type.TIME_EXCEEDED.value(), map);

    map = new HashMap<Byte, IcmpV6Code>();
    map.put(ERRONEOUS_HEADER_FIELD.value(), ERRONEOUS_HEADER_FIELD);
    map.put(UNRECOGNIZED_NEXT_HEADER_TYPE.value(), UNRECOGNIZED_NEXT_HEADER_TYPE);
    map.put(UNRECOGNIZED_IP_V6_OPT.value(), UNRECOGNIZED_IP_V6_OPT);
    registry.put(IcmpV6Type.PARAMETER_PROBLEM.value(), map);

    map = new HashMap<Byte, IcmpV6Code>();
    map.put(NO_CODE.value(), NO_CODE);
    registry.put(IcmpV6Type.ECHO_REQUEST.value(), map);

    map = new HashMap<Byte, IcmpV6Code>();
    map.put(NO_CODE.value(), NO_CODE);
    registry.put(IcmpV6Type.ECHO_REPLY.value(), map);

    map = new HashMap<Byte, IcmpV6Code>();
    map.put(NO_CODE.value(), NO_CODE);
    registry.put(IcmpV6Type.ROUTER_SOLICITATION.value(), map);

    map = new HashMap<Byte, IcmpV6Code>();
    map.put(NO_CODE.value(), NO_CODE);
    registry.put(IcmpV6Type.ROUTER_ADVERTISEMENT.value(), map);

    map = new HashMap<Byte, IcmpV6Code>();
    map.put(NO_CODE.value(), NO_CODE);
    registry.put(IcmpV6Type.NEIGHBOR_SOLICITATION.value(), map);

    map = new HashMap<Byte, IcmpV6Code>();
    map.put(NO_CODE.value(), NO_CODE);
    registry.put(IcmpV6Type.NEIGHBOR_ADVERTISEMENT.value(), map);

    map = new HashMap<Byte, IcmpV6Code>();
    map.put(NO_CODE.value(), NO_CODE);
    registry.put(IcmpV6Type.REDIRECT.value(), map);
  }

  /**
   *
   * @param value
   * @param name
   */
  public IcmpV6Code(Byte value, String name) {
    super(value, name);
  }

  /**
   *
   * @param type
   * @param value
   * @return an IcmpV6Code object.
   */
  public static IcmpV6Code getInstance(Byte type, Byte value) {
    if (registry.containsKey(type) && registry.get(type).containsKey(value)) {
      return registry.get(type).get(value);
    }
    else {
      return new IcmpV6Code(value, "unknown");
    }
  }

  /**
   *
   * @param type
   * @param code
   * @return an IcmpV6Code object.
   */
  public static IcmpV6Code register(IcmpV6Type type, IcmpV6Code code) {
    if (registry.containsKey(type.value())) {
      return registry.get(type.value()).put(code.value(), code);
    }
    else {
      Map<Byte, IcmpV6Code> map = new HashMap<Byte, IcmpV6Code>();
      map.put(code.value(), code);
      registry.put(type.value(), map);
      return null;
    }
  }

  @Override
  public String valueAsString() {
    return String.valueOf(value() & 0xFF);
  }

  @Override
  public int compareTo(IcmpV6Code o) {
    return value().compareTo(o.value());
  }

}