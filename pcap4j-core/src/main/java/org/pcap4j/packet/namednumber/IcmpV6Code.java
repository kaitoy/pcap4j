/*_##########################################################################
  _##
  _##  Copyright (C) 2013-2018  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.namednumber;

import java.util.HashMap;
import java.util.Map;

/**
 * ICMPv6 Code
 *
 * @see <a
 *     href="http://www.iana.org/assignments/icmpv6-parameters/icmpv6-parameters.xml#icmpv6-parameters-3">IANA
 *     Registry</a>
 * @author Kaito Yamada
 * @since pcap4j 0.9.15
 */
public final class IcmpV6Code extends NamedNumber<Byte, IcmpV6Code> {

  /** */
  private static final long serialVersionUID = 1442278011840551830L;

  /** No Code: 0 */
  public static final IcmpV6Code NO_CODE = new IcmpV6Code((byte) 0x00, "No Code");

  // **** Type 1 — Destination Unreachable ****//

  /** [Type 1 — Destination Unreachable] no route to destination: 0 */
  public static final IcmpV6Code NO_ROUTE_TO_DST =
      new IcmpV6Code((byte) 0, "no route to destination");

  /**
   * [Type 1 — Destination Unreachable] communication with destination administratively prohibited:
   * 1
   */
  public static final IcmpV6Code COMMUNICATION_WITH_DST_PROHIBITED =
      new IcmpV6Code((byte) 1, "communication with destination administratively prohibited");

  /** [Type 1 — Destination Unreachable] beyond scope of source address: 2 */
  public static final IcmpV6Code BEYOND_SCOPE_OF_SRC_ADDR =
      new IcmpV6Code((byte) 2, "beyond scope of source address");

  /** [Type 1 — Destination Unreachable] address unreachable: 3 */
  public static final IcmpV6Code ADDR_UNREACHABLE = new IcmpV6Code((byte) 3, "address unreachable");

  /** [Type 1 — Destination Unreachable] port unreachable: 4 */
  public static final IcmpV6Code PORT_UNREACHABLE = new IcmpV6Code((byte) 4, "port unreachable");

  /** [Type 1 — Destination Unreachable] source address failed ingress/egress policy: 5 */
  public static final IcmpV6Code SRC_ADDR_FAILED_POLICY =
      new IcmpV6Code((byte) 5, "source address failed ingress/egress policy");

  /** [Type 1 — Destination Unreachable] reject route to destination: 6 */
  public static final IcmpV6Code REJECT_ROUTE_TO_DST =
      new IcmpV6Code((byte) 6, "reject route to destination");

  /** [Type 1 — Destination Unreachable] Error in Source Routing Header: 7 */
  public static final IcmpV6Code ERROR_IN_SRC_ROUTING_HEADER =
      new IcmpV6Code((byte) 7, "Error in Source Routing Header");

  // **** Type 3 — Time Exceeded ****//

  /** [Type 3 — Time Exceeded] hop limit exceeded in transit: 0 */
  public static final IcmpV6Code HOP_LIMIT_EXCEEDED =
      new IcmpV6Code((byte) 0, "hop limit exceeded in transit");

  /** [Type 3 — Time Exceeded] fragment reassembly time exceeded: 1 */
  public static final IcmpV6Code FRAGMENT_REASSEMBLY_TIME_EXCEEDED =
      new IcmpV6Code((byte) 1, "fragment reassembly time exceeded");

  // **** Type 4 - Parameter Problem ****//

  /** [Type 4 - Parameter Problem] erroneous header field encountered: 0 */
  public static final IcmpV6Code ERRONEOUS_HEADER_FIELD =
      new IcmpV6Code((byte) 0, "erroneous header field encountered");

  /** [Type 4 - Parameter Problem] unrecognized Next Header type encountered: 1 */
  public static final IcmpV6Code UNRECOGNIZED_NEXT_HEADER_TYPE =
      new IcmpV6Code((byte) 1, "unrecognized Next Header type encountered");

  /** [Type 4 - Parameter Problem] unrecognized IPv6 option encountered: 2 */
  public static final IcmpV6Code UNRECOGNIZED_IP_V6_OPT =
      new IcmpV6Code((byte) 2, "unrecognized IPv6 option encountered");

  /** [Type 4 - Parameter Problem] IPv6 First Fragment has incomplete IPv6 Header Chain: 3 */
  public static final IcmpV6Code FIRST_FRAGMENT_HAS_INCOMPLETE_IP_V6_HEADER_CHAIN =
      new IcmpV6Code((byte) 3, "IPv6 First Fragment has incomplete IPv6 Header Chain");

  // **** Type 138 - Router Renumbering ****//

  /** [Type 138 - Router Renumbering] Router Renumbering Command: 0 */
  public static final IcmpV6Code ROUTER_RENUMBERING_COMMAND =
      new IcmpV6Code((byte) 0, "Router Renumbering Command");

  /** [Type 138 - Router Renumbering] Router Renumbering Result: 1 */
  public static final IcmpV6Code ROUTER_RENUMBERING_RESULT =
      new IcmpV6Code((byte) 1, "Router Renumbering Result");

  /** [Type 138 - Router Renumbering] Sequence Number Reset: 255 */
  public static final IcmpV6Code SEQUENCE_NUMBER_RESET =
      new IcmpV6Code((byte) 255, "Sequence Number Reset");

  // **** Type 139 - ICMP Node Information Query ****//

  /**
   * [Type 139 - ICMP Node Information Query] The Data field contains an IPv6 address which is the
   * Subject of this Query: 0
   */
  public static final IcmpV6Code SUBJECT_IP_V6_ADDRESS =
      new IcmpV6Code((byte) 0, "Subject IPv6 address");

  /**
   * [Type 139 - ICMP Node Information Query] The Data field contains a name which is the Subject of
   * this Query, or is empty, as in the case of a NOOP: 1
   */
  public static final IcmpV6Code SUBJECT_NAME = new IcmpV6Code((byte) 1, "Subject name");

  /**
   * [Type 139 - ICMP Node Information Query] The Data field contains an IPv4 address which is the
   * Subject of this Query: 2
   */
  public static final IcmpV6Code SUBJECT_IP_V4_ADDRESS =
      new IcmpV6Code((byte) 2, "Subject IPv4 address");

  // **** Type 140 - ICMP Node Information Response ****//

  /**
   * [Type 140 - ICMP Node Information Response] A successful reply. The Reply Data field may or may
   * not be empty: 0
   */
  public static final IcmpV6Code SUCCESSFUL_REPLY = new IcmpV6Code((byte) 0, "Successful reply");

  /**
   * [Type 140 - ICMP Node Information Response] The Responder refuses to supply the answer. The
   * Reply Data field will be empty: 1
   */
  public static final IcmpV6Code REFUSE = new IcmpV6Code((byte) 1, "Refuse");

  /**
   * [Type 140 - ICMP Node Information Response] The Qtype of the Query is unknown to the Responder.
   * The Reply Data field will be empty: 2
   */
  public static final IcmpV6Code UNKNOWN_QTYPE = new IcmpV6Code((byte) 2, "Unknown Qtype");

  private static final Map<Byte, Map<Byte, IcmpV6Code>> registry =
      new HashMap<Byte, Map<Byte, IcmpV6Code>>();

  static {
    Map<Byte, IcmpV6Code> map;

    // Type 1 - Destination Unreachable
    map = new HashMap<Byte, IcmpV6Code>();
    map.put(NO_ROUTE_TO_DST.value(), NO_ROUTE_TO_DST);
    map.put(COMMUNICATION_WITH_DST_PROHIBITED.value(), COMMUNICATION_WITH_DST_PROHIBITED);
    map.put(BEYOND_SCOPE_OF_SRC_ADDR.value(), BEYOND_SCOPE_OF_SRC_ADDR);
    map.put(ADDR_UNREACHABLE.value(), ADDR_UNREACHABLE);
    map.put(PORT_UNREACHABLE.value(), PORT_UNREACHABLE);
    map.put(SRC_ADDR_FAILED_POLICY.value(), SRC_ADDR_FAILED_POLICY);
    map.put(REJECT_ROUTE_TO_DST.value(), REJECT_ROUTE_TO_DST);
    map.put(ERROR_IN_SRC_ROUTING_HEADER.value(), ERROR_IN_SRC_ROUTING_HEADER);
    registry.put(IcmpV6Type.DESTINATION_UNREACHABLE.value(), map);

    // Type 2 - Packet Too Big
    map = new HashMap<Byte, IcmpV6Code>();
    map.put(NO_CODE.value(), NO_CODE);
    registry.put(IcmpV6Type.PACKET_TOO_BIG.value(), map);

    // Type 3 - Time Exceeded
    map = new HashMap<Byte, IcmpV6Code>();
    map.put(HOP_LIMIT_EXCEEDED.value(), HOP_LIMIT_EXCEEDED);
    map.put(FRAGMENT_REASSEMBLY_TIME_EXCEEDED.value(), FRAGMENT_REASSEMBLY_TIME_EXCEEDED);
    registry.put(IcmpV6Type.TIME_EXCEEDED.value(), map);

    // Type 4 - Parameter Problem
    map = new HashMap<Byte, IcmpV6Code>();
    map.put(ERRONEOUS_HEADER_FIELD.value(), ERRONEOUS_HEADER_FIELD);
    map.put(UNRECOGNIZED_NEXT_HEADER_TYPE.value(), UNRECOGNIZED_NEXT_HEADER_TYPE);
    map.put(UNRECOGNIZED_IP_V6_OPT.value(), UNRECOGNIZED_IP_V6_OPT);
    map.put(
        FIRST_FRAGMENT_HAS_INCOMPLETE_IP_V6_HEADER_CHAIN.value(),
        FIRST_FRAGMENT_HAS_INCOMPLETE_IP_V6_HEADER_CHAIN);
    registry.put(IcmpV6Type.PARAMETER_PROBLEM.value(), map);

    // Type 128 - Echo Request
    map = new HashMap<Byte, IcmpV6Code>();
    map.put(NO_CODE.value(), NO_CODE);
    registry.put(IcmpV6Type.ECHO_REQUEST.value(), map);

    // Type 129 - Echo Reply
    map = new HashMap<Byte, IcmpV6Code>();
    map.put(NO_CODE.value(), NO_CODE);
    registry.put(IcmpV6Type.ECHO_REPLY.value(), map);

    // Type 130 - Multicast Listener Query
    map = new HashMap<Byte, IcmpV6Code>();
    map.put(NO_CODE.value(), NO_CODE);
    registry.put(IcmpV6Type.MULTICAST_LISTENER_QUERY.value(), map);

    // Type 131 - Multicast Listener Report
    map = new HashMap<Byte, IcmpV6Code>();
    map.put(NO_CODE.value(), NO_CODE);
    registry.put(IcmpV6Type.MULTICAST_LISTENER_REPORT.value(), map);

    // Type 131 - Multicast Listener Done
    map = new HashMap<Byte, IcmpV6Code>();
    map.put(NO_CODE.value(), NO_CODE);
    registry.put(IcmpV6Type.MULTICAST_LISTENER_DONE.value(), map);

    // Type 133 - Router Solicitation
    map = new HashMap<Byte, IcmpV6Code>();
    map.put(NO_CODE.value(), NO_CODE);
    registry.put(IcmpV6Type.ROUTER_SOLICITATION.value(), map);

    // Type 134 - Router Advertisement
    map = new HashMap<Byte, IcmpV6Code>();
    map.put(NO_CODE.value(), NO_CODE);
    registry.put(IcmpV6Type.ROUTER_ADVERTISEMENT.value(), map);

    // Type 135 - Neighbor Solicitation
    map = new HashMap<Byte, IcmpV6Code>();
    map.put(NO_CODE.value(), NO_CODE);
    registry.put(IcmpV6Type.NEIGHBOR_SOLICITATION.value(), map);

    // Type 136 - Neighbor Advertisement
    map = new HashMap<Byte, IcmpV6Code>();
    map.put(NO_CODE.value(), NO_CODE);
    registry.put(IcmpV6Type.NEIGHBOR_ADVERTISEMENT.value(), map);

    // Type 137 - Redirect
    map = new HashMap<Byte, IcmpV6Code>();
    map.put(NO_CODE.value(), NO_CODE);
    registry.put(IcmpV6Type.REDIRECT.value(), map);

    // Type 138 - Router Renumbering
    map = new HashMap<Byte, IcmpV6Code>();
    map.put(ROUTER_RENUMBERING_COMMAND.value(), ROUTER_RENUMBERING_COMMAND);
    map.put(ROUTER_RENUMBERING_RESULT.value(), ROUTER_RENUMBERING_RESULT);
    map.put(SEQUENCE_NUMBER_RESET.value(), SEQUENCE_NUMBER_RESET);
    registry.put(IcmpV6Type.ROUTER_RENUMBERING.value(), map);

    // Type 139 - ICMP Node Information Query
    map = new HashMap<Byte, IcmpV6Code>();
    map.put(SUBJECT_IP_V6_ADDRESS.value(), SUBJECT_IP_V6_ADDRESS);
    map.put(SUBJECT_NAME.value(), SUBJECT_NAME);
    map.put(SUBJECT_IP_V4_ADDRESS.value(), SUBJECT_IP_V4_ADDRESS);
    registry.put(IcmpV6Type.ICMP_NODE_INFORMATION_QUERY.value(), map);

    // Type 140 - ICMP Node Information Response
    map = new HashMap<Byte, IcmpV6Code>();
    map.put(SUCCESSFUL_REPLY.value(), SUCCESSFUL_REPLY);
    map.put(REFUSE.value(), REFUSE);
    map.put(UNKNOWN_QTYPE.value(), UNKNOWN_QTYPE);
    registry.put(IcmpV6Type.ICMP_NODE_INFORMATION_RESPONSE.value(), map);

    // Type 141 - Inverse Neighbor Discovery
    map = new HashMap<Byte, IcmpV6Code>();
    map.put(NO_CODE.value(), NO_CODE);
    registry.put(IcmpV6Type.INVERSE_NEIGHBOR_DISCOVERY_SOLICITATION.value(), map);

    // Type 142 - Inverse Neighbor Discovery
    map = new HashMap<Byte, IcmpV6Code>();
    map.put(NO_CODE.value(), NO_CODE);
    registry.put(IcmpV6Type.INVERSE_NEIGHBOR_DISCOVERY_ADVERTISEMENT.value(), map);

    // Type 144 - Home Agent Address Discovery
    map = new HashMap<Byte, IcmpV6Code>();
    map.put(NO_CODE.value(), NO_CODE);
    registry.put(IcmpV6Type.HOME_AGENT_ADDRESS_DISCOVERY_REQUEST.value(), map);

    // Type 145 - Home Agent Address Discovery
    map = new HashMap<Byte, IcmpV6Code>();
    map.put(NO_CODE.value(), NO_CODE);
    registry.put(IcmpV6Type.HOME_AGENT_ADDRESS_DISCOVERY_REPLY.value(), map);

    // Type 146 - Mobile Prefix Solicitation
    map = new HashMap<Byte, IcmpV6Code>();
    map.put(NO_CODE.value(), NO_CODE);
    registry.put(IcmpV6Type.MOBILE_PREFIX_SOLICITATION.value(), map);

    // Type 146 - Mobile Prefix Advertisement
    map = new HashMap<Byte, IcmpV6Code>();
    map.put(NO_CODE.value(), NO_CODE);
    registry.put(IcmpV6Type.MOBILE_PREFIX_ADVERTISEMENT.value(), map);
  }

  /**
   * @param value value
   * @param name name
   */
  public IcmpV6Code(Byte value, String name) {
    super(value, name);
  }

  /**
   * @param type ICMPv6 type
   * @param value value
   * @return an IcmpV6Code object.
   */
  public static IcmpV6Code getInstance(Byte type, Byte value) {
    if (registry.containsKey(type) && registry.get(type).containsKey(value)) {
      return registry.get(type).get(value);
    } else {
      return new IcmpV6Code(value, "unknown");
    }
  }

  /**
   * @param type type
   * @param code code
   * @return an IcmpV6Code object.
   */
  public static IcmpV6Code register(IcmpV6Type type, IcmpV6Code code) {
    if (registry.containsKey(type.value())) {
      return registry.get(type.value()).put(code.value(), code);
    } else {
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
