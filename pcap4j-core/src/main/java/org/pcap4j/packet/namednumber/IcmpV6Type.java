/*_##########################################################################
  _##
  _##  Copyright (C) 2013-2015  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.namednumber;

import java.util.HashMap;
import java.util.Map;

/**
 * ICMPv6 Type
 *
 * @see <a
 *     href="http://www.iana.org/assignments/icmpv6-parameters/icmpv6-parameters.xml#icmpv6-parameters-2">IANA
 *     Registry</a>
 * @author Kaito Yamada
 * @since pcap4j 0.9.15
 */
public final class IcmpV6Type extends NamedNumber<Byte, IcmpV6Type> {

  /** */
  private static final long serialVersionUID = 9190204239119018362L;

  /** Destination Unreachable: 1 */
  public static final IcmpV6Type DESTINATION_UNREACHABLE =
      new IcmpV6Type((byte) 1, "Destination Unreachable");

  /** Packet Too Big: 2 */
  public static final IcmpV6Type PACKET_TOO_BIG = new IcmpV6Type((byte) 2, "Packet Too Big");

  /** Time Exceeded: 3 */
  public static final IcmpV6Type TIME_EXCEEDED = new IcmpV6Type((byte) 3, "Time Exceeded");

  /** Parameter Problem: 4 */
  public static final IcmpV6Type PARAMETER_PROBLEM = new IcmpV6Type((byte) 4, "Parameter Problem");

  /** Echo Request: 128 */
  public static final IcmpV6Type ECHO_REQUEST = new IcmpV6Type((byte) 128, "Echo Request");

  /** Echo Reply: 129 */
  public static final IcmpV6Type ECHO_REPLY = new IcmpV6Type((byte) 129, "Echo Reply");

  /** Multicast Listener Query: 130 */
  public static final IcmpV6Type MULTICAST_LISTENER_QUERY =
      new IcmpV6Type((byte) 130, "Multicast Listener Query");

  /** Multicast Listener Report: 131 */
  public static final IcmpV6Type MULTICAST_LISTENER_REPORT =
      new IcmpV6Type((byte) 131, "Multicast Listener Report");

  /** Multicast Listener Done: 132 */
  public static final IcmpV6Type MULTICAST_LISTENER_DONE =
      new IcmpV6Type((byte) 132, "Multicast Listener Done");

  /** Router Solicitation: 133 */
  public static final IcmpV6Type ROUTER_SOLICITATION =
      new IcmpV6Type((byte) 133, "Router Solicitation");

  /** Router Advertisement: 134 */
  public static final IcmpV6Type ROUTER_ADVERTISEMENT =
      new IcmpV6Type((byte) 134, "Router Advertisement");

  /** Neighbor Solicitation: 135 */
  public static final IcmpV6Type NEIGHBOR_SOLICITATION =
      new IcmpV6Type((byte) 135, "Neighbor Solicitation");

  /** Neighbor Advertisement: 136 */
  public static final IcmpV6Type NEIGHBOR_ADVERTISEMENT =
      new IcmpV6Type((byte) 136, "Neighbor Advertisement");

  /** Redirect: 137 */
  public static final IcmpV6Type REDIRECT = new IcmpV6Type((byte) 137, "Redirect");

  /** Router Renumbering: 138 */
  public static final IcmpV6Type ROUTER_RENUMBERING =
      new IcmpV6Type((byte) 138, "Router Renumbering");

  /** ICMP Node Information Query: 139 */
  public static final IcmpV6Type ICMP_NODE_INFORMATION_QUERY =
      new IcmpV6Type((byte) 139, "ICMP Node Information Query");

  /** ICMP Node Information Response: 140 */
  public static final IcmpV6Type ICMP_NODE_INFORMATION_RESPONSE =
      new IcmpV6Type((byte) 140, "ICMP Node Information Response");

  /** Inverse Neighbor Discovery Solicitation: 141 */
  public static final IcmpV6Type INVERSE_NEIGHBOR_DISCOVERY_SOLICITATION =
      new IcmpV6Type((byte) 141, "Inverse Neighbor Discovery Solicitation");

  /** Inverse Neighbor Discovery Advertisement: 142 */
  public static final IcmpV6Type INVERSE_NEIGHBOR_DISCOVERY_ADVERTISEMENT =
      new IcmpV6Type((byte) 142, "Inverse Neighbor Discovery Advertisement");

  /** Version 2 Multicast Listener Report: 143 */
  public static final IcmpV6Type V2_MULTICAST_LISTENER_REPORT =
      new IcmpV6Type((byte) 143, "Version 2 Multicast Listener Report");

  /** Home Agent Address Discovery Request: 144 */
  public static final IcmpV6Type HOME_AGENT_ADDRESS_DISCOVERY_REQUEST =
      new IcmpV6Type((byte) 144, "Home Agent Address Discovery Request");

  /** Home Agent Address Discovery Reply: 145 */
  public static final IcmpV6Type HOME_AGENT_ADDRESS_DISCOVERY_REPLY =
      new IcmpV6Type((byte) 145, "Home Agent Address Discovery Reply");

  /** Mobile Prefix Solicitation: 146 */
  public static final IcmpV6Type MOBILE_PREFIX_SOLICITATION =
      new IcmpV6Type((byte) 146, "Mobile Prefix Solicitation");

  /** Mobile Prefix Advertisement: 147 */
  public static final IcmpV6Type MOBILE_PREFIX_ADVERTISEMENT =
      new IcmpV6Type((byte) 147, "Mobile Prefix Advertisement");

  /** Certification Path Solicitation: 148 */
  public static final IcmpV6Type CERTIFICATION_PATH_SOLICITATION =
      new IcmpV6Type((byte) 148, "Certification Path Solicitation");

  /** Certification Path Advertisement: 149 */
  public static final IcmpV6Type CERTIFICATION_PATH_ADVERTISEMENT =
      new IcmpV6Type((byte) 149, "Certification Path Advertisement");

  /** Multicast Router Advertisement: 151 */
  public static final IcmpV6Type MULTICAST_ROUTER_ADVERTISEMENT =
      new IcmpV6Type((byte) 151, "Multicast Router Advertisement");

  /** Multicast Router Solicitation: 152 */
  public static final IcmpV6Type MULTICAST_ROUTER_SOLICITATION =
      new IcmpV6Type((byte) 152, "Multicast Router Solicitation");

  /** Multicast Router Termination: 153 */
  public static final IcmpV6Type MULTICAST_ROUTER_TERMINATION =
      new IcmpV6Type((byte) 153, "Multicast Router Termination");

  /** FMIPv6: 154 */
  public static final IcmpV6Type FMIP_V6 = new IcmpV6Type((byte) 154, "FMIPv6");

  /** RPL Control: 155 */
  public static final IcmpV6Type RPL_CONTROL = new IcmpV6Type((byte) 155, "RPL Control");

  /** ILNPv6 Locator Update: 156 */
  public static final IcmpV6Type ILNP_V6_LOCATOR_UPDATE =
      new IcmpV6Type((byte) 156, "ILNPv6 Locator Update");

  /** Duplicate Address Request: 157 */
  public static final IcmpV6Type DUPLICATE_ADDRESS_REQUEST =
      new IcmpV6Type((byte) 157, "Duplicate Address Request");

  /** Duplicate Address Confirmation: 158 */
  public static final IcmpV6Type DUPLICATE_ADDRESS_CONFIRMATION =
      new IcmpV6Type((byte) 158, "Duplicate Address Confirmation");

  private static final Map<Byte, IcmpV6Type> registry = new HashMap<Byte, IcmpV6Type>();

  static {
    registry.put(DESTINATION_UNREACHABLE.value(), DESTINATION_UNREACHABLE);
    registry.put(PACKET_TOO_BIG.value(), PACKET_TOO_BIG);
    registry.put(TIME_EXCEEDED.value(), TIME_EXCEEDED);
    registry.put(PARAMETER_PROBLEM.value(), PARAMETER_PROBLEM);
    registry.put(ECHO_REQUEST.value(), ECHO_REQUEST);
    registry.put(ECHO_REPLY.value(), ECHO_REPLY);
    registry.put(MULTICAST_LISTENER_QUERY.value(), MULTICAST_LISTENER_QUERY);
    registry.put(MULTICAST_LISTENER_REPORT.value(), MULTICAST_LISTENER_REPORT);
    registry.put(MULTICAST_LISTENER_DONE.value(), MULTICAST_LISTENER_DONE);
    registry.put(ROUTER_SOLICITATION.value(), ROUTER_SOLICITATION);
    registry.put(ROUTER_ADVERTISEMENT.value(), ROUTER_ADVERTISEMENT);
    registry.put(NEIGHBOR_SOLICITATION.value(), NEIGHBOR_SOLICITATION);
    registry.put(NEIGHBOR_ADVERTISEMENT.value(), NEIGHBOR_ADVERTISEMENT);
    registry.put(REDIRECT.value(), REDIRECT);
    registry.put(ROUTER_RENUMBERING.value(), ROUTER_RENUMBERING);
    registry.put(ICMP_NODE_INFORMATION_QUERY.value(), ICMP_NODE_INFORMATION_QUERY);
    registry.put(ICMP_NODE_INFORMATION_RESPONSE.value(), ICMP_NODE_INFORMATION_RESPONSE);
    registry.put(
        INVERSE_NEIGHBOR_DISCOVERY_SOLICITATION.value(), INVERSE_NEIGHBOR_DISCOVERY_SOLICITATION);
    registry.put(
        INVERSE_NEIGHBOR_DISCOVERY_ADVERTISEMENT.value(), INVERSE_NEIGHBOR_DISCOVERY_ADVERTISEMENT);
    registry.put(V2_MULTICAST_LISTENER_REPORT.value(), V2_MULTICAST_LISTENER_REPORT);
    registry.put(
        HOME_AGENT_ADDRESS_DISCOVERY_REQUEST.value(), HOME_AGENT_ADDRESS_DISCOVERY_REQUEST);
    registry.put(HOME_AGENT_ADDRESS_DISCOVERY_REPLY.value(), HOME_AGENT_ADDRESS_DISCOVERY_REPLY);
    registry.put(MOBILE_PREFIX_SOLICITATION.value(), MOBILE_PREFIX_SOLICITATION);
    registry.put(MOBILE_PREFIX_ADVERTISEMENT.value(), MOBILE_PREFIX_ADVERTISEMENT);
    registry.put(CERTIFICATION_PATH_SOLICITATION.value(), CERTIFICATION_PATH_SOLICITATION);
    registry.put(CERTIFICATION_PATH_ADVERTISEMENT.value(), CERTIFICATION_PATH_ADVERTISEMENT);
    registry.put(MULTICAST_ROUTER_ADVERTISEMENT.value(), MULTICAST_ROUTER_ADVERTISEMENT);
    registry.put(MULTICAST_ROUTER_SOLICITATION.value(), MULTICAST_ROUTER_SOLICITATION);
    registry.put(MULTICAST_ROUTER_TERMINATION.value(), MULTICAST_ROUTER_TERMINATION);
    registry.put(FMIP_V6.value(), FMIP_V6);
    registry.put(RPL_CONTROL.value(), RPL_CONTROL);
    registry.put(ILNP_V6_LOCATOR_UPDATE.value(), ILNP_V6_LOCATOR_UPDATE);
    registry.put(DUPLICATE_ADDRESS_REQUEST.value(), DUPLICATE_ADDRESS_REQUEST);
    registry.put(DUPLICATE_ADDRESS_CONFIRMATION.value(), DUPLICATE_ADDRESS_CONFIRMATION);
  }

  /**
   * @param value value
   * @param name name
   */
  public IcmpV6Type(Byte value, String name) {
    super(value, name);
  }

  /**
   * @param value value
   * @return a IcmpV6Type object.
   */
  public static IcmpV6Type getInstance(Byte value) {
    if (registry.containsKey(value)) {
      return registry.get(value);
    } else {
      return new IcmpV6Type(value, "unknown");
    }
  }

  /**
   * @param type type
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
  public int compareTo(IcmpV6Type o) {
    return value().compareTo(o.value());
  }
}
