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
 * ICMPv4 Code
 *
 * @see <a
 *     href="http://www.iana.org/assignments/icmp-parameters/icmp-parameters.xml#icmp-parameters-codes">IANA
 *     Registry</a>
 * @author Kaito Yamada
 * @since pcap4j 0.9.11
 */
public final class IcmpV4Code extends NamedNumber<Byte, IcmpV4Code> {

  /** */
  private static final long serialVersionUID = 7592798859079852877L;

  /** No Code: 0 */
  public static final IcmpV4Code NO_CODE = new IcmpV4Code((byte) 0, "No Code");

  // **** Type 3 — Destination Unreachable ****//

  /** [Type 3 — Destination Unreachable] Network Unreachable: 0 */
  public static final IcmpV4Code NETWORK_UNREACHABLE =
      new IcmpV4Code((byte) 0, "Network Unreachable");

  /** [Type 3 — Destination Unreachable] Host Unreachable: 1 */
  public static final IcmpV4Code HOST_UNREACHABLE = new IcmpV4Code((byte) 1, "Host Unreachable");

  /** [Type 3 — Destination Unreachable] Protocol Unreachable: 2 */
  public static final IcmpV4Code PROTOCOL_UNREACHABLE =
      new IcmpV4Code((byte) 2, "Protocol Unreachable");

  /** [Type 3 — Destination Unreachable] Port Unreachable: 3 */
  public static final IcmpV4Code PORT_UNREACHABLE = new IcmpV4Code((byte) 3, "Port Unreachable");

  /** [Type 3 — Destination Unreachable] Fragmentation needed but no fragment bit set: 4 */
  public static final IcmpV4Code FRAGMENTATION_BLOCKED =
      new IcmpV4Code((byte) 4, "Fragmentation needed but no fragment bit set");

  /** [Type 3 — Destination Unreachable] Source routing failed: 5 */
  public static final IcmpV4Code SRC_ROUTE_FAILED =
      new IcmpV4Code((byte) 5, "Source routing failed");

  /** [Type 3 — Destination Unreachable] Destination network unknown: 6 */
  public static final IcmpV4Code DST_NETWORK_UNKNOWN =
      new IcmpV4Code((byte) 6, "Destination network unknown");

  /** [Type 3 — Destination Unreachable] Destination host unknown: 7 */
  public static final IcmpV4Code DST_HOST_UNKNOWN =
      new IcmpV4Code((byte) 7, "Destination host unknown");

  /** [Type 3 — Destination Unreachable] Source host isolated: 8 */
  public static final IcmpV4Code SRC_HOST_ISOLATED =
      new IcmpV4Code((byte) 8, "Source host isolated");

  /** [Type 3 — Destination Unreachable] Destination network administratively prohibited: 9 */
  public static final IcmpV4Code DST_NETWORK_PROHIBITED =
      new IcmpV4Code((byte) 9, "Destination network administratively prohibited");

  /** [Type 3 — Destination Unreachable] Destination host administratively prohibited: 10 */
  public static final IcmpV4Code DST_HOST_PROHIBITED =
      new IcmpV4Code((byte) 10, "Destination host administratively prohibited");

  /** [Type 3 — Destination Unreachable] Network unreachable for TOS: 11 */
  public static final IcmpV4Code DST_NETWORK_UNREACHABLE_FOR_TOS =
      new IcmpV4Code((byte) 11, "Network unreachable for TOS");

  /** [Type 3 — Destination Unreachable] Host unreachable for TOS: 12 */
  public static final IcmpV4Code DST_HOST_UNREACHABLE_FOR_TOS =
      new IcmpV4Code((byte) 12, "Host unreachable for TOS");

  /**
   * [Type 3 — Destination Unreachable] Communication administratively prohibited by filtering: 13
   */
  public static final IcmpV4Code COMMUNICATION_PROHIBITED =
      new IcmpV4Code((byte) 13, "Communication administratively prohibited by filtering");

  /** [Type 3 — Destination Unreachable] Host precedence violation: 14 */
  public static final IcmpV4Code HOST_PRECEDENCE_VIOLATION =
      new IcmpV4Code((byte) 14, "Host precedence violation");

  /** [Type 3 — Destination Unreachable] Precedence cutoff in effect: 15 */
  public static final IcmpV4Code PRECEDENCE_CUTOFF_IN_EFFECT =
      new IcmpV4Code((byte) 15, "Precedence cutoff in effect");

  // **** Type 5 — Redirect ****//

  /** [Type 5 — Redirect] Redirect datagrams for the Network: 0 */
  public static final IcmpV4Code REDIRECT_DATAGRAMS_FOR_NETWORK =
      new IcmpV4Code((byte) 0, "Redirect datagrams for the Network");

  /** [Type 5 — Redirect] Redirect datagrams for the Host: 1 */
  public static final IcmpV4Code REDIRECT_DATAGRAMS_FOR_HOST =
      new IcmpV4Code((byte) 1, "Redirect datagrams for the Host");

  /** [Type 5 — Redirect] Redirect datagrams for the Type of Service and Network: 2 */
  public static final IcmpV4Code REDIRECT_DATAGRAMS_FOR_TOS_AND_NETWORK =
      new IcmpV4Code((byte) 2, "Redirect datagrams for the Type of Service and Network");

  /** [Type 5 — Redirect] Redirect datagrams for the Type of Service and Host: 3 */
  public static final IcmpV4Code REDIRECT_DATAGRAMS_FOR_TOS_AND_HOST =
      new IcmpV4Code((byte) 3, "Redirect datagrams for the Type of Service and Host");

  // **** Type 6 — Alternate Host Address ****//

  /** [Type 6 — Alternate Host Address] Alternate Address for Host: 0 */
  public static final IcmpV4Code ALTERNATE_ADDRESS_FOR_HOST =
      new IcmpV4Code((byte) 0, "Alternate Address for Host");

  // **** Type 9 — Router Advertisement ****//

  /** [Type 9 — Router Advertisement] Normal router advertisement: 0 */
  public static final IcmpV4Code NORMAL_ROUTER_ADVERTISEMENT =
      new IcmpV4Code((byte) 0, "Normal router advertisement");

  /** [Type 9 — Router Advertisement] Alternate Address for Host: 16 */
  public static final IcmpV4Code DOES_NOT_ROUTE_COMMON_TRAFFIC =
      new IcmpV4Code((byte) 16, "Does not route common traffic");

  // **** Type 11 — Time Exceeded ****//

  /** [Type 11 — Time Exceeded] Time to Live exceeded during transit: 0 */
  public static final IcmpV4Code TIME_TO_LIVE_EXCEEDED =
      new IcmpV4Code((byte) 0, "Time to Live exceeded during transit");

  /** [Type 11 — Time Exceeded] Fragment Reassembly Time Exceeded: 1 */
  public static final IcmpV4Code FRAGMENT_REASSEMBLY_TIME_EXCEEDED =
      new IcmpV4Code((byte) 1, "Fragment Reassembly Time Exceeded");

  // **** Type 12 — Parameter Problem ****//

  /** [Type 12 — Parameter Problem] Pointer indicates the error: 0 */
  public static final IcmpV4Code POINTER_INDICATES_ERROR =
      new IcmpV4Code((byte) 0, "Pointer indicates the error");

  /** [Type 12 — Parameter Problem] Missing a Required Option: 1 */
  public static final IcmpV4Code MISSING_REQUIRED_OPTION =
      new IcmpV4Code((byte) 1, "Missing a Required Option");

  /** [Type 12 — Parameter Problem] Bad Length: 2 */
  public static final IcmpV4Code BAD_LENGTH = new IcmpV4Code((byte) 2, "Bad Length");

  // **** Type 40 — Photuris ****//

  /** [Type 40 — Photuris] Bad SPI: 0 */
  public static final IcmpV4Code BAD_SPI = new IcmpV4Code((byte) 0, "Bad SPI");

  /** [Type 40 — Photuris] Authentication Failed: 1 */
  public static final IcmpV4Code AUTHENTICATION_FAILED =
      new IcmpV4Code((byte) 1, "Authentication Failed");

  /** [Type 40 — Photuris] Decompression Failed: 2 */
  public static final IcmpV4Code DECOMPRESSION_FAILED =
      new IcmpV4Code((byte) 2, "Decompression Failed");

  /** [Type 40 — Photuris] Decryption Failed: 3 */
  public static final IcmpV4Code DECRYPTION_FAILED = new IcmpV4Code((byte) 3, "Decryption Failed");

  /** [Type 40 — Photuris] Need Authentication: 4 */
  public static final IcmpV4Code NEED_AUTHENTICATION =
      new IcmpV4Code((byte) 4, "Need Authentication");

  /** [Type 40 — Photuris] Need Authorization: 5 */
  public static final IcmpV4Code NEED_AUTHORIZATION =
      new IcmpV4Code((byte) 5, "Need Authorization");

  private static final Map<Byte, Map<Byte, IcmpV4Code>> registry =
      new HashMap<Byte, Map<Byte, IcmpV4Code>>();

  static {
    Map<Byte, IcmpV4Code> map;

    // Type 0 — Echo Reply
    map = new HashMap<Byte, IcmpV4Code>();
    map.put(NO_CODE.value(), NO_CODE);
    registry.put(IcmpV4Type.ECHO_REPLY.value(), map);

    // Type 3 — Destination Unreachable
    map = new HashMap<Byte, IcmpV4Code>();
    map.put(NETWORK_UNREACHABLE.value(), NETWORK_UNREACHABLE);
    map.put(HOST_UNREACHABLE.value(), HOST_UNREACHABLE);
    map.put(PROTOCOL_UNREACHABLE.value(), PROTOCOL_UNREACHABLE);
    map.put(PORT_UNREACHABLE.value(), PORT_UNREACHABLE);
    map.put(FRAGMENTATION_BLOCKED.value(), FRAGMENTATION_BLOCKED);
    map.put(SRC_ROUTE_FAILED.value(), SRC_ROUTE_FAILED);
    map.put(DST_NETWORK_UNKNOWN.value(), DST_NETWORK_UNKNOWN);
    map.put(DST_HOST_UNKNOWN.value(), DST_HOST_UNKNOWN);
    map.put(SRC_HOST_ISOLATED.value(), SRC_HOST_ISOLATED);
    map.put(DST_NETWORK_PROHIBITED.value(), DST_NETWORK_PROHIBITED);
    map.put(DST_HOST_PROHIBITED.value(), DST_HOST_PROHIBITED);
    map.put(DST_NETWORK_UNREACHABLE_FOR_TOS.value(), DST_NETWORK_UNREACHABLE_FOR_TOS);
    map.put(DST_HOST_UNREACHABLE_FOR_TOS.value(), DST_HOST_UNREACHABLE_FOR_TOS);
    map.put(COMMUNICATION_PROHIBITED.value(), COMMUNICATION_PROHIBITED);
    map.put(HOST_PRECEDENCE_VIOLATION.value(), HOST_PRECEDENCE_VIOLATION);
    map.put(PRECEDENCE_CUTOFF_IN_EFFECT.value(), PRECEDENCE_CUTOFF_IN_EFFECT);
    registry.put(IcmpV4Type.DESTINATION_UNREACHABLE.value(), map);

    // Type 4 — Source Quench
    map = new HashMap<Byte, IcmpV4Code>();
    map.put(NO_CODE.value(), NO_CODE);
    registry.put(IcmpV4Type.SOURCE_QUENCH.value(), map);

    // Type 5 — Redirect
    map = new HashMap<Byte, IcmpV4Code>();
    map.put(REDIRECT_DATAGRAMS_FOR_NETWORK.value(), REDIRECT_DATAGRAMS_FOR_NETWORK);
    map.put(REDIRECT_DATAGRAMS_FOR_HOST.value(), REDIRECT_DATAGRAMS_FOR_HOST);
    map.put(REDIRECT_DATAGRAMS_FOR_TOS_AND_NETWORK.value(), REDIRECT_DATAGRAMS_FOR_TOS_AND_NETWORK);
    map.put(REDIRECT_DATAGRAMS_FOR_TOS_AND_HOST.value(), REDIRECT_DATAGRAMS_FOR_TOS_AND_HOST);
    registry.put(IcmpV4Type.REDIRECT.value(), map);

    // Type 6 — Alternate Host Address
    map = new HashMap<Byte, IcmpV4Code>();
    map.put(ALTERNATE_ADDRESS_FOR_HOST.value(), ALTERNATE_ADDRESS_FOR_HOST);
    registry.put(IcmpV4Type.ALTERNATE_HOST_ADDRESS.value(), map);

    // Type 8 — Echo
    map = new HashMap<Byte, IcmpV4Code>();
    map.put(NO_CODE.value(), NO_CODE);
    registry.put(IcmpV4Type.ECHO.value(), map);

    // Type 9 — Router Advertisement
    map = new HashMap<Byte, IcmpV4Code>();
    map.put(NORMAL_ROUTER_ADVERTISEMENT.value(), NORMAL_ROUTER_ADVERTISEMENT);
    map.put(DOES_NOT_ROUTE_COMMON_TRAFFIC.value(), DOES_NOT_ROUTE_COMMON_TRAFFIC);
    registry.put(IcmpV4Type.ROUTER_ADVERTISEMENT.value(), map);

    // Type 10 — Router Selection
    map = new HashMap<Byte, IcmpV4Code>();
    map.put(NO_CODE.value(), NO_CODE);
    registry.put(IcmpV4Type.ROUTER_SOLICITATION.value(), map);

    // Type 11 — Time Exceeded
    map = new HashMap<Byte, IcmpV4Code>();
    map.put(TIME_TO_LIVE_EXCEEDED.value(), TIME_TO_LIVE_EXCEEDED);
    map.put(FRAGMENT_REASSEMBLY_TIME_EXCEEDED.value(), FRAGMENT_REASSEMBLY_TIME_EXCEEDED);
    registry.put(IcmpV4Type.TIME_EXCEEDED.value(), map);

    // Type 12 — Parameter Problem
    map = new HashMap<Byte, IcmpV4Code>();
    map.put(POINTER_INDICATES_ERROR.value(), POINTER_INDICATES_ERROR);
    map.put(MISSING_REQUIRED_OPTION.value(), MISSING_REQUIRED_OPTION);
    map.put(BAD_LENGTH.value(), BAD_LENGTH);
    registry.put(IcmpV4Type.PARAMETER_PROBLEM.value(), map);

    // Type 13 — Timestamp
    map = new HashMap<Byte, IcmpV4Code>();
    map.put(NO_CODE.value(), NO_CODE);
    registry.put(IcmpV4Type.TIMESTAMP.value(), map);

    // Type 14 — Timestamp Reply
    map = new HashMap<Byte, IcmpV4Code>();
    map.put(NO_CODE.value(), NO_CODE);
    registry.put(IcmpV4Type.TIMESTAMP_REPLY.value(), map);

    // Type 15 — Information Request
    map = new HashMap<Byte, IcmpV4Code>();
    map.put(NO_CODE.value(), NO_CODE);
    registry.put(IcmpV4Type.INFORMATION_REQUEST.value(), map);

    // Type 16 — Information Reply
    map = new HashMap<Byte, IcmpV4Code>();
    map.put(NO_CODE.value(), NO_CODE);
    registry.put(IcmpV4Type.INFORMATION_REPLY.value(), map);

    // Type 17 — Address Mask Request
    map = new HashMap<Byte, IcmpV4Code>();
    map.put(NO_CODE.value(), NO_CODE);
    registry.put(IcmpV4Type.ADDRESS_MASK_REQUEST.value(), map);

    // Type 18 — Address Mask Reply
    map = new HashMap<Byte, IcmpV4Code>();
    map.put(NO_CODE.value(), NO_CODE);
    registry.put(IcmpV4Type.ADDRESS_MASK_REPLY.value(), map);

    // Type 40 — Photuris
    map = new HashMap<Byte, IcmpV4Code>();
    map.put(BAD_SPI.value(), BAD_SPI);
    map.put(AUTHENTICATION_FAILED.value(), AUTHENTICATION_FAILED);
    map.put(DECOMPRESSION_FAILED.value(), DECOMPRESSION_FAILED);
    map.put(DECRYPTION_FAILED.value(), DECRYPTION_FAILED);
    map.put(NEED_AUTHENTICATION.value(), NEED_AUTHENTICATION);
    map.put(NEED_AUTHORIZATION.value(), NEED_AUTHORIZATION);
    registry.put(IcmpV4Type.PHOTURIS.value(), map);
  }

  /**
   * @param value value
   * @param name name
   */
  public IcmpV4Code(Byte value, String name) {
    super(value, name);
  }

  /**
   * @param type ICMPv4 type
   * @param value value
   * @return a IcmpV4Code object.
   */
  public static IcmpV4Code getInstance(Byte type, Byte value) {
    if (registry.containsKey(type) && registry.get(type).containsKey(value)) {
      return registry.get(type).get(value);
    } else {
      return new IcmpV4Code(value, "unknown");
    }
  }

  /**
   * @param type type
   * @param code code
   * @return a IcmpV4Code object.
   */
  public static IcmpV4Code register(IcmpV4Type type, IcmpV4Code code) {
    if (registry.containsKey(type.value())) {
      return registry.get(type.value()).put(code.value(), code);
    } else {
      Map<Byte, IcmpV4Code> map = new HashMap<Byte, IcmpV4Code>();
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
  public int compareTo(IcmpV4Code o) {
    return value().compareTo(o.value());
  }
}
