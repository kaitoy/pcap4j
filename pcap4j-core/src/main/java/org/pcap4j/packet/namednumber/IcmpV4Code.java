/*_##########################################################################
  _##
  _##  Copyright (C) 2012-2014  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet.namednumber;

import java.util.HashMap;
import java.util.Map;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.11
 */
public final class IcmpV4Code extends NamedNumber<Byte, IcmpV4Code> {

  /**
   *
   */
  private static final long serialVersionUID = 7592798859079852877L;

  // http://www.iana.org/assignments/icmp-parameters/icmp-parameters.xml

  /**
   *
   */
  public static final IcmpV4Code NO_CODE
    = new IcmpV4Code((byte)0x00, "No Code");

  //**** Type 3 — Destination Unreachable ****//

  /**
   *
   */
  public static final IcmpV4Code NETWORK_UNREACHABLE
    = new IcmpV4Code((byte)0x00, "Network Unreachable");

  /**
   *
   */
  public static final IcmpV4Code HOST_UNREACHABLE
    = new IcmpV4Code((byte)0x01, "Host Unreachable");

  /**
   *
   */
  public static final IcmpV4Code PROTOCOL_UNREACHABLE
    = new IcmpV4Code((byte)0x02, "Protocol Unreachable");

  /**
   *
   */
  public static final IcmpV4Code PORT_UNREACHABLE
    = new IcmpV4Code((byte)0x03, "Port Unreachable");

  /**
   *
   */
  public static final IcmpV4Code FRAGMENTATION_BLOCKED
    = new IcmpV4Code(
        (byte)0x04,
        "Fragmentation needed but no fragment bit set"
      );

  /**
   *
   */
  public static final IcmpV4Code SRC_ROUTE_FAILED
    = new IcmpV4Code((byte)0x05, "Source routing failed");

  /**
   *
   */
  public static final IcmpV4Code DST_NETWORK_UNKNOWN
    = new IcmpV4Code((byte)0x06, "Destination network unknown");

  /**
   *
   */
  public static final IcmpV4Code DST_HOST_UNKNOWN
    = new IcmpV4Code((byte)0x07, "Destination host unknown");

  /**
   *
   */
  public static final IcmpV4Code SRC_HOST_ISOLATED
    = new IcmpV4Code((byte)0x08, "Source host isolated");

  /**
   *
   */
  public static final IcmpV4Code DST_NETWORK_PROHIBITED
    = new IcmpV4Code(
        (byte)0x09,
        "Destination network administratively prohibited "
      );

  /**
   *
   */
  public static final IcmpV4Code DST_HOST_PROHIBITED
    = new IcmpV4Code(
        (byte)0x0a,
        "Destination host administratively prohibited"
      );

  /**
   *
   */
  public static final IcmpV4Code DST_NETWORK_UNREACHABLE_FOR_TOS
    = new IcmpV4Code((byte)0x0b, "Network unreachable for TOS");

  /**
   *
   */
  public static final IcmpV4Code DST_HOST_UNREACHABLE_FOR_TOS
    = new IcmpV4Code((byte)0x0c, "Host unreachable for TOS");

  /**
   *
   */
  public static final IcmpV4Code COMMUNICATION_PROHIBITED
    = new IcmpV4Code(
        (byte)0x0d,
        "Communication administratively prohibited by filtering"
      );

  /**
   *
   */
  public static final IcmpV4Code HOST_PRECEDENCE_VIOLATION
    = new IcmpV4Code((byte)0x0e, "Host precedence violation");

  /**
   *
   */
  public static final IcmpV4Code PRECEDENCE_CUTOFF_IN_EFFECT
    = new IcmpV4Code((byte)0x0f, "Precedence cutoff in effect");

  //**** Type 5 — Redirect ****//

  /**
   *
   */
  public static final IcmpV4Code REDIRECT_DATAGRAMS_FOR_NETWORK
    = new IcmpV4Code((byte)0x00, "Redirect datagrams for the Network");

  /**
   *
   */
  public static final IcmpV4Code REDIRECT_DATAGRAMS_FOR_HOST
    = new IcmpV4Code((byte)0x01, "Redirect datagrams for the Host");

  /**
   *
   */
  public static final IcmpV4Code REDIRECT_DATAGRAMS_FOR_TOS_AND_NETWORK
    = new IcmpV4Code(
        (byte)0x02, "Redirect datagrams for the Type of Service and Network"
      );

  /**
   *
   */
  public static final IcmpV4Code REDIRECT_DATAGRAMS_FOR_TOS_AND_HOST
    = new IcmpV4Code(
        (byte)0x03, "Redirect datagrams for the Type of Service and Host"
      );

  //**** Type 11 — Time Exceeded ****//

  /**
   *
   */
  public static final IcmpV4Code TIME_TO_LIVE_EXCEEDED
    = new IcmpV4Code((byte)0x00, "Time to Live exceeded during transit");

  /**
   *
   */
  public static final IcmpV4Code FRAGMENT_REASSEMBLY_TIME_EXCEEDED
    = new IcmpV4Code((byte)0x01, "Fragment Reassembly Time Exceeded");

  //**** Type 12 — Parameter Problem ****//

  /**
   *
   */
  public static final IcmpV4Code POINTER_INDICATES_ERROR
    = new IcmpV4Code((byte)0x00, "Pointer indicates the error");

  /**
   *
   */
  public static final IcmpV4Code MISSING_REQUIRED_OPTION
    = new IcmpV4Code((byte)0x01, "Missing a Required Option");

  /**
   *
   */
  public static final IcmpV4Code BAD_LENGTH
    = new IcmpV4Code((byte)0x02, "Bad Length");

  private static final Map<Byte, Map<Byte, IcmpV4Code>> registry
    = new HashMap<Byte, Map<Byte, IcmpV4Code>>();

  static {
    Map<Byte, IcmpV4Code> map;

    map = new HashMap<Byte, IcmpV4Code>();
    map.put(NO_CODE.value(), NO_CODE);
    registry.put(IcmpV4Type.ECHO_REPLY.value(), map);

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
    map.put(
      DST_NETWORK_UNREACHABLE_FOR_TOS.value(), DST_NETWORK_UNREACHABLE_FOR_TOS
    );
    map.put(DST_HOST_UNREACHABLE_FOR_TOS.value(), DST_HOST_UNREACHABLE_FOR_TOS);
    map.put(COMMUNICATION_PROHIBITED.value(), COMMUNICATION_PROHIBITED);
    map.put(HOST_PRECEDENCE_VIOLATION.value(), HOST_PRECEDENCE_VIOLATION);
    map.put(PRECEDENCE_CUTOFF_IN_EFFECT.value(), PRECEDENCE_CUTOFF_IN_EFFECT);
    registry.put(IcmpV4Type.DESTINATION_UNREACHABLE.value(), map);

    map = new HashMap<Byte, IcmpV4Code>();
    map.put(NO_CODE.value(), NO_CODE);
    registry.put(IcmpV4Type.SOURCE_QUENCH.value(), map);

    map = new HashMap<Byte, IcmpV4Code>();
    map.put(
      REDIRECT_DATAGRAMS_FOR_NETWORK.value(), REDIRECT_DATAGRAMS_FOR_NETWORK
    );
    map.put(
      REDIRECT_DATAGRAMS_FOR_HOST.value(), REDIRECT_DATAGRAMS_FOR_HOST
    );
    map.put(
      REDIRECT_DATAGRAMS_FOR_TOS_AND_NETWORK.value(),
      REDIRECT_DATAGRAMS_FOR_TOS_AND_NETWORK
    );
    map.put(
      REDIRECT_DATAGRAMS_FOR_TOS_AND_HOST.value(),
      REDIRECT_DATAGRAMS_FOR_TOS_AND_HOST
    );
    registry.put(IcmpV4Type.REDIRECT.value(), map);

    map = new HashMap<Byte, IcmpV4Code>();
    map.put(NO_CODE.value(), NO_CODE);
    registry.put(IcmpV4Type.ECHO.value(), map);

    map = new HashMap<Byte, IcmpV4Code>();
    map.put(NO_CODE.value(), NO_CODE);
    registry.put(IcmpV4Type.ROUTER_SOLICITATION.value(), map);

    map = new HashMap<Byte, IcmpV4Code>();
    map.put(TIME_TO_LIVE_EXCEEDED.value(), TIME_TO_LIVE_EXCEEDED);
    map.put(
      FRAGMENT_REASSEMBLY_TIME_EXCEEDED.value(),
      FRAGMENT_REASSEMBLY_TIME_EXCEEDED
    );
    registry.put(IcmpV4Type.TIME_EXCEEDED.value(), map);

    map = new HashMap<Byte, IcmpV4Code>();
    map.put(POINTER_INDICATES_ERROR.value(), POINTER_INDICATES_ERROR);
    map.put(MISSING_REQUIRED_OPTION.value(), MISSING_REQUIRED_OPTION);
    map.put(BAD_LENGTH.value(), BAD_LENGTH);
    registry.put(IcmpV4Type.PARAMETER_PROBLEM.value(), map);

    map = new HashMap<Byte, IcmpV4Code>();
    map.put(NO_CODE.value(), NO_CODE);
    registry.put(IcmpV4Type.TIMESTAMP.value(), map);

    map = new HashMap<Byte, IcmpV4Code>();
    map.put(NO_CODE.value(), NO_CODE);
    registry.put(IcmpV4Type.TIMESTAMP_REPLY.value(), map);

    map = new HashMap<Byte, IcmpV4Code>();
    map.put(NO_CODE.value(), NO_CODE);
    registry.put(IcmpV4Type.INFORMATION_REQUEST.value(), map);

    map = new HashMap<Byte, IcmpV4Code>();
    map.put(NO_CODE.value(), NO_CODE);
    registry.put(IcmpV4Type.INFORMATION_REPLY.value(), map);
  }

  /**
   *
   * @param value
   * @param name
   */
  public IcmpV4Code(Byte value, String name) {
    super(value, name);
  }

  /**
   *
   * @param type
   * @param value
   * @return a IcmpV4Code object.
   */
  public static IcmpV4Code getInstance(Byte type, Byte value) {
    if (registry.containsKey(type) && registry.get(type).containsKey(value)) {
      return registry.get(type).get(value);
    }
    else {
      return new IcmpV4Code(value, "unknown");
    }
  }

  /**
   *
   * @param type
   * @param code
   * @return a IcmpV4Code object.
   */
  public static IcmpV4Code register(IcmpV4Type type, IcmpV4Code code) {
    if (registry.containsKey(type.value())) {
      return registry.get(type.value()).put(code.value(), code);
    }
    else {
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