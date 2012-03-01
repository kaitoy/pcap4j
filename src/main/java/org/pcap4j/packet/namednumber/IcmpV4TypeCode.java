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
import org.pcap4j.util.ByteArrays;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.1
 */
public final class IcmpV4TypeCode extends NamedNumber<Short> {

  /**
   *
   */
  private static final long serialVersionUID = 5392428616149161453L;

  //http://www.iana.org/assignments/icmp-parameters/icmp-parameters.xml

  /**
   *
   */
  public static final IcmpV4TypeCode ECHO_REPLY
    = new IcmpV4TypeCode((short)0x0000, "EchoReply");

  /**
   *
   */
  public static final IcmpV4TypeCode NETWORK_UNREACHABLE
    = new IcmpV4TypeCode((short)0x0300, "Network Unreachable");

  /**
   *
   */
  public static final IcmpV4TypeCode HOST_UNREACHABLE
    = new IcmpV4TypeCode((short)0x0301, "Host Unreachable");

  /**
   *
   */
  public static final IcmpV4TypeCode PROTOCOL_UNREACHABLE
    = new IcmpV4TypeCode((short)0x0302, "Protocol Unreachable");

  /**
   *
   */
  public static final IcmpV4TypeCode PORT_UNREACHABLE
    = new IcmpV4TypeCode((short)0x0303, "Port Unreachable");

  /**
   *
   */
  public static final IcmpV4TypeCode FRAGMENTATION_BLOCKED
    = new IcmpV4TypeCode(
        (short)0x0304,
        "Fragmentation needed but no fragment bit set"
      );

  /**
   *
   */
  public static final IcmpV4TypeCode SRC_ROUTE_FAILED
    = new IcmpV4TypeCode((short)0x0305, "Source routing failed");

  /**
   *
   */
  public static final IcmpV4TypeCode DST_NETWORK_UNKNOWN
    = new IcmpV4TypeCode((short)0x0306, "Destination network unknown");

  /**
   *
   */
  public static final IcmpV4TypeCode DST_HOST_UNKNOWN
    = new IcmpV4TypeCode((short)0x0307, "Destination host unknown");

  /**
   *
   */
  public static final IcmpV4TypeCode SRC_HOST_ISOLATED
    = new IcmpV4TypeCode((short)0x0308, "Source host isolated");

  /**
   *
   */
  public static final IcmpV4TypeCode DST_NETWORK_PROHIBITED
    = new IcmpV4TypeCode(
        (short)0x0309,
        "Destination network administratively prohibited "
      );

  /**
   *
   */
  public static final IcmpV4TypeCode DST_HOST_PROHIBITED
    = new IcmpV4TypeCode(
        (short)0x030a,
        "Destination host administratively prohibited"
      );

  /**
   *
   */
  public static final IcmpV4TypeCode DST_NETWORK_UNREACHABLE_FOR_TOS
    = new IcmpV4TypeCode((short)0x030b, "Network unreachable for TOS");

  /**
   *
   */
  public static final IcmpV4TypeCode DST_HOST_UNREACHABLE_FOR_TOS
    = new IcmpV4TypeCode((short)0x030c, "Host unreachable for TOS");

  /**
   *
   */
  public static final IcmpV4TypeCode COMMUNICATION_PROHIBITED
    = new IcmpV4TypeCode(
        (short)0x030d,
        "Communication administratively prohibited by filtering"
      );

  /**
   *
   */
  public static final IcmpV4TypeCode SOURCE_QUENCH
    = new IcmpV4TypeCode((short)0x0400, "Source quench");

  /**
   *
   */
  public static final IcmpV4TypeCode HOST_PRECEDENCE_VIOLATION
    = new IcmpV4TypeCode((short)0x030e, "Host precedence violation");

  /**
   *
   */
  public static final IcmpV4TypeCode PRECEDENCE_CUTOFF_IN_EFFECT
    = new IcmpV4TypeCode((short)0x030f, "Precedence cutoff in effect");

  /**
   *
   */
  public static final IcmpV4TypeCode ECHO
    = new IcmpV4TypeCode((short)0x0800, "Echo");

  /**
   *
   */
  public static final IcmpV4TypeCode TIME_TO_LIVE_EXCEEDED
    = new IcmpV4TypeCode((short)0x0b00, "Time to Live exceeded during transit");

  private static final Map<Short, IcmpV4TypeCode> registry
    = new HashMap<Short, IcmpV4TypeCode>();

  static {
    for (Field field: IcmpV4TypeCode.class.getFields()) {
      if (field.getType().isAssignableFrom(IcmpV4TypeCode.class)) {
        try {
          IcmpV4TypeCode typeCode = (IcmpV4TypeCode)field.get(null);
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
  }

  private IcmpV4TypeCode(Short value, String name) {
    super(value, name);
  }

  /**
   *
   * @param value
   * @return
   */
  public static IcmpV4TypeCode getInstance(Short value) {
    if (registry.containsKey(value)) {
      return registry.get(value);
    }
    else {
      return new IcmpV4TypeCode(value, "unknown");
    }
  }

  public static IcmpV4TypeCode getInstance(int type, int code) {
    return getInstance(Short.valueOf((short)(type << 16 | code)));
  }

  public int getType() {
    return value() >>> 8;
  }

  public int getCode() {
    return value() & 0xFF;
  }

  /**
   *
   * @return
   */
  @Override
  public String valueAsString() {
    byte[] bytes = ByteArrays.toByteArray(value());
    return bytes[0] + "," + bytes[1];
  }

  @Override
  public int compareTo(Short o) {
    return value().compareTo(o);
  }

}