/*_##########################################################################
  _##
  _##  Copyright (C) 2012  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet.namednumber;

import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Map;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.11
 */
public final class IcmpV4Type extends NamedNumber<Byte> {

  //http://www.iana.org/assignments/icmp-parameters/icmp-parameters.xml

  /**
   *
   */
  private static final long serialVersionUID = -6737808159892354431L;

  /**
   *
   */
  public static final IcmpV4Type ECHO_REPLY
    = new IcmpV4Type((byte)0x00, "Echo Reply");

  /**
   *
   */
  public static final IcmpV4Type DESTINATION_UNREACHABLE
    = new IcmpV4Type((byte)0x03, "Destination Unreachable");

  /**
   *
   */
  public static final IcmpV4Type SOURCE_QUENCH
    = new IcmpV4Type((byte)0x04, "Source quench");

  /**
   *
   */
  public static final IcmpV4Type REDIRECT
    = new IcmpV4Type((byte)0x05, "Redirect");

  /**
   *
   */
  public static final IcmpV4Type ALTERNATE_HOST_ADDRESS
    = new IcmpV4Type((byte)0x06, "Alternate Host Address");

  /**
   *
   */
  public static final IcmpV4Type ECHO
    = new IcmpV4Type((byte)0x08, "Echo");

  /**
   *
   */
  public static final IcmpV4Type ROUTER_ADVERTISEMENT
    = new IcmpV4Type((byte)0x09, "Router Advertisement");

  /**
   *
   */
  public static final IcmpV4Type ROUTER_SOLICITATION
    = new IcmpV4Type((byte)0x0a, "Router Solicitation");

  /**
   *
   */
  public static final IcmpV4Type TIME_EXCEEDED
    = new IcmpV4Type((byte)0x0b, "Time Exceeded");

  /**
   *
   */
  public static final IcmpV4Type PARAMETER_PROBLEM
    = new IcmpV4Type((byte)0x0c, "Parameter Problem");

  /**
   *
   */
  public static final IcmpV4Type TIMESTAMP
    = new IcmpV4Type((byte)0x0d, "Timestamp");

  /**
   *
   */
  public static final IcmpV4Type TIMESTAMP_REPLY
    = new IcmpV4Type((byte)0x0e, "Timestamp Reply");

  /**
   *
   */
  public static final IcmpV4Type INFORMATION_REQUEST
    = new IcmpV4Type((byte)0x0f, "Information Request");

  /**
   *
   */
  public static final IcmpV4Type INFORMATION_REPLY
    = new IcmpV4Type((byte)0x10, "Information Reply");

  private static final Map<Byte, IcmpV4Type> registry
    = new HashMap<Byte, IcmpV4Type>();

  static {
    for (Field field: IcmpV4Type.class.getFields()) {
      if (IcmpV4Type.class.isAssignableFrom(field.getType())) {
        try {
          IcmpV4Type f = (IcmpV4Type)field.get(null);
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
  public IcmpV4Type(Byte value, String name) {
    super(value, name);
  }

  /**
   *
   * @param value
   * @return a IcmpV4Type object.
   */
  public static IcmpV4Type getInstance(Byte value) {
    if (registry.containsKey(value)) {
      return registry.get(value);
    }
    else {
      return new IcmpV4Type(value, "unknown");
    }
  }

  /**
   *
   * @param type
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
  public int compareTo(Byte o) {
    return value().compareTo(o);
  }

}