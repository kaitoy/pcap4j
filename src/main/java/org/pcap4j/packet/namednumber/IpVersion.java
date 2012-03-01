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
public final class IpVersion extends NamedNumber<Byte> {

  /**
   *
   */
  private static final long serialVersionUID = 3155818580398801532L;

  //http://www.iana.org/assignments/version-numbers/version-numbers.xml

  /**
   *
   */
  public static final IpVersion IPv4
    = new IpVersion((byte)4, "IPv4");

  /**
   *
   */
  public static final IpVersion ST
    = new IpVersion((byte)4, "ST Datagram Mode");

  /**
   *
   */
  public static final IpVersion IPv6
    = new IpVersion((byte)6, "IPv6");

  /**
   *
   */
  public static final IpVersion TPIX
    = new IpVersion((byte)4, "TP/IX: The Next Internet");

  /**
   *
   */
  public static final IpVersion PIP
    = new IpVersion((byte)4, "The P Internet Protocol");

  /**
   *
   */
  public static final IpVersion TUBA
    = new IpVersion((byte)4, "TUBA");

  private static final Map<Byte, IpVersion> registry
    = new HashMap<Byte, IpVersion>();

  static {
    for (Field field: IpVersion.class.getFields()) {
      if (field.getType().isAssignableFrom(IpVersion.class)) {
        try {
          IpVersion typeCode = (IpVersion)field.get(null);
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

  private IpVersion(Byte value, String name) {
    super(value, name);
  }

  /**
   *
   * @param value
   * @return
   */
  public static IpVersion getInstance(Byte value) {
    if ((value & 0xF0) != 0) {
      throw new IllegalArgumentException(
              value + " is invalid value. "
                +"Version field of IP header must be between 0 and 15"
            );
    }

    if (registry.containsKey(value)) {
      return registry.get(value);
    }
    else {
      return new IpVersion(value, "unknown");
    }
  }

  @Override
  public int compareTo(Byte o) {
    return value().compareTo(o);
  }

}