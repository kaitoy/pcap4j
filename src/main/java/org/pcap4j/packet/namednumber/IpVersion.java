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
  public static final IpVersion IPV4
    = new IpVersion((byte)4, "IPv4");

  /**
   *
   */
  public static final IpVersion ST
    = new IpVersion((byte)5, "ST Datagram Mode");

  /**
   *
   */
  public static final IpVersion IPV6
    = new IpVersion((byte)6, "IPv6");

  /**
   *
   */
  public static final IpVersion TP_IX
    = new IpVersion((byte)7, "TP/IX: The Next Internet");

  /**
   *
   */
  public static final IpVersion PIP
    = new IpVersion((byte)8, "The P Internet Protocol");

  /**
   *
   */
  public static final IpVersion TUBA
    = new IpVersion((byte)9, "TUBA");

  private static final Map<Byte, IpVersion> registry
    = new HashMap<Byte, IpVersion>();

  static {
    for (Field field: IpVersion.class.getFields()) {
      if (IpVersion.class.isAssignableFrom(field.getType())) {
        try {
          IpVersion f = (IpVersion)field.get(null);
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
  public IpVersion(Byte value, String name) {
    super(value, name);
    if ((value & 0xF0) != 0) {
      throw new IllegalArgumentException(
              value + " is invalid value. "
                +"Version field of IP header must be between 0 and 15"
            );
    }
  }

  /**
   *
   * @param value
   * @return
   */
  public static IpVersion getInstance(Byte value) {
    if (registry.containsKey(value)) {
      return registry.get(value);
    }
    else {
      return new IpVersion(value, "unknown");
    }
  }

  /**
   *
   * @param version
   * @return
   */
  public static IpVersion register(IpVersion version) {
    return registry.put(version.value(), version);
  }

  @Override
  public int compareTo(Byte o) {
    return value().compareTo(o);
  }

}