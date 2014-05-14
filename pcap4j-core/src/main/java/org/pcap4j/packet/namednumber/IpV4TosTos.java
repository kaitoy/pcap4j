/*_##########################################################################
  _##
  _##  Copyright (C) 2011-2014  Kaito Yamada
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
public final class IpV4TosTos extends NamedNumber<Byte, IpV4TosTos> {

  // http://www.iana.org/assignments/ip-parameters

  /**
   *
   */
  private static final long serialVersionUID = -7507790549660176346L;

  /**
   *
   */
  public static final IpV4TosTos DEFAULT
    = new IpV4TosTos((byte)0x00, "Default");

  /**
   *
   */
  public static final IpV4TosTos MINIMIZE_MONETARY_COST
    = new IpV4TosTos((byte)0x01, "Minimize Monetary Cost");

  /**
   *
   */
  public static final IpV4TosTos MAXIMIZE_RELIABILITY
    = new IpV4TosTos((byte)0x02, "Maximize Reliability");

  /**
   *
   */
  public static final IpV4TosTos MAXIMIZE_THROUGHPUT
    = new IpV4TosTos((byte)0x04, "Maximize Throughput");

  /**
   *
   */
  public static final IpV4TosTos MINIMIZE_DELAY
    = new IpV4TosTos((byte)0x08, "Minimize Delay");

  /**
   *
   */
  public static final IpV4TosTos MAXIMIZE_SECURITY
    = new IpV4TosTos((byte)0x0F, "Maximize Security");

  private static final Map<Byte, IpV4TosTos> registry
    = new HashMap<Byte, IpV4TosTos>();

  static {
    for (Field field: IpV4TosTos.class.getFields()) {
      if (IpV4TosTos.class.isAssignableFrom(field.getType())) {
        try {
          IpV4TosTos f = (IpV4TosTos)field.get(null);
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
  public IpV4TosTos(Byte value, String name) {
    super(value, name);
    if ((value & 0xF0) != 0) {
      throw new IllegalArgumentException(
              value + " is invalid value. "
                +"TOS field of IPv4 TOS must be between 0 and 15"
            );
    }
  }

  /**
   *
   * @param value
   * @return a IpV4TosTos object.
   */
  public static IpV4TosTos getInstance(Byte value) {
    if (registry.containsKey(value)) {
      return registry.get(value);
    }
    else {
      return new IpV4TosTos(value, "unknown");
    }
  }

  /**
   *
   * @param tos
   * @return a IpV4TosTos object.
   */
  public static IpV4TosTos register(IpV4TosTos tos) {
    return registry.put(tos.value(), tos);
  }

  @Override
  public int compareTo(IpV4TosTos o) {
    return value().compareTo(o.value());
  }

}