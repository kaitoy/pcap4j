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
 * @since pcap4j 0.9.11
 */
public final class IpV4TosPrecedence extends NamedNumber<Byte> {

  /**
   *
   */
  private static final long serialVersionUID = 3155818580398801532L;

  // http://www.ietf.org/rfc/rfc791.txt

  /**
   *
   */
  public static final IpV4TosPrecedence ROUTINE
    = new IpV4TosPrecedence((byte)0, "Routine");

  /**
   *
   */
  public static final IpV4TosPrecedence PRIORITY
    = new IpV4TosPrecedence((byte)1, "Priority");

  /**
   *
   */
  public static final IpV4TosPrecedence IMMEDIATE
    = new IpV4TosPrecedence((byte)2, "Immediate");

  /**
   *
   */
  public static final IpV4TosPrecedence FLASH
    = new IpV4TosPrecedence((byte)3, "Flash");

  /**
   *
   */
  public static final IpV4TosPrecedence FLASH_OVERRIDE
    = new IpV4TosPrecedence((byte)4, "Flash Override");

  /**
   *
   */
  public static final IpV4TosPrecedence CRITIC_ECP
    = new IpV4TosPrecedence((byte)5, "CRITIC/ECP");

  /**
   *
   */
  public static final IpV4TosPrecedence INTERNETWORK_CONTROL
    = new IpV4TosPrecedence((byte)6, "Internetwork Control/ECP");

  /**
   *
   */
  public static final IpV4TosPrecedence NETWORK_CONTROL
    = new IpV4TosPrecedence((byte)7, "Network Control");

  private static final Map<Byte, IpV4TosPrecedence> registry
    = new HashMap<Byte, IpV4TosPrecedence>();

  static {
    for (Field field: IpV4TosPrecedence.class.getFields()) {
      if (IpV4TosPrecedence.class.isAssignableFrom(field.getType())) {
        try {
          IpV4TosPrecedence f = (IpV4TosPrecedence)field.get(null);
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
  public IpV4TosPrecedence(Byte value, String name) {
    super(value, name);
    if ((value & 0xF8) != 0) {
      throw new IllegalArgumentException(
              value + " is invalid value. "
                +"Precedence field of IPv4 TOS must be between 0 and 7"
            );
    }
  }

  /**
   *
   * @param value
   * @return a IpV4TosPrecedence object.
   */
  public static IpV4TosPrecedence getInstance(Byte value) {
    if (registry.containsKey(value)) {
      return registry.get(value);
    }
    else {
      return new IpV4TosPrecedence(value, "unknown");
    }
  }

  /**
   *
   * @param precedence
   * @return a IpV4TosPrecedence object.
   */
  public static IpV4TosPrecedence register(IpV4TosPrecedence precedence) {
    return registry.put(precedence.value(), precedence);
  }

  @Override
  public int compareTo(Byte o) {
    return value().compareTo(o);
  }

}