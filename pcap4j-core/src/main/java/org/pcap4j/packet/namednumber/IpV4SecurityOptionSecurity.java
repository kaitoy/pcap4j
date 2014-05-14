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
import org.pcap4j.util.ByteArrays;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.11
 */
public final class IpV4SecurityOptionSecurity
extends NamedNumber<Short, IpV4SecurityOptionSecurity> {

  // http://www.ietf.org/rfc/rfc791.txt

  /**
   *
   */
  private static final long serialVersionUID = -5609708606668323329L;

  /**
   *
   */
  public static final IpV4SecurityOptionSecurity UNCLASSIFIED
    = new IpV4SecurityOptionSecurity((short)0x0000, "Unclassified");

  /**
   *
   */
  public static final IpV4SecurityOptionSecurity CONFIDENTIAL
    = new IpV4SecurityOptionSecurity((short)0xF135, "Confidential");

  /**
   *
   */
  public static final IpV4SecurityOptionSecurity EFTO
    = new IpV4SecurityOptionSecurity((short)0x789A, "EFTO");

  /**
   *
   */
  public static final IpV4SecurityOptionSecurity MMMM
    = new IpV4SecurityOptionSecurity((short)0xBC4D, "MMMM");

  /**
   *
   */
  public static final IpV4SecurityOptionSecurity PROG
    = new IpV4SecurityOptionSecurity((short)0x5E26, "PROG");

  /**
   *
   */
  public static final IpV4SecurityOptionSecurity RESTRICTED
    = new IpV4SecurityOptionSecurity((short)0xAF13, "Restricted");

  /**
   *
   */
  public static final IpV4SecurityOptionSecurity SECRET
    = new IpV4SecurityOptionSecurity((short)0xD788, "Secret");

  /**
   *
   */
  public static final IpV4SecurityOptionSecurity TOP_SECRET
    = new IpV4SecurityOptionSecurity((short)0x6BC5, "Top Secret");

  private static final Map<Short, IpV4SecurityOptionSecurity> registry
    = new HashMap<Short, IpV4SecurityOptionSecurity>();

  static {
    for (Field field: IpV4SecurityOptionSecurity.class.getFields()) {
      if (IpV4SecurityOptionSecurity.class.isAssignableFrom(field.getType())) {
        try {
          IpV4SecurityOptionSecurity f = (IpV4SecurityOptionSecurity)field.get(null);
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
  public IpV4SecurityOptionSecurity(Short value, String name) {
    super(value, name);
  }

  /**
   *
   * @param value
   * @return a IpV4SecurityOptionSecurity object.
   */
  public static IpV4SecurityOptionSecurity getInstance(Short value) {
    if (registry.containsKey(value)) {
      return registry.get(value);
    }
    else {
      return new IpV4SecurityOptionSecurity(value, "unknown");
    }
  }

  /**
   *
   * @param number
   * @return a IpV4SecurityOptionSecurity object.
   */
  public static IpV4SecurityOptionSecurity register(
    IpV4SecurityOptionSecurity number
  ) {
    return registry.put(number.value(), number);
  }

  @Override
  public String valueAsString() {
    return "0x" + ByteArrays.toHexString(value(), "");
  }

  @Override
  public int compareTo(IpV4SecurityOptionSecurity o) {
    return value().compareTo(o.value());
  }

}
