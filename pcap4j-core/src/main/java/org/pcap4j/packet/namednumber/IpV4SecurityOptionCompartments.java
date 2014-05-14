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
public final class IpV4SecurityOptionCompartments
extends NamedNumber<Short, IpV4SecurityOptionCompartments> {

  /**
   *
   */
  private static final long serialVersionUID = -420949071267484565L;

  // http://www.ietf.org/rfc/rfc791.txt

  /**
   *
   */
  public static final IpV4SecurityOptionCompartments NOT_COMPARTMENTED
    = new IpV4SecurityOptionCompartments((short)0x0000, "not compartmented");

  private static final Map<Short, IpV4SecurityOptionCompartments> registry
    = new HashMap<Short, IpV4SecurityOptionCompartments>();

  static {
    for (Field field: IpV4SecurityOptionCompartments.class.getFields()) {
      if (IpV4SecurityOptionCompartments.class.isAssignableFrom(field.getType())) {
        try {
          IpV4SecurityOptionCompartments f = (IpV4SecurityOptionCompartments)field.get(null);
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
  public IpV4SecurityOptionCompartments(Short value, String name) {
    super(value, name);
  }

  /**
   *
   * @param value
   * @return a IpV4SecurityOptionCompartments object.
   */
  public static IpV4SecurityOptionCompartments getInstance(Short value) {
    if (registry.containsKey(value)) {
      return registry.get(value);
    }
    else {
      return new IpV4SecurityOptionCompartments(value, "unknown");
    }
  }

  /**
   *
   * @param number
   * @return a IpV4SecurityOptionCompartments object.
   */
  public static IpV4SecurityOptionCompartments register(
    IpV4SecurityOptionCompartments number
  ) {
    return registry.put(number.value(), number);
  }

  @Override
  public String valueAsString() {
    return "0x" + ByteArrays.toHexString(value(), "");
  }

  @Override
  public int compareTo(IpV4SecurityOptionCompartments o) {
    return value().compareTo(o.value());
  }

}
