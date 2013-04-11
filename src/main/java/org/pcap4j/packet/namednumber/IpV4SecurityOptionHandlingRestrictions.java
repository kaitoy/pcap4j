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
 * @since pcap4j 0.9.11
 */
public final class IpV4SecurityOptionHandlingRestrictions extends NamedNumber<Short> {


  // http://www.ietf.org/rfc/rfc791.txt

  /**
   *
   */
  private static final long serialVersionUID = 3041825811304706489L;

  private static final Map<Short, IpV4SecurityOptionHandlingRestrictions> registry
    = new HashMap<Short, IpV4SecurityOptionHandlingRestrictions>();

  static {
    for (
      Field field: IpV4SecurityOptionHandlingRestrictions.class.getFields()
    ) {
      if (
        IpV4SecurityOptionHandlingRestrictions.class
          .isAssignableFrom(field.getType())
      ) {
        try {
          IpV4SecurityOptionHandlingRestrictions f
            = (IpV4SecurityOptionHandlingRestrictions)field.get(null);
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
  public IpV4SecurityOptionHandlingRestrictions(Short value, String name) {
    super(value, name);
  }

  /**
   *
   * @param value
   * @return
   */
  public static IpV4SecurityOptionHandlingRestrictions getInstance(
    Short value
  ) {
    if (registry.containsKey(value)) {
      return registry.get(value);
    }
    else {
      return new IpV4SecurityOptionHandlingRestrictions(value, "unknown");
    }
  }

  /**
   *
   * @param number
   * @return
   */
  public static IpV4SecurityOptionHandlingRestrictions register(
    IpV4SecurityOptionHandlingRestrictions number
  ) {
    return registry.put(number.value(), number);
  }

  @Override
  public String valueAsString() {
    return "0x" + ByteArrays.toHexString(value(), "");
  }

  @Override
  public int compareTo(Short o) {
    return value().compareTo(o);
  }

}
