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
public final class
IpV4SecurityOptionTransmissionControlCode
extends NamedNumber<Integer, IpV4SecurityOptionTransmissionControlCode> {


  // http://www.ietf.org/rfc/rfc791.txt

  /**
   *
   */
  private static final long serialVersionUID = 3041825811304706489L;

  private static final
  Map<Integer, IpV4SecurityOptionTransmissionControlCode> registry
    = new HashMap<Integer, IpV4SecurityOptionTransmissionControlCode>();

  static {
    for (
      Field field: IpV4SecurityOptionTransmissionControlCode.class.getFields()
    ) {
      if (
        IpV4SecurityOptionTransmissionControlCode.class
          .isAssignableFrom(field.getType())
      ) {
        try {
          IpV4SecurityOptionTransmissionControlCode f
            = (IpV4SecurityOptionTransmissionControlCode)field.get(null);
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
  public IpV4SecurityOptionTransmissionControlCode(Integer value, String name) {
    super(value, name);
    if ((value & 0xFF000000) != 0) {
      throw new IllegalArgumentException(
              value + " is invalid value. "
                +"The value must be between 0 and 16777215"
            );
    }
  }

  /**
   *
   * @param value
   * @return a IpV4SecurityOptionTransmissionControlCode object.
   */
  public static IpV4SecurityOptionTransmissionControlCode getInstance(
    Integer value
  ) {
    if (registry.containsKey(value)) {
      return registry.get(value);
    }
    else {
      return new IpV4SecurityOptionTransmissionControlCode(value, "unknown");
    }
  }

  /**
   *
   * @param number
   * @return a IpV4SecurityOptionTransmissionControlCode object.
   */
  public static IpV4SecurityOptionTransmissionControlCode register(
    IpV4SecurityOptionTransmissionControlCode number
  ) {
    return registry.put(number.value(), number);
  }

  @Override
  public String valueAsString() {
    return "0x" + ByteArrays.toHexString(value(), "");
  }

  @Override
  public int compareTo(IpV4SecurityOptionTransmissionControlCode o) {
    return value().compareTo(o.value());
  }

}
