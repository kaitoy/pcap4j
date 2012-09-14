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
public final class IpV4InternetTimestampOptionFlag extends NamedNumber<Byte> {

  // http://www.ietf.org/rfc/rfc791.txt

  /**
   *
   */
  private static final long serialVersionUID = -8701646393814443788L;

  /**
   *
   */
  public static final IpV4InternetTimestampOptionFlag TIMESTAMPS_ONLY
    = new IpV4InternetTimestampOptionFlag((byte)0, "timestamps only");

  /**
   *
   */
  public static final IpV4InternetTimestampOptionFlag EACH_TIMESTAMP_PRECEDED_WITH_ADDRESS
    = new IpV4InternetTimestampOptionFlag(
        (byte)1,
        "each timestamp is preceded with internet address"
          + " of the registering entity"
      );

  /**
   *
   */
  public static final IpV4InternetTimestampOptionFlag ADDRESS_PRESPECIFIED
    = new IpV4InternetTimestampOptionFlag(
        (byte)3, "the internet address fields are prespecified"
      );

  private static final Map<Byte, IpV4InternetTimestampOptionFlag> registry
    = new HashMap<Byte, IpV4InternetTimestampOptionFlag>();

  static {
    for (Field field: IpV4InternetTimestampOptionFlag.class.getFields()) {
      if (IpV4InternetTimestampOptionFlag.class.isAssignableFrom(field.getType())) {
        try {
          IpV4InternetTimestampOptionFlag f = (IpV4InternetTimestampOptionFlag)field.get(null);
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
  public IpV4InternetTimestampOptionFlag(Byte value, String name) {
    super(value, name);
    if ((value & 0xF0) != 0) {
      throw new IllegalArgumentException(
              value + " is invalid value. It must be between 0 and 15"
            );
    }
  }

  /**
   *
   * @param value
   * @return
   */
  public static IpV4InternetTimestampOptionFlag getInstance(Byte value) {
    if (registry.containsKey(value)) {
      return registry.get(value);
    }
    else {
      return new IpV4InternetTimestampOptionFlag(value, "unknown");
    }
  }

  /**
   *
   * @param flag
   * @return
   */
  public static IpV4InternetTimestampOptionFlag register(
    IpV4InternetTimestampOptionFlag flag
  ) {
    return registry.put(flag.value(), flag);
  }

  @Override
  public int compareTo(Byte o) { return value().compareTo(o); }

}