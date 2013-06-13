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
public final class Oui extends NamedNumber<Integer> {

  /**
   *
   */
  private static final long serialVersionUID = 8322878251680068566L;

  // http://standards.ieee.org/develop/regauth/oui/oui.txt

  /**
   *
   */
  public static final Oui CISCO_00000C
    = new Oui(0x00000C, "Cisco");

  /**
   *
   */
  public static final Oui FUJITSU_00000E
    = new Oui(0x00000E, "Fujitsu");

  /**
   *
   */
  public static final Oui HEWLETT_PACKARD_080009
    = new Oui(0x080009, "Hewlett-Packard");

  /**
   *
   */
  public static final Oui FUJI_XEROX_080037
    = new Oui(0x080037, "Fuji-Xerox");

  /**
   *
   */
  public static final Oui IBM_08005A
    = new Oui(0x08005A, "IBM");

  /**
   *
   */
  public static final Oui CISCO_000142
    = new Oui(0x000142, "Cisco");

  /**
   *
   */
  public static final Oui CISCO_000143
    = new Oui(0x000143, "Cisco");

  /**
   *
   */
  public static final Oui ALAXALA_0012E2
    = new Oui(0x0012E2, "AlaxalA");

  /**
   *
   */
  public static final Oui Hitachi_001F67
    = new Oui(0x001F67, "Hitachi");

  /**
   *
   */
  public static final Oui HITACHI_CABLE_004066
    = new Oui(0x004066, "Hitachi Cable");

  private static final Map<Integer, Oui> registry
    = new HashMap<Integer, Oui>();

  static {
    for (Field field: Oui.class.getFields()) {
      if (Oui.class.isAssignableFrom(field.getType())) {
        try {
          Oui f = (Oui)field.get(null);
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
  public Oui(Integer value, String name) {
    super(value, name);
    if ((value & 0xFF000000) != 0) {
      throw new IllegalArgumentException(
              value + " is invalid value. "
                +"value must be between 0 and 0x00FFFFFF"
            );
    }
  }

  /**
   *
   * @param value
   * @return a Oui object.
   */
  public static Oui getInstance(Integer value) {
    if (registry.containsKey(value)) {
      return registry.get(value);
    }
    else {
      return new Oui(value, "unknown");
    }
  }

  /**
   *
   * @param value
   * @return a Oui object.
   */
  public static Oui getInstance(byte[] value) {
    if (value.length != 3) {
      throw new IllegalArgumentException("value length must be 3");
    }
    return getInstance(
             ByteArrays.getInt(
               new byte[] { (byte)0, value[0], value[1], value[2] }, 0
             )
           );
  }

  /**
   *
   * @param version
   * @return a Oui object.
   */
  public static Oui register(Oui version) {
    return registry.put(version.value(), version);
  }

  /**
   *
   */
  @Override
  public String valueAsString() {
    return ByteArrays.toHexString(value(), "-").substring(3);
  }

  /**
   *
   * @return a byte array representation of this value.
   */
  public byte[] valueAsByteArray() {
    return ByteArrays.getSubArray(ByteArrays.toByteArray(value()), 1, 3);
  }

  @Override
  public int compareTo(Integer o) {
    return value().compareTo(o);
  }

}