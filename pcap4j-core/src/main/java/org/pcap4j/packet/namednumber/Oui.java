/*_##########################################################################
  _##
  _##  Copyright (C) 2011-2015  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.namednumber;

import java.util.HashMap;
import java.util.Map;
import org.pcap4j.util.ByteArrays;

/**
 * OUI
 *
 * @see <a href="http://standards.ieee.org/develop/regauth/oui/oui.txt">IEEE OUI</a>
 * @author Kaito Yamada
 * @since pcap4j 0.9.11
 */
public final class Oui extends NamedNumber<Integer, Oui> {

  /** */
  private static final long serialVersionUID = 8322878251680068566L;

  //

  /** Cisco: 0x00000C */
  public static final Oui CISCO_00000C = new Oui(0x00000C, "Cisco");

  /** Fujitsu: 0x00000E */
  public static final Oui FUJITSU_00000E = new Oui(0x00000E, "Fujitsu");

  /** Hewlett-Packard: 0x080009 */
  public static final Oui HEWLETT_PACKARD_080009 = new Oui(0x080009, "Hewlett-Packard");

  /** Fuji-Xerox: 0x080037 */
  public static final Oui FUJI_XEROX_080037 = new Oui(0x080037, "Fuji-Xerox");

  /** IBM: 0x08005A */
  public static final Oui IBM_08005A = new Oui(0x08005A, "IBM");

  /** Cisco: 0x000142 */
  public static final Oui CISCO_000142 = new Oui(0x000142, "Cisco");

  /** Cisco: 0x000143 */
  public static final Oui CISCO_000143 = new Oui(0x000143, "Cisco");

  /** AlaxalA: 0x0012E2 */
  public static final Oui ALAXALA_0012E2 = new Oui(0x0012E2, "AlaxalA");

  /** Hitachi: 0x001F67 */
  public static final Oui Hitachi_001F67 = new Oui(0x001F67, "Hitachi");

  /** Hitachi Cable: 0x004066 */
  public static final Oui HITACHI_CABLE_004066 = new Oui(0x004066, "Hitachi Cable");

  private static final Map<Integer, Oui> registry = new HashMap<Integer, Oui>();

  static {
    registry.put(CISCO_00000C.value(), CISCO_00000C);
    registry.put(FUJITSU_00000E.value(), FUJITSU_00000E);
    registry.put(HEWLETT_PACKARD_080009.value(), HEWLETT_PACKARD_080009);
    registry.put(FUJI_XEROX_080037.value(), FUJI_XEROX_080037);
    registry.put(IBM_08005A.value(), IBM_08005A);
    registry.put(CISCO_000142.value(), CISCO_000142);
    registry.put(CISCO_000143.value(), CISCO_000143);
    registry.put(ALAXALA_0012E2.value(), ALAXALA_0012E2);
    registry.put(Hitachi_001F67.value(), Hitachi_001F67);
    registry.put(HITACHI_CABLE_004066.value(), HITACHI_CABLE_004066);
  }

  /**
   * @param value value
   * @param name name
   */
  public Oui(Integer value, String name) {
    super(value, name);
    if ((value & 0xFF000000) != 0) {
      throw new IllegalArgumentException(
          value + " is invalid value. " + "value must be between 0 and 0x00FFFFFF");
    }
  }

  /**
   * @param value value
   * @return a Oui object.
   */
  public static Oui getInstance(Integer value) {
    if (registry.containsKey(value)) {
      return registry.get(value);
    } else {
      return new Oui(value, "unknown");
    }
  }

  /**
   * @param value value
   * @return a Oui object.
   */
  public static Oui getInstance(byte[] value) {
    if (value.length != 3) {
      throw new IllegalArgumentException("value length must be 3");
    }
    return getInstance(ByteArrays.getInt(new byte[] {(byte) 0, value[0], value[1], value[2]}, 0));
  }

  /**
   * @param version version
   * @return a Oui object.
   */
  public static Oui register(Oui version) {
    return registry.put(version.value(), version);
  }

  /** */
  @Override
  public String valueAsString() {
    return ByteArrays.toHexString(value(), "-").substring(3);
  }

  /** @return a byte array representation of this value. */
  public byte[] valueAsByteArray() {
    return ByteArrays.getSubArray(ByteArrays.toByteArray(value()), 1, 3);
  }

  @Override
  public int compareTo(Oui o) {
    return value().compareTo(o.value());
  }
}
