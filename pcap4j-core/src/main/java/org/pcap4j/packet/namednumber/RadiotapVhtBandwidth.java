/*_##########################################################################
  _##
  _##  Copyright (C) 2016  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.namednumber;

import java.util.HashMap;
import java.util.Map;

/**
 * Radiotap VHT field's Bandwidth
 *
 * @see <a href="http://www.radiotap.org/defined-fields/VHT">Radiotap VHT</a>
 * @author Kaito Yamada
 * @since pcap4j 1.6.5
 */
public final class RadiotapVhtBandwidth extends NamedNumber<Byte, RadiotapVhtBandwidth> {

  /** */
  private static final long serialVersionUID = 3400539041474374620L;

  /** 20: 0 */
  public static final RadiotapVhtBandwidth BW_20 = new RadiotapVhtBandwidth((byte) 0, "20");

  /** 40: 1 */
  public static final RadiotapVhtBandwidth BW_40 = new RadiotapVhtBandwidth((byte) 1, "40");

  /** 20L: 2 */
  public static final RadiotapVhtBandwidth BW_20L = new RadiotapVhtBandwidth((byte) 2, "20L");

  /** 20U: 3 */
  public static final RadiotapVhtBandwidth BW_20U = new RadiotapVhtBandwidth((byte) 3, "20U");

  /** 80: 4 */
  public static final RadiotapVhtBandwidth BW_80 = new RadiotapVhtBandwidth((byte) 4, "80");

  /** 40L: 5 */
  public static final RadiotapVhtBandwidth BW_40L = new RadiotapVhtBandwidth((byte) 5, "40L");

  /** 40U: 6 */
  public static final RadiotapVhtBandwidth BW_40U = new RadiotapVhtBandwidth((byte) 6, "40U");

  /** 20LL: 7 */
  public static final RadiotapVhtBandwidth BW_20LL = new RadiotapVhtBandwidth((byte) 7, "20LL");

  /** 20LU: 8 */
  public static final RadiotapVhtBandwidth BW_20LU = new RadiotapVhtBandwidth((byte) 8, "20LU");

  /** 20UL: 9 */
  public static final RadiotapVhtBandwidth BW_20UL = new RadiotapVhtBandwidth((byte) 9, "20UL");

  /** 20UU: 10 */
  public static final RadiotapVhtBandwidth BW_20UU = new RadiotapVhtBandwidth((byte) 10, "20UU");

  /** 160: 11 */
  public static final RadiotapVhtBandwidth BW_160 = new RadiotapVhtBandwidth((byte) 11, "160");

  /** 80L: 12 */
  public static final RadiotapVhtBandwidth BW_80L = new RadiotapVhtBandwidth((byte) 12, "80L");

  /** 80U: 13 */
  public static final RadiotapVhtBandwidth BW_80U = new RadiotapVhtBandwidth((byte) 13, "80U");

  /** 40LL: 14 */
  public static final RadiotapVhtBandwidth BW_40LL = new RadiotapVhtBandwidth((byte) 14, "40LL");

  /** 40LU: 15 */
  public static final RadiotapVhtBandwidth BW_40LU = new RadiotapVhtBandwidth((byte) 15, "40LU");

  /** 40UL: 16 */
  public static final RadiotapVhtBandwidth BW_40UL = new RadiotapVhtBandwidth((byte) 16, "40UL");

  /** 40UU: 17 */
  public static final RadiotapVhtBandwidth BW_40UU = new RadiotapVhtBandwidth((byte) 17, "40UU");

  /** 20LLL: 18 */
  public static final RadiotapVhtBandwidth BW_20LLL = new RadiotapVhtBandwidth((byte) 18, "20LLL");

  /** 20LLU: 19 */
  public static final RadiotapVhtBandwidth BW_20LLU = new RadiotapVhtBandwidth((byte) 19, "20LLU");

  /** 20LUL: 20 */
  public static final RadiotapVhtBandwidth BW_20LUL = new RadiotapVhtBandwidth((byte) 20, "20LUL");

  /** 20LUU: 21 */
  public static final RadiotapVhtBandwidth BW_20LUU = new RadiotapVhtBandwidth((byte) 21, "20LUU");

  /** 20ULL: 22 */
  public static final RadiotapVhtBandwidth BW_20ULL = new RadiotapVhtBandwidth((byte) 22, "20ULL");

  /** 20ULU: 23 */
  public static final RadiotapVhtBandwidth BW_20ULU = new RadiotapVhtBandwidth((byte) 23, "20ULU");

  /** 20UUL: 24 */
  public static final RadiotapVhtBandwidth BW_20UUL = new RadiotapVhtBandwidth((byte) 24, "20UUL");

  /** 20UUU: 25 */
  public static final RadiotapVhtBandwidth BW_20UUU = new RadiotapVhtBandwidth((byte) 25, "20UUU");

  private static final Map<Byte, RadiotapVhtBandwidth> registry =
      new HashMap<Byte, RadiotapVhtBandwidth>();

  static {
    registry.put(BW_20.value(), BW_20);
    registry.put(BW_40.value(), BW_40);
    registry.put(BW_20L.value(), BW_20L);
    registry.put(BW_20U.value(), BW_20U);
    registry.put(BW_80.value(), BW_80);
    registry.put(BW_40L.value(), BW_40L);
    registry.put(BW_40U.value(), BW_40U);
    registry.put(BW_20LL.value(), BW_20LL);
    registry.put(BW_20LU.value(), BW_20LU);
    registry.put(BW_20UL.value(), BW_20UL);
    registry.put(BW_20UU.value(), BW_20UU);
    registry.put(BW_160.value(), BW_160);
    registry.put(BW_80L.value(), BW_80L);
    registry.put(BW_80U.value(), BW_80U);
    registry.put(BW_40LL.value(), BW_40LL);
    registry.put(BW_40LU.value(), BW_40LU);
    registry.put(BW_40UL.value(), BW_40UL);
    registry.put(BW_40UU.value(), BW_40UU);
    registry.put(BW_20LLL.value(), BW_20LLL);
    registry.put(BW_20LLU.value(), BW_20LLU);
    registry.put(BW_20LUL.value(), BW_20LUL);
    registry.put(BW_20LUU.value(), BW_20LUU);
    registry.put(BW_20ULL.value(), BW_20ULL);
    registry.put(BW_20ULU.value(), BW_20ULU);
    registry.put(BW_20UUL.value(), BW_20UUL);
    registry.put(BW_20UUU.value(), BW_20UUU);
  }

  /**
   * @param value value
   * @param name name
   */
  public RadiotapVhtBandwidth(Byte value, String name) {
    super(value, name);
  }

  /**
   * @param value value
   * @return a RadiotapVhtBandwidth object.
   */
  public static RadiotapVhtBandwidth getInstance(Byte value) {
    if (registry.containsKey(value)) {
      return registry.get(value);
    } else {
      return new RadiotapVhtBandwidth(value, "unknown");
    }
  }

  /**
   * @param number number
   * @return a RadiotapVhtBandwidth object.
   */
  public static RadiotapVhtBandwidth register(RadiotapVhtBandwidth number) {
    return registry.put(number.value(), number);
  }

  @Override
  public int compareTo(RadiotapVhtBandwidth o) {
    return value().compareTo(o.value());
  }

  /** */
  @Override
  public String valueAsString() {
    return String.valueOf(value() & 0xFF);
  }
}
