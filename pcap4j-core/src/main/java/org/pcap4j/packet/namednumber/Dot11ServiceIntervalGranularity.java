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
 * IEEE802.11 Service Interval Granularity
 *
 * @see <a href="http://standards.ieee.org/getieee802/download/802.11-2012.pdf">IEEE802.11</a>
 * @author Kaito Yamada
 * @since pcap4j 1.7.0
 */
public final class Dot11ServiceIntervalGranularity
    extends NamedNumber<Byte, Dot11ServiceIntervalGranularity> {

  /** */
  private static final long serialVersionUID = -935382239962360264L;

  /** 5 ms: 0 */
  public static final Dot11ServiceIntervalGranularity SIG_5_MS =
      new Dot11ServiceIntervalGranularity((byte) 0, "5 ms");

  /** 10 ms: 1 */
  public static final Dot11ServiceIntervalGranularity SIG_10_MS =
      new Dot11ServiceIntervalGranularity((byte) 1, "10 ms");

  /** 15 ms: 2 */
  public static final Dot11ServiceIntervalGranularity SIG_15_MS =
      new Dot11ServiceIntervalGranularity((byte) 2, "15 ms");

  /** 20 ms: 3 */
  public static final Dot11ServiceIntervalGranularity SIG_20_MS =
      new Dot11ServiceIntervalGranularity((byte) 3, "20 ms");

  /** 25 ms: 4 */
  public static final Dot11ServiceIntervalGranularity SIG_25_MS =
      new Dot11ServiceIntervalGranularity((byte) 4, "25 ms");

  /** 30 ms: 5 */
  public static final Dot11ServiceIntervalGranularity SIG_30_MS =
      new Dot11ServiceIntervalGranularity((byte) 5, "30 ms");

  /** 35 ms: 6 */
  public static final Dot11ServiceIntervalGranularity SIG_35_MS =
      new Dot11ServiceIntervalGranularity((byte) 6, "35 ms");

  /** 40 ms: 7 */
  public static final Dot11ServiceIntervalGranularity SIG_40_MS =
      new Dot11ServiceIntervalGranularity((byte) 7, "40 ms");

  private static final Map<Byte, Dot11ServiceIntervalGranularity> registry =
      new HashMap<Byte, Dot11ServiceIntervalGranularity>();

  static {
    registry.put(SIG_5_MS.value(), SIG_5_MS);
    registry.put(SIG_10_MS.value(), SIG_10_MS);
    registry.put(SIG_15_MS.value(), SIG_15_MS);
    registry.put(SIG_20_MS.value(), SIG_20_MS);
    registry.put(SIG_25_MS.value(), SIG_25_MS);
    registry.put(SIG_30_MS.value(), SIG_30_MS);
    registry.put(SIG_35_MS.value(), SIG_35_MS);
    registry.put(SIG_40_MS.value(), SIG_40_MS);
  }

  /**
   * @param value value
   * @param name name
   */
  public Dot11ServiceIntervalGranularity(Byte value, String name) {
    super(value, name);
    if ((value & 0xF8) != 0) {
      throw new IllegalArgumentException(
          "The value must be between 0 and 7 but is actually: " + value);
    }
  }

  /**
   * @param value value
   * @return a Dot11ServiceIntervalGranularity object.
   */
  public static Dot11ServiceIntervalGranularity getInstance(Byte value) {
    if (registry.containsKey(value)) {
      return registry.get(value);
    } else {
      return new Dot11ServiceIntervalGranularity(value, "unknown");
    }
  }

  /**
   * @param number number
   * @return a Dot11ServiceIntervalGranularity object.
   */
  public static Dot11ServiceIntervalGranularity register(Dot11ServiceIntervalGranularity number) {
    return registry.put(number.value(), number);
  }

  @Override
  public int compareTo(Dot11ServiceIntervalGranularity o) {
    return value().compareTo(o.value());
  }

  /** */
  @Override
  public String valueAsString() {
    return String.valueOf(value() & 0xFF);
  }
}
