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
 * Radiotap present bit number.
 *
 * @see <a href="http://www.radiotap.org/defined-fields">Radiotap</a>
 * @author Kaito Yamada
 * @since pcap4j 1.6.5
 */
public final class RadiotapPresentBitNumber extends NamedNumber<Integer, RadiotapPresentBitNumber> {

  /** */
  private static final long serialVersionUID = -1778769702168080669L;

  /** Radiotap Namespace: 29 (29 + 32*n) */
  public static final int RADIOTAP_NAMESPACE = 29;

  /** Vendor Namespace: 30 (30 + 32*n) */
  public static final int VENDOR_NAMESPACE = 30;

  /** another bitmap follows: 31 (31 + 32*n) */
  public static final int ANOTHER_BITMAP_FOLLOWS = 31;

  /** TSFT: 0 */
  public static final RadiotapPresentBitNumber TSFT = new RadiotapPresentBitNumber(0, "TSFT", 8);

  /** Flags: 1 */
  public static final RadiotapPresentBitNumber FLAGS = new RadiotapPresentBitNumber(1, "Flags", 1);

  /** Rate: 2 */
  public static final RadiotapPresentBitNumber RATE = new RadiotapPresentBitNumber(2, "Rate", 1);

  /** Channel: 3 */
  public static final RadiotapPresentBitNumber CHANNEL =
      new RadiotapPresentBitNumber(3, "Channel", 2);

  /** FHSS: 4 */
  public static final RadiotapPresentBitNumber FHSS = new RadiotapPresentBitNumber(4, "FHSS", 1);

  /** Antenna signal: 5 */
  public static final RadiotapPresentBitNumber ANTENNA_SIGNAL =
      new RadiotapPresentBitNumber(5, "Antenna signal", 1);

  /** Antenna noise: 6 */
  public static final RadiotapPresentBitNumber ANTENNA_NOISE =
      new RadiotapPresentBitNumber(6, "Antenna noise", 1);

  /** Lock quality: 7 */
  public static final RadiotapPresentBitNumber LOCK_QUALITY =
      new RadiotapPresentBitNumber(7, "Lock quality", 2);

  /** TX attenuation: 8 */
  public static final RadiotapPresentBitNumber TX_ATTENUATION =
      new RadiotapPresentBitNumber(8, "TX attenuation", 2);

  /** dB TX attenuation: 9 */
  public static final RadiotapPresentBitNumber DB_TX_ATTENUATION =
      new RadiotapPresentBitNumber(9, "dB TX attenuation", 2);

  /** dBm TX power: 10 */
  public static final RadiotapPresentBitNumber DBM_TX_POWER =
      new RadiotapPresentBitNumber(10, "dBm TX power", 1);

  /** Antenna: 11 */
  public static final RadiotapPresentBitNumber ANTENNA =
      new RadiotapPresentBitNumber(11, "Antenna", 1);

  /** dB antenna signal: 12 */
  public static final RadiotapPresentBitNumber DB_ANTENNA_SIGNAL =
      new RadiotapPresentBitNumber(12, "dB antenna signal", 1);

  /** dB antenna noise: 13 */
  public static final RadiotapPresentBitNumber DB_ANTENNA_NOISE =
      new RadiotapPresentBitNumber(13, "dB antenna noise", 1);

  /** RX flags: 14 */
  public static final RadiotapPresentBitNumber RX_FLAGS =
      new RadiotapPresentBitNumber(14, "RX flags", 2);

  /** MCS: 19 */
  public static final RadiotapPresentBitNumber MCS = new RadiotapPresentBitNumber(19, "MCS", 1);

  /** A-MPDU status: 20 */
  public static final RadiotapPresentBitNumber A_MPDU_STATUS =
      new RadiotapPresentBitNumber(20, "A-MPDU status", 4);

  /** Antenna: 21 */
  public static final RadiotapPresentBitNumber VHT = new RadiotapPresentBitNumber(21, "VHT", 2);

  private static final Map<String, Map<Integer, RadiotapPresentBitNumber>> registry =
      new HashMap<String, Map<Integer, RadiotapPresentBitNumber>>();

  static {
    Map<Integer, RadiotapPresentBitNumber> defaultRegistry =
        new HashMap<Integer, RadiotapPresentBitNumber>();
    defaultRegistry.put(TSFT.value(), TSFT);
    defaultRegistry.put(FLAGS.value(), FLAGS);
    defaultRegistry.put(RATE.value(), RATE);
    defaultRegistry.put(CHANNEL.value(), CHANNEL);
    defaultRegistry.put(FHSS.value(), FHSS);
    defaultRegistry.put(ANTENNA_SIGNAL.value(), ANTENNA_SIGNAL);
    defaultRegistry.put(ANTENNA_NOISE.value(), ANTENNA_NOISE);
    defaultRegistry.put(LOCK_QUALITY.value(), LOCK_QUALITY);
    defaultRegistry.put(TX_ATTENUATION.value(), TX_ATTENUATION);
    defaultRegistry.put(DB_TX_ATTENUATION.value(), DB_TX_ATTENUATION);
    defaultRegistry.put(DBM_TX_POWER.value(), DBM_TX_POWER);
    defaultRegistry.put(ANTENNA.value(), ANTENNA);
    defaultRegistry.put(DB_ANTENNA_SIGNAL.value(), DB_ANTENNA_SIGNAL);
    defaultRegistry.put(DB_ANTENNA_NOISE.value(), DB_ANTENNA_NOISE);
    defaultRegistry.put(RX_FLAGS.value(), RX_FLAGS);
    defaultRegistry.put(MCS.value(), MCS);
    defaultRegistry.put(A_MPDU_STATUS.value(), A_MPDU_STATUS);
    defaultRegistry.put(VHT.value(), VHT);
    registry.put("", defaultRegistry);
  }

  private final String namespace;
  private final int requiredAlignment;

  /**
   * @param value value
   * @param name name
   * @param requiredAlignment requiredAlignment
   */
  public RadiotapPresentBitNumber(Integer value, String name, int requiredAlignment) {
    this(value, name, "", requiredAlignment);
  }

  /**
   * @param value value
   * @param name name
   * @param namespace namespace
   * @param requiredAlignment requiredAlignment
   */
  public RadiotapPresentBitNumber(
      Integer value, String name, String namespace, int requiredAlignment) {
    super(value, name);
    if (value % 32 == RADIOTAP_NAMESPACE) {
      throw new IllegalArgumentException("Reserved for Radiotap Namespace: " + value);
    }
    if (value % 32 == VENDOR_NAMESPACE) {
      throw new IllegalArgumentException("Reserved for Vendor Namespace: " + value);
    }
    if (value % 32 == ANOTHER_BITMAP_FOLLOWS) {
      throw new IllegalArgumentException("Reserved for another bitmap follows: " + value);
    }
    this.namespace = namespace;
    this.requiredAlignment = requiredAlignment;
  }

  /** @return namespace */
  public String getNamespace() {
    return namespace;
  }

  /** @return requiredAlignment */
  public int getRequiredAlignment() {
    return requiredAlignment;
  }

  /**
   * @param value value
   * @return a RadiotapDataField object.
   */
  public static RadiotapPresentBitNumber getInstance(Integer value) {
    return getInstance(value, "");
  }

  /**
   * @param value value
   * @param namespace namespace
   * @return a RadiotapDataField object.
   */
  public static RadiotapPresentBitNumber getInstance(Integer value, String namespace) {
    Map<Integer, RadiotapPresentBitNumber> namedRegistry = registry.get(namespace);
    if (namedRegistry != null) {
      RadiotapPresentBitNumber num = namedRegistry.get(value);
      if (num != null) {
        return num;
      }
    }
    return new RadiotapPresentBitNumber(value, "unknown", namespace, 1);
  }

  /**
   * @param num num
   * @return a RadiotapDataField object.
   */
  public static RadiotapPresentBitNumber register(RadiotapPresentBitNumber num) {
    String namespace = num.getNamespace();
    Map<Integer, RadiotapPresentBitNumber> namedRegistry = registry.get(namespace);
    if (namedRegistry == null) {
      namedRegistry = new HashMap<Integer, RadiotapPresentBitNumber>();
      registry.put(namespace, namedRegistry);
    }
    return namedRegistry.put(num.value(), num);
  }

  /** */
  @Override
  public String valueAsString() {
    if (namespace.isEmpty()) {
      return String.valueOf(value() & 0xFFFFFFFFL);
    } else {
      StringBuilder sb =
          new StringBuilder(30).append(namespace).append("/").append(value() & 0xFFFFFFFFL);

      return sb.toString();
    }
  }

  @Override
  public boolean equals(Object obj) {
    if (obj == this) {
      return true;
    }
    if (!this.getClass().isInstance(obj)) {
      return false;
    }

    RadiotapPresentBitNumber other = (RadiotapPresentBitNumber) obj;
    return value().equals(other.value()) && namespace.equals(other.namespace);
  }

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + value().hashCode();
    result = prime * result + namespace.hashCode();
    return result;
  }

  @Override
  public int compareTo(RadiotapPresentBitNumber o) {
    return value().compareTo(o.value());
  }
}
