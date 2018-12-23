/*_##########################################################################
  _##
  _##  Copyright (C) 2016  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

/**
 * @author Kaito Yamada
 * @since pcap4j 1.6.6
 */
public enum GtpVersion {

  /** v0 */
  V0(0),

  /** v1 */
  V1(1),

  /** v2 */
  V2(2),

  /** v3 */
  V3(3),

  /** v4 */
  V4(4),

  /** v5 */
  V5(5),

  /** v6 */
  V6(6),

  /** v7 */
  V7(7);

  private final int value;

  private GtpVersion(int value) {
    this.value = value;
  }

  /**
   * @param value value
   * @return a GtpVersion object.
   */
  public static GtpVersion getInstance(int value) {
    for (GtpVersion ver : values()) {
      if (ver.value == value) {
        return ver;
      }
    }
    throw new IllegalArgumentException("Invalid value: " + value);
  }

  /** @return value */
  public int getValue() {
    return value;
  }
}
