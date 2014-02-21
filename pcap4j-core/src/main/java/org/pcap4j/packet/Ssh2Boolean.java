/*_##########################################################################
  _##
  _##  Copyright (C) 2014  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import org.pcap4j.util.ByteArrays;


/**
 * @author Kaito Yamada
 * @since pcap4j 1.0.1
 */
public final class Ssh2Boolean {

  /**
   *
   */
  public static final Ssh2Boolean TRUE = new Ssh2Boolean((byte)1);

  /**
   *
   */
  public static final Ssh2Boolean FALSE = new Ssh2Boolean((byte)0);

  private final byte rawData;

  /**
   *
   * @param rawData
   */
  public Ssh2Boolean(byte rawData) {
    this.rawData = rawData;
  }

  /**
   *
   * @param rawData
   */
  public Ssh2Boolean(byte[] rawData) {
    if (rawData == null) {
      throw new NullPointerException("array may not be null");
    }
    if (rawData.length < 1) {
      throw new IllegalRawDataException("The rawData is empty.");
    }

    this.rawData = rawData[0];
  }

  /**
   *
   * @return false if the raw data is 0x00; otherwise true.
   */
  public boolean getValue() {
    return rawData == 0 ? false : true;
  }

  /**
   *
   * @return length
   */
  public int length() {
    return 1;
  }

  /**
   *
   * @return rawData
   */
  public byte[] getRawData() {
    return new byte[] { rawData };
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder(10);
    sb.append(getValue())
      .append("(0x")
      .append(ByteArrays.toHexString(rawData, ""))
      .append(")");
    return sb.toString();
  }

}
