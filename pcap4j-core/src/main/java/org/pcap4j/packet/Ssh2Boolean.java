/*_##########################################################################
  _##
  _##  Copyright (C) 2014  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import java.io.Serializable;
import org.pcap4j.util.ByteArrays;


/**
 * @author Kaito Yamada
 * @since pcap4j 1.0.1
 */
public final class Ssh2Boolean implements Serializable {

  /*
   * http://www.ietf.org/rfc/rfc4251.txt
   *
   * A boolean value is stored as a single byte.  The value 0
   * represents FALSE, and the value 1 represents TRUE.  All non-zero
   * values MUST be interpreted as TRUE; however, applications MUST NOT
   * store values other than 0 and 1.
   */

  /**
   *
   */
  private static final long serialVersionUID = 951415749644317915L;

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
   * @throws NullPointerException if the rawData argument is null.
   * @throws IllegalArgumentException if the rawData argument is empty.
   */
  public Ssh2Boolean(byte[] rawData) {
    if (rawData == null) {
      throw new NullPointerException("rawData must not be null.");
    }
    if (rawData.length == 0) {
      throw new IllegalArgumentException("rawData is empty.");
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

  @Override
  public boolean equals(Object obj) {
    if (obj == this) { return true; }
    if (!this.getClass().isInstance(obj)) { return false; }
    return (getClass().cast(obj)).rawData ==  rawData;
  }

  @Override
  public int hashCode() {
    return rawData;
  }

}
