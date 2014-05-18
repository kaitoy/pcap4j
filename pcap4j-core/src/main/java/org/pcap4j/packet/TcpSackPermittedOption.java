/*_##########################################################################
  _##
  _##  Copyright (C) 2014  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import java.io.ObjectStreamException;
import org.pcap4j.packet.TcpPacket.TcpOption;
import org.pcap4j.packet.namednumber.TcpOptionKind;
import org.pcap4j.util.ByteArrays;

/**
 * @author Kaito Yamada
 * @since pcap4j 1.2.0
 */
public final class TcpSackPermittedOption implements TcpOption {

  /*
   * http://tools.ietf.org/html/rfc2018
   *
   *   +---------+---------+
   *   | Kind=4  | Length=2|
   *   +---------+---------+
   */

  /**
   *
   */
  private static final long serialVersionUID = -5364948716212977767L;

  private static final TcpSackPermittedOption INSTANCE
    = new TcpSackPermittedOption();

  private final TcpOptionKind kind = TcpOptionKind.SACK_PERMITTED;
  private final byte length = 2;

  private TcpSackPermittedOption() {}

  /**
   *
   * @return the singleton instance of TcpEndOfOptionList.
   */
  public static TcpSackPermittedOption getInstance() { return INSTANCE; }

  /**
   *
   * @param rawData
   * @return a new TcpSackPermittedOption object.
   * @throws IllegalRawDataException
   * @throws NullPointerException if the rawData argument is null.
   * @throws IllegalArgumentException if the rawData argument is empty.
   */
  public static TcpSackPermittedOption newInstance(
    byte[] rawData
  ) throws IllegalRawDataException {
    if (rawData == null) {
      throw new NullPointerException("rawData must not be null.");
    }
    if (rawData.length == 0) {
      throw new IllegalArgumentException("rawData is empty.");
    }
    return new TcpSackPermittedOption(rawData);
  }

  private TcpSackPermittedOption(byte[] rawData) throws IllegalRawDataException {
    if (rawData.length < 2) {
      StringBuilder sb = new StringBuilder(50);
      sb.append("The raw data length must be more than 1. rawData: ")
        .append(ByteArrays.toHexString(rawData, " "));
      throw new IllegalRawDataException(sb.toString());
    }
    if (rawData[0] != kind.value()) {
      StringBuilder sb = new StringBuilder(100);
      sb.append("The kind must be: ")
        .append(kind.valueAsString())
        .append(" rawData: ")
        .append(ByteArrays.toHexString(rawData, " "));
      throw new IllegalRawDataException(sb.toString());
    }
    if (rawData[1] != 2) {
      throw new IllegalRawDataException(
                  "The value of length field must be 2 but: " + rawData[1]
                );
    }
  }

  @Override
  public TcpOptionKind getKind() {
    return kind;
  }

  /**
   *
   * @return length
   */
  public byte getLength() { return length; }

  /**
   *
   * @return length
   */
  public int getLengthAsInt() { return 0xFF & length; }

  @Override
  public int length() { return 2; }

  @Override
  public byte[] getRawData() {
    byte[] rawData = new byte[length()];
    rawData[0] = kind.value();
    rawData[1] = length;
    return rawData;
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("[Kind: ")
      .append(kind);
    sb.append("] [Length: ")
      .append(getLengthAsInt())
      .append(" bytes]");
    return sb.toString();
  }

  // Override deserializer to keep singleton
  @SuppressWarnings("static-method")
  private Object readResolve() throws ObjectStreamException {
    return INSTANCE;
  }

}
