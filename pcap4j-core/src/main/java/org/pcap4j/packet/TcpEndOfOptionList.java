/*_##########################################################################
  _##
  _##  Copyright (C) 2012-2014  Pcap4J.org
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
 * @since pcap4j 0.9.12
 */
public final class TcpEndOfOptionList implements TcpOption {

  /*
   *  +--------+
   *  |00000000|
   *  +--------+
   *    Kind=0
   */

  /** */
  private static final long serialVersionUID = -4181756738827638374L;

  private static final TcpEndOfOptionList INSTANCE = new TcpEndOfOptionList();

  private static final TcpOptionKind kind = TcpOptionKind.END_OF_OPTION_LIST;

  private TcpEndOfOptionList() {}

  /** @return the singleton instance of TcpEndOfOptionList. */
  public static TcpEndOfOptionList getInstance() {
    return INSTANCE;
  }

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return the singleton instance of TcpEndOfOptionList.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static TcpEndOfOptionList newInstance(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    if (rawData[offset] != kind.value()) {
      StringBuilder sb = new StringBuilder(100);
      sb.append("The kind must be: ")
          .append(kind.valueAsString())
          .append(" rawData: ")
          .append(ByteArrays.toHexString(rawData, " "))
          .append(", offset: ")
          .append(offset)
          .append(", length: ")
          .append(length);
      throw new IllegalRawDataException(sb.toString());
    }
    return INSTANCE;
  }

  @Override
  public TcpOptionKind getKind() {
    return kind;
  }

  @Override
  public int length() {
    return 1;
  }

  @Override
  public byte[] getRawData() {
    return new byte[1];
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("[Kind: ").append(kind);
    sb.append("]");
    return sb.toString();
  }

  // Override deserializer to keep singleton
  @SuppressWarnings("static-method")
  private Object readResolve() throws ObjectStreamException {
    return INSTANCE;
  }
}
