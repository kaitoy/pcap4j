/*_##########################################################################
  _##
  _##  Copyright (C) 2012 Kaito Yamada
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
public final class TcpNoOperationOption implements TcpOption {

  /*
   *  +--------+
   *  |00000001|
   *  +--------+
   *    Kind=1
   */


  /**
   *
   */
  private static final long serialVersionUID = -3555140079365778548L;

  private static final TcpNoOperationOption INSTANCE
    = new TcpNoOperationOption();

  private static final TcpOptionKind kind = TcpOptionKind.NO_OPERATION;

  private TcpNoOperationOption() {}

  /**
   *
   * @return
   */
  public static TcpNoOperationOption getInstance() { return INSTANCE; }

  /**
   *
   * @param rawData
   * @return
   */
  public static TcpNoOperationOption newInstance(byte[] rawData) {
    if (rawData == null) {
      throw new NullPointerException("rawData may not be null");
    }
    if (rawData.length == 0) {
      StringBuilder sb = new StringBuilder(40);
      sb.append("The raw data length must be more than 0");
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
    return getInstance();
  }

  public TcpOptionKind getKind() { return kind; }

  public int length() { return 1; }

  public byte[] getRawData() { return new byte[] {(byte)1}; }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("[Kind: ")
      .append(kind);
    sb.append("]");
    return sb.toString();
  }

  // Override deserializer to keep singleton
  @SuppressWarnings("static-method")
  private Object readResolve() throws ObjectStreamException {
    return INSTANCE;
  }

}
