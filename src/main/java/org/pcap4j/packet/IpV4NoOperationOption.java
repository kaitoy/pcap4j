/*_##########################################################################
  _##
  _##  Copyright (C) 2012 Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import java.io.ObjectStreamException;
import org.pcap4j.packet.IpV4Packet.IpV4Option;
import org.pcap4j.packet.namednumber.IpV4OptionType;
import org.pcap4j.util.ByteArrays;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.11
 */
public final class IpV4NoOperationOption implements IpV4Option {

  /*
   *  +--------+
   *  |00000001|
   *  +--------+
   *    Type=1
   */

  /**
   *
   */
  private static final long serialVersionUID = 194338954674452009L;

  private static final IpV4NoOperationOption INSTANCE
    = new IpV4NoOperationOption();

  private static final IpV4OptionType type = IpV4OptionType.NO_OPERATION;

  private IpV4NoOperationOption() {}

  /**
   *
   * @return the singleton instance of IpV4NoOperationOption.
   */
  public static IpV4NoOperationOption getInstance() { return INSTANCE; }

  /**
   *
   * @param rawData
   * @return the singleton instance of IpV4NoOperationOption.
   */
  public static IpV4NoOperationOption newInstance(byte[] rawData) {
    if (rawData == null) {
      throw new NullPointerException("rawData may not be null");
    }
    if (rawData.length == 0) {
      StringBuilder sb = new StringBuilder(40);
      sb.append("The raw data length must be more than 0");
      throw new IllegalRawDataException(sb.toString());
    }
    if (rawData[0] != type.value()) {
      StringBuilder sb = new StringBuilder(100);
      sb.append("The type must be: ")
        .append(type.valueAsString())
        .append(" rawData: ")
        .append(ByteArrays.toHexString(rawData, " "));
      throw new IllegalRawDataException(sb.toString());
    }
    return getInstance();
  }

  public IpV4OptionType getType() { return type; }

  public int length() { return 1; }

  public byte[] getRawData() { return new byte[] {(byte)1}; }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("[option-type: ")
      .append(type);
    sb.append("]");
    return sb.toString();
  }

  // Override deserializer to keep singleton
  private Object readResolve() throws ObjectStreamException {
    return INSTANCE;
  }

}
