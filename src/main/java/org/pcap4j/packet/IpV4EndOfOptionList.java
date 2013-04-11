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
public final class IpV4EndOfOptionList implements IpV4Option {

  /*
   *  +--------+
   *  |00000000|
   *  +--------+
   *    Type=0
   */

  /**
   *
   */
  private static final long serialVersionUID = 5323215977996813586L;

  private static final IpV4EndOfOptionList INSTANCE
    = new IpV4EndOfOptionList();

  private static final IpV4OptionType type = IpV4OptionType.END_OF_OPTION_LIST;

  private IpV4EndOfOptionList() {}

  /**
   *
   * @return
   */
  public static IpV4EndOfOptionList getInstance() { return INSTANCE; }

  /**
   *
   * @param rawData
   * @return
   */
  public static IpV4EndOfOptionList newInstance(byte[] rawData) {
    if (rawData == null) {
      throw new NullPointerException("rawData may not be null");
    }
    if (rawData.length == 0) {
      throw new IllegalRawDataException(
              "The raw data length must be more than 0"
            );
    }
    if (rawData[0] != type.value()) {
      StringBuilder sb = new StringBuilder(100);
      sb.append("The type must be: ")
        .append(type.valueAsString())
        .append(" rawData: ")
        .append(ByteArrays.toHexString(rawData, " "));
      throw new IllegalRawDataException(sb.toString());
    }
    return INSTANCE;
  }

  public IpV4OptionType getType() { return type; }

  public int length() { return 1; }

  public byte[] getRawData() { return new byte[1]; }

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
