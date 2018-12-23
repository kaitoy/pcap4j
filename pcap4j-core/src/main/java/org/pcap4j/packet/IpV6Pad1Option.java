/*_##########################################################################
  _##
  _##  Copyright (C) 2012-2014  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import java.io.ObjectStreamException;
import org.pcap4j.packet.IpV6ExtOptionsPacket.IpV6Option;
import org.pcap4j.packet.namednumber.IpV6OptionType;
import org.pcap4j.util.ByteArrays;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.10
 */
public final class IpV6Pad1Option implements IpV6Option {

  /*
   * Pad1 option  (alignment requirement: none)
   *
   *   +-+-+-+-+-+-+-+-+
   *   |       0       |
   *   +-+-+-+-+-+-+-+-+
   */

  /** */
  private static final long serialVersionUID = 2182260121605325195L;

  private static final IpV6Pad1Option INSTANCE = new IpV6Pad1Option();

  private static final IpV6OptionType type = IpV6OptionType.getInstance((byte) 0);

  private IpV6Pad1Option() {}

  /** @return the singleton instance of IpV6Pad1Option. */
  public static IpV6Pad1Option getInstance() {
    return INSTANCE;
  }

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return the singleton instance of IpV6Pad1Option.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static IpV6Pad1Option newInstance(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    if (rawData[offset] != type.value()) {
      StringBuilder sb = new StringBuilder(100);
      sb.append("The type must be: ")
          .append(type.valueAsString())
          .append(" rawData: ")
          .append(ByteArrays.toHexString(rawData, " "));
      throw new IllegalRawDataException(sb.toString());
    }
    return INSTANCE;
  }

  @Override
  public IpV6OptionType getType() {
    return type;
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
    sb.append("[Option Type: ").append(type);
    sb.append("]");
    return sb.toString();
  }

  // Override deserializer to keep singleton
  @SuppressWarnings("static-method")
  private Object readResolve() throws ObjectStreamException {
    return INSTANCE;
  }
}
