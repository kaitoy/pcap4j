/*_##########################################################################
  _##
  _##  Copyright (C) 2012  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import java.io.Serializable;
import org.pcap4j.packet.namednumber.IpV6OptionType;
import org.pcap4j.util.ByteArrays;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.10
 */
public final class IpV6Option implements Serializable {

  /**
   *
   */
  private static final long serialVersionUID = 2182260121605325195L;

  private final IpV6OptionType optionType;
  private final byte optDataLen;
  private final byte[] optionData;

  public static IpV6Option newInstance(byte[] rawData) {
    return new IpV6Option(rawData);
  }

  private IpV6Option(byte[] rawData) {
    if (rawData == null) {
      throw new NullPointerException("rawData may not be null");
    }
    if (rawData.length == 0) {
      throw new IllegalPacketDataException("IPv6 option length may not be 0");
    }

    this.optionType
      = IpV6OptionType.getInstance(ByteArrays.getByte(rawData, 0));

    if (optionType.equals(IpV6OptionType.PAD1)) {
      this.optDataLen = 0;
      this.optionData = null;
    }
    else {
      if (rawData.length == 1) {
        throw new IllegalPacketDataException(
                "IPv6 option(except Pad1) length must be more than 1"
              );
      }

      this.optDataLen = ByteArrays.getByte(rawData, 1);

      if (rawData.length < optDataLen) {
        StringBuilder sb = new StringBuilder(100);
        sb.append("The data is too short to build an IPv6 option(")
          .append(optDataLen)
          .append(" bytes). data: ")
          .append(ByteArrays.toHexString(rawData, " "));
        throw new IllegalPacketDataException(sb.toString());
      }

      this.optionData = ByteArrays.getSubArray(rawData, 2, optDataLen);
    }
  }

  public IpV6OptionType getOptionType() {
    return optionType;
  }

  public byte getOptDataLen() {
    return optDataLen;
  }

  public int getOptDataLenAsInt() {
    return 0xFF & optDataLen;
  }

  public byte[] getOptionData() {
    byte[] copy = new byte[optionData.length];
    System.arraycopy(optionData, 0, copy, 0, copy.length);
    return copy;
  }

  public boolean isValid() {
    return optionData.length == getOptDataLenAsInt();
  }

  public int length() {
    return optionData.length + 2;
  }

  public byte[] getRawData() {
    if (optionType.equals(IpV6OptionType.PAD1)) {
      return new byte[1];
    }

    byte[] rawData = new byte[optionData.length + 2];

    rawData[0] = optionType.value();
    rawData[1] = optDataLen;
    System.arraycopy(
      optionData, 0,
      rawData, 2, optionData.length
    );

    return rawData;
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("[Option Type] ")
      .append(optionType);
    sb.append(" [Opt Data Len] ")
      .append(getOptDataLenAsInt())
      .append(" bytes");
    sb.append(" [Option Data] ")
      .append(ByteArrays.toHexString(optionData, " "));
    return sb.toString();
  }

}
