/*_##########################################################################
  _##
  _##  Copyright (C) 2012-2014  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import static org.pcap4j.util.ByteArrays.*;

import java.io.Serializable;
import java.net.Inet4Address;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import org.pcap4j.packet.IpV4InternetTimestampOption.IpV4InternetTimestampOptionData;
import org.pcap4j.util.ByteArrays;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.11
 */
public final class IpV4InternetTimestampOptionTimestampsWithAddresses
    implements IpV4InternetTimestampOptionData {

  /*   0                            15                              31
   *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   *  |                        internet address                       |
   *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   *  |                           timestamp                           |
   *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   *  |                        internet address                       |
   *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   *  |                           timestamp                           |
   *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   *  |                                .                              |
   *                                   .
   *                                   .
   */

  /** */
  private static final long serialVersionUID = -331040457248187753L;

  private final List<TimestampWithAddress> timestampsWithAddresses;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new IpV4InternetTimestampOptionTimestampsWithAddresses object.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static IpV4InternetTimestampOptionTimestampsWithAddresses newInstance(
      byte[] rawData, int offset, int length) throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    return new IpV4InternetTimestampOptionTimestampsWithAddresses(rawData, offset, length);
  }

  private IpV4InternetTimestampOptionTimestampsWithAddresses(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    if ((length % INT_SIZE_IN_BYTES) != 0) {
      StringBuilder sb = new StringBuilder(100);
      sb.append("The raw data length must be an integer multiple of 4 octets long." + " rawData: ")
          .append(ByteArrays.toHexString(rawData, " "))
          .append(", offset: ")
          .append(offset)
          .append(", length: ")
          .append(length);
      throw new IllegalRawDataException(sb.toString());
    }

    this.timestampsWithAddresses = new ArrayList<TimestampWithAddress>();
    for (int i = 0; i < length; i += INT_SIZE_IN_BYTES * 2) {
      Inet4Address address = ByteArrays.getInet4Address(rawData, i + offset);
      Integer timestamp = null;
      if (i + INT_SIZE_IN_BYTES < length) {
        timestamp = ByteArrays.getInt(rawData, i + INT_SIZE_IN_BYTES + offset);
      }
      timestampsWithAddresses.add(new TimestampWithAddress(address, timestamp));
    }
  }

  /** @param timestampsWithAddresses timestampsWithAddresses */
  public IpV4InternetTimestampOptionTimestampsWithAddresses(
      List<TimestampWithAddress> timestampsWithAddresses) {
    if (timestampsWithAddresses == null) {
      throw new NullPointerException("timestamps may not be null");
    }

    Iterator<TimestampWithAddress> iter = timestampsWithAddresses.iterator();
    while (iter.hasNext()) {
      TimestampWithAddress twa = iter.next();
      if (twa.timestamp == null && iter.hasNext()) {
        throw new IllegalArgumentException(
            "Every element of timestampsWithAddresses must not have"
                + " null field except last element.");
      }
    }

    this.timestampsWithAddresses = new ArrayList<TimestampWithAddress>(timestampsWithAddresses);
  }

  /** @return timestampsWithAddresses */
  public List<TimestampWithAddress> getTimestampWithAddress() {
    return new ArrayList<TimestampWithAddress>(timestampsWithAddresses);
  }

  public int length() {
    if (timestampsWithAddresses.get(timestampsWithAddresses.size() - 1).timestamp == null) {
      return timestampsWithAddresses.size() * INT_SIZE_IN_BYTES * 2 - INT_SIZE_IN_BYTES;
    } else {
      return timestampsWithAddresses.size() * INT_SIZE_IN_BYTES * 2;
    }
  }

  public byte[] getRawData() {
    byte[] rawData = new byte[length()];
    Iterator<TimestampWithAddress> iter = timestampsWithAddresses.iterator();
    for (int i = 0; i < rawData.length; i += INT_SIZE_IN_BYTES * 2) {
      TimestampWithAddress twa = iter.next();
      System.arraycopy(ByteArrays.toByteArray(twa.address), 0, rawData, i, INT_SIZE_IN_BYTES);
      if (twa.timestamp != null) {
        System.arraycopy(
            ByteArrays.toByteArray(twa.timestamp),
            0,
            rawData,
            i + INT_SIZE_IN_BYTES,
            INT_SIZE_IN_BYTES);
      }
    }
    return rawData;
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("[(address, timestamp):");
    for (TimestampWithAddress twa : timestampsWithAddresses) {
      sb.append(twa);
    }
    sb.append("]");
    return sb.toString();
  }

  @Override
  public boolean equals(Object obj) {
    if (obj == this) {
      return true;
    }
    if (!this.getClass().isInstance(obj)) {
      return false;
    }
    return Arrays.equals((getClass().cast(obj)).getRawData(), getRawData());
  }

  @Override
  public int hashCode() {
    return Arrays.hashCode(getRawData());
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 0.9.11
   */
  public static final class TimestampWithAddress implements Serializable {

    /** */
    private static final long serialVersionUID = -1592713837380606740L;

    private final Inet4Address address;
    private final Integer timestamp;

    /**
     * @param address address
     * @param timestamp timestamp
     */
    public TimestampWithAddress(Inet4Address address, Integer timestamp) {
      if (address == null) {
        throw new NullPointerException("address may not be null");
      }
      this.address = address;
      this.timestamp = timestamp;
    }

    /** @return address */
    public Inet4Address getAddress() {
      return address;
    }

    /** @return timestamp */
    public Integer getTimestamp() {
      return timestamp;
    }

    @Override
    public String toString() {
      StringBuilder sb = new StringBuilder();
      sb.append("(").append(address).append(", ");
      if (timestamp != null) {
        sb.append(timestamp & 0xFFFFFFFFL);
      }
      sb.append(")");
      return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
      if (obj == this) {
        return true;
      }
      if (!this.getClass().isInstance(obj)) {
        return false;
      }
      TimestampWithAddress other = (TimestampWithAddress) obj;
      return this.timestamp.equals(other.timestamp) && this.address.equals(other.address);
    }

    @Override
    public int hashCode() {
      int hash = 17; // seed
      if (timestamp != null) {
        hash = 31 * hash + timestamp.hashCode();
      }
      hash = 31 * hash + address.hashCode();
      return hash;
    }
  }
}
