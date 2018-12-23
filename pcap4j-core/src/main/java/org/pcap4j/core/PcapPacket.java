/*_##########################################################################
  _##
  _##  Copyright (C) 2017  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.core;

import java.time.Instant;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.Arrays;
import org.pcap4j.packet.AbstractPacket;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.factory.PacketFactories;
import org.pcap4j.packet.namednumber.DataLinkType;
import org.pcap4j.util.LazyValue;

/**
 * Pseudo packet to hold a timestamp, an original length, and a raw data of a captured packet. This
 * class doesn't dissect the raw data until a certain method (refer to each method's javadoc) is
 * called. Instances of this class are not immutable.
 *
 * @author Kaito Yamada
 * @since pcap4j 2.0.0
 */
public final class PcapPacket extends AbstractPacket {

  private static final long serialVersionUID = -5252229699437537792L;

  private final byte[] rawData;
  private final Instant timestamp;
  private final int originalLength;
  private final LazyValue<Packet> packet;

  PcapPacket(byte[] rawData, DataLinkType dlt, Instant timestamp, int originalLength) {
    // Don't do null checks for performance reason.
    // All code to call this method must not pass nulls.
    //
    // this.rawData = Objects.requireNonNull(rawData, "rawData must not be null.");
    // this.timestamp = Objects.requireNonNull(timestamp, "timestamp must not be null.");

    // Don't do a defensive copy for performance reason.
    // All code to call this method must not modify the rawData.
    this.rawData = rawData;

    this.timestamp = timestamp;
    this.originalLength = originalLength;
    this.packet =
        new LazyValue<Packet>(
            () ->
                PacketFactories.getFactory(Packet.class, DataLinkType.class)
                    .newInstance(rawData, 0, rawData.length, dlt));
  }

  /** @return the timestamp of when this packet was captured. */
  public Instant getTimestamp() {
    return timestamp;
  }

  /** @return the original length of this packet. */
  public int getOriginalLength() {
    return originalLength;
  }

  /**
   * This method dissect the raw data.
   *
   * @return the captured packet.
   */
  public Packet getPacket() {
    return packet.getValue();
  }

  /**
   * An alternative to {@link #getPacket()}. This method dissect the raw data.
   *
   * @return the same object as {@link #getPacket()}.
   */
  @Override
  public Packet getPayload() {
    return packet.getValue();
  }

  /**
   * Get the length of the captured packet.
   *
   * @return length
   */
  @Override
  public int length() {
    return rawData.length;
  }

  /**
   * Get the raw data of the captured packet. This method doesn't do a defensive copy for
   * performance reason.
   *
   * @return raw data
   */
  @Override
  public byte[] getRawData() {
    return rawData;
  }

  /**
   * This method returns the same object as {@link #getPacket()}.{@link Packet#getBuilder()
   * getBuilder()}. This method dissect the raw data.
   *
   * @return {@link Builder} instance of the captured packet.
   */
  @Override
  public Builder getBuilder() {
    return packet.getValue().getBuilder();
  }

  @Override
  protected String buildString() {
    StringBuilder sb = new StringBuilder();
    String ls = System.getProperty("line.separator");

    sb.append("Captured at: ")
        .append(ZonedDateTime.ofInstant(timestamp, ZoneId.systemDefault()))
        .append(ls)
        .append("Original length: ")
        .append(originalLength)
        .append(" bytes")
        .append(ls)
        .append(packet.getValue());

    return sb.toString();
  }

  /** Returns a string representation of the object. This method dissect the raw data. */
  @Override
  public String toString() {
    return super.toString();
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    if (!super.equals(o)) {
      return false;
    }

    PcapPacket packets = (PcapPacket) o;

    if (originalLength != packets.originalLength) {
      return false;
    }
    if (!Arrays.equals(rawData, packets.rawData)) {
      return false;
    }
    return timestamp.equals(packets.timestamp);
  }

  @Override
  public int hashCode() {
    int result = super.hashCode();
    result = 31 * result + Arrays.hashCode(rawData);
    result = 31 * result + timestamp.hashCode();
    result = 31 * result + originalLength;
    return result;
  }
}
