/*_##########################################################################
  _##
  _##  Copyright (C) 2016  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import java.util.Arrays;
import org.pcap4j.packet.SctpPacket.SctpChunk;
import org.pcap4j.packet.namednumber.SctpChunkType;
import org.pcap4j.util.ByteArrays;

/**
 * Illegal SCTP Chunk
 *
 * @see <a href="https://tools.ietf.org/html/rfc4960#section-3.2">RFC 4960</a>
 * @author Kaito Yamada
 * @since pcap4j 1.6.6
 */
public final class IllegalSctpChunk implements SctpChunk, IllegalRawDataHolder {

  /** */
  private static final long serialVersionUID = 379650793871792784L;

  private final SctpChunkType type;
  private final byte[] rawData;
  private final IllegalRawDataException cause;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @param cause cause
   * @return a new UnknownSctpChunk object.
   */
  public static IllegalSctpChunk newInstance(
      byte[] rawData, int offset, int length, IllegalRawDataException cause) {
    if (cause == null) {
      throw new NullPointerException("cause is null.");
    }
    ByteArrays.validateBounds(rawData, offset, length);
    return new IllegalSctpChunk(rawData, offset, length, cause);
  }

  private IllegalSctpChunk(byte[] rawData, int offset, int length, IllegalRawDataException cause) {
    this.type = SctpChunkType.getInstance(rawData[offset]);
    this.rawData = new byte[length];
    System.arraycopy(rawData, offset, this.rawData, 0, length);
    this.cause = cause;
  }

  @Override
  public SctpChunkType getType() {
    return type;
  }

  @Override
  public int length() {
    return rawData.length;
  }

  @Override
  public byte[] getRawData() {
    byte[] copy = new byte[rawData.length];
    System.arraycopy(rawData, 0, copy, 0, copy.length);
    return copy;
  }

  @Override
  public IllegalRawDataException getCause() {
    return cause;
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();

    sb.append("[Type: ").append(type);
    sb.append(", Illegal Raw Data: 0x").append(ByteArrays.toHexString(rawData, ""));
    sb.append(", Cause: ").append(cause);
    sb.append("]");

    return sb.toString();
  }

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + cause.hashCode();
    result = prime * result + Arrays.hashCode(rawData);
    return result;
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }
    if (obj == null) {
      return false;
    }
    if (getClass() != obj.getClass()) {
      return false;
    }
    IllegalSctpChunk other = (IllegalSctpChunk) obj;
    if (!cause.equals(other.cause)) {
      return false;
    }
    if (!Arrays.equals(rawData, other.rawData)) {
      return false;
    }
    return true;
  }
}
