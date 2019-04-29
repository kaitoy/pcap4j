/*_##########################################################################
  _##
  _##  Copyright (C) 2016-2019 Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import static org.pcap4j.util.ByteArrays.INT_SIZE_IN_BYTES;
import static org.pcap4j.util.ByteArrays.SHORT_SIZE_IN_BYTES;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.pcap4j.packet.factory.PacketFactories;
import org.pcap4j.packet.namednumber.SctpChunkType;
import org.pcap4j.packet.namednumber.SctpPort;
import org.pcap4j.util.ByteArrays;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * SCTP Packet
 *
 * @see <a href="https://tools.ietf.org/html/rfc4960">RFC 4960</a>
 * @author Jeff Myers (myersj@gmail.com)
 * @since pcap4j 1.6.6
 */
public final class SctpPacket extends AbstractPacket implements TransportPacket {

  /** */
  private static final long serialVersionUID = -1082956644945517426L;

  private static final Logger logger = LoggerFactory.getLogger(SctpPacket.class);

  private final SctpHeader header;
  private final Packet payload;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new SctpPacket object.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static SctpPacket newPacket(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    return new SctpPacket(rawData, offset, length);
  }

  private SctpPacket(byte[] rawData, int offset, int length) throws IllegalRawDataException {
    this.header = new SctpHeader(rawData, offset, length);
    this.payload = null;
  }

  private SctpPacket(Builder builder) {
    if (builder == null || builder.srcPort == null || builder.dstPort == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("builder: ")
          .append(builder)
          .append(" builder.srcPort: ")
          .append(builder.srcPort)
          .append(" builder.dstPort: ")
          .append(builder.dstPort);
      throw new NullPointerException(sb.toString());
    }

    this.payload = builder.payloadBuilder != null ? builder.payloadBuilder.build() : null;
    this.header = new SctpHeader(builder);
  }

  @Override
  public SctpHeader getHeader() {
    return header;
  }

  @Override
  public Packet getPayload() {
    return payload;
  }

  @Override
  public Builder getBuilder() {
    return new Builder(this);
  }

  /** @return true if the checksum in this header is valid; false otherwise. */
  public boolean hasValidChecksum() {
    return header.calcChecksum() == header.checksum;
  }

  /**
   * @author Jeff Myers (myersj@gmail.com)
   * @since pcap4j 1.6.6
   */
  public static final class Builder extends AbstractBuilder implements ChecksumBuilder<SctpPacket> {

    private SctpPort srcPort;
    private SctpPort dstPort;
    private int verificationTag;
    private int checksum;
    private List<SctpChunk> chunks;
    private boolean correctChecksumAtBuild;
    private Packet.Builder payloadBuilder;

    /** */
    public Builder() {}

    /** @param packet packet */
    public Builder(SctpPacket packet) {
      this.srcPort = packet.header.srcPort;
      this.dstPort = packet.header.dstPort;
      this.verificationTag = packet.header.verificationTag;
      this.checksum = packet.header.checksum;
      this.chunks = packet.header.chunks;
      this.payloadBuilder = packet.payload != null ? packet.payload.getBuilder() : null;
    }

    /**
     * @param srcPort srcPort
     * @return this Builder object for method chaining.
     */
    public Builder srcPort(SctpPort srcPort) {
      this.srcPort = srcPort;
      return this;
    }

    /**
     * @param dstPort dstPort
     * @return this Builder object for method chaining.
     */
    public Builder dstPort(SctpPort dstPort) {
      this.dstPort = dstPort;
      return this;
    }

    /**
     * @param verificationTag verification tag
     * @return this Builder object for method chaining.
     */
    public Builder verificationTag(int verificationTag) {
      this.verificationTag = verificationTag;
      return this;
    }

    /**
     * @param checksum checksum
     * @return this Builder object for method chaining.
     */
    public Builder checksum(int checksum) {
      this.checksum = checksum;
      return this;
    }

    /**
     * @param chunks chunks
     * @return this Builder object for method chaining.
     */
    public Builder chunks(List<SctpChunk> chunks) {
      this.chunks = chunks;
      return this;
    }

    @Override
    public Builder correctChecksumAtBuild(boolean correctChecksumAtBuild) {
      this.correctChecksumAtBuild = correctChecksumAtBuild;
      return this;
    }

    @Override
    public Builder payloadBuilder(Packet.Builder payloadBuilder) {
      this.payloadBuilder = payloadBuilder;
      return this;
    }

    @Override
    public Packet.Builder getPayloadBuilder() {
      return payloadBuilder;
    }

    @Override
    public SctpPacket build() {
      return new SctpPacket(this);
    }
  }

  /**
   * SCTP header
   *
   * <pre style="white-space: pre;">
   *  0                              16                            31
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   * |           Src Port            |           Dst Port            |
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   * |                        Verification Tag                       |
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   * |                            Checksum                           |
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   * |                          Chunk #1                             |
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   * |                           ...                                 |
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   * |                          Chunk #n                             |
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   * </pre>
   *
   * @see <a href="https://tools.ietf.org/html/rfc4960">RFC 4960</a>
   * @author Jeff Myers (myersj@gmail.com)
   * @since pcap4j 1.6.6
   */
  public static final class SctpHeader extends AbstractHeader implements TransportHeader {

    /** */
    private static final long serialVersionUID = -8223170335586535940L;

    private static final int SRC_PORT_OFFSET = 0;
    private static final int SRC_PORT_SIZE = SHORT_SIZE_IN_BYTES;
    private static final int DST_PORT_OFFSET = SRC_PORT_OFFSET + SRC_PORT_SIZE;
    private static final int DST_PORT_SIZE = SHORT_SIZE_IN_BYTES;
    private static final int VERIFICATION_TAG_OFFSET = DST_PORT_OFFSET + DST_PORT_SIZE;
    private static final int VERIFICAION_TAG_SIZE = INT_SIZE_IN_BYTES;
    private static final int CHECKSUM_OFFSET = VERIFICATION_TAG_OFFSET + VERIFICAION_TAG_SIZE;
    private static final int CHECKSUM_SIZE = INT_SIZE_IN_BYTES;
    private static final int CHUNKS_OFFSET = CHECKSUM_OFFSET + CHECKSUM_SIZE;

    private final SctpPort srcPort;
    private final SctpPort dstPort;
    private final int verificationTag;
    private final int checksum;
    private final List<SctpChunk> chunks;

    private SctpHeader(byte[] rawData, int offset, int length) throws IllegalRawDataException {
      if (length < CHUNKS_OFFSET) {
        StringBuilder sb = new StringBuilder(80);
        sb.append("The data is too short to build a SCTP header(")
            .append(CHUNKS_OFFSET)
            .append(" bytes). data: ")
            .append(ByteArrays.toHexString(rawData, " "))
            .append(", offset: ")
            .append(offset)
            .append(", length: ")
            .append(length);
        throw new IllegalRawDataException(sb.toString());
      }

      this.srcPort = SctpPort.getInstance(ByteArrays.getShort(rawData, SRC_PORT_OFFSET + offset));
      this.dstPort = SctpPort.getInstance(ByteArrays.getShort(rawData, DST_PORT_OFFSET + offset));
      this.verificationTag = ByteArrays.getInt(rawData, VERIFICATION_TAG_OFFSET + offset);
      this.checksum = ByteArrays.getInt(rawData, CHECKSUM_OFFSET + offset);

      this.chunks = new ArrayList<SctpChunk>();
      length -= CHUNKS_OFFSET;
      offset += CHUNKS_OFFSET;
      try {
        while (length != 0) {
          SctpChunkType type = SctpChunkType.getInstance(rawData[offset]);
          SctpChunk newOne;
          newOne =
              PacketFactories.getFactory(SctpChunk.class, SctpChunkType.class)
                  .newInstance(rawData, offset, length, type);
          chunks.add(newOne);
          int newOneLen = newOne.length();
          offset += newOneLen;
          length -= newOneLen;
        }
      } catch (Exception e) {
        logger.error("Exception occurred during analyzing SCTP chunks: ", e);
        throw new IllegalRawDataException("Exception occurred during analyzing SCTP chunks", e);
      }
    }

    private SctpHeader(Builder builder) {
      this.srcPort = builder.srcPort;
      this.dstPort = builder.dstPort;
      this.verificationTag = builder.verificationTag;
      if (builder.chunks != null) {
        this.chunks = new ArrayList<SctpChunk>(builder.chunks);
      } else {
        this.chunks = Collections.emptyList();
      }

      if (builder.correctChecksumAtBuild) {
        this.checksum = calcChecksum();
      } else {
        this.checksum = builder.checksum;
      }
    }

    private int calcChecksum() {
      byte[] data = new byte[length()];

      // If call getRawData() here, rawData will be cached with
      // an invalid checksum in some cases.
      // To avoid it, use buildRawData() instead.
      System.arraycopy(buildRawData(), 0, data, 0, data.length);

      for (int i = 0; i < CHECKSUM_SIZE; i++) {
        data[CHECKSUM_OFFSET + i] = (byte) 0;
      }

      if (PacketPropertiesLoader.getInstance().sctpCalcChecksumByAdler32()) {
        return ByteArrays.calcAdler32Checksum(data);
      } else {
        int crc = ByteArrays.calcCrc32cChecksum(data);
        return (crc << 24)
            | (crc & 0x0000FF00) << 8
            | (crc & 0x00FF0000) >> 8
            | (crc & 0xFF000000) >>> 24;
      }
    }

    @Override
    public SctpPort getSrcPort() {
      return srcPort;
    }

    @Override
    public SctpPort getDstPort() {
      return dstPort;
    }

    /** @return verification tag */
    public int getVerificationTag() {
      return verificationTag;
    }

    /** @return checksum */
    public int getChecksum() {
      return checksum;
    }

    /** @return chunks */
    public List<SctpChunk> getChunks() {
      return new ArrayList<SctpChunk>(chunks);
    }

    @Override
    protected List<byte[]> getRawFields() {
      List<byte[]> rawFields = new ArrayList<byte[]>();
      rawFields.add(ByteArrays.toByteArray(srcPort.value()));
      rawFields.add(ByteArrays.toByteArray(dstPort.value()));
      rawFields.add(ByteArrays.toByteArray(verificationTag));
      rawFields.add(ByteArrays.toByteArray(checksum));
      for (SctpChunk chunk : chunks) {
        rawFields.add(chunk.getRawData());
      }
      return rawFields;
    }

    @Override
    protected int calcLength() {
      int len = CHUNKS_OFFSET;
      for (SctpChunk chunk : chunks) {
        len += chunk.length();
      }
      return len;
    }

    @Override
    protected String buildString() {
      StringBuilder sb = new StringBuilder();
      String ls = System.getProperty("line.separator");

      sb.append("[SCTP Header (").append(length()).append(" bytes)]").append(ls);
      sb.append("  Source port: ").append(getSrcPort()).append(ls);
      sb.append("  Destination port: ").append(getDstPort()).append(ls);
      sb.append("  Verification tag: 0x")
          .append(ByteArrays.toHexString(verificationTag, ""))
          .append(ls);
      sb.append("  Checksum: 0x").append(ByteArrays.toHexString(checksum, "")).append(ls);
      sb.append("  Chunks:").append(ls);
      for (SctpChunk chunk : chunks) {
        sb.append("    ").append(chunk).append(ls);
      }
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

      SctpHeader other = (SctpHeader) obj;
      return checksum == other.checksum
          && verificationTag == other.verificationTag
          && srcPort.equals(other.srcPort)
          && dstPort.equals(other.dstPort)
          && chunks.equals(other.chunks);
    }

    @Override
    protected int calcHashCode() {
      int result = 17;
      result = 31 * result + srcPort.hashCode();
      result = 31 * result + dstPort.hashCode();
      result = 31 * result + verificationTag;
      result = 31 * result + checksum;
      result = 31 * result + chunks.hashCode();
      return result;
    }
  }

  /**
   * The interface representing an SCTP Chunk Field. If you use {@link
   * org.pcap4j.packet.factory.propertiesbased.PropertiesBasedPacketFactory
   * PropertiesBasedPacketFactory}, classes which implement this interface must implement the
   * following method: {@code public static SctpChunk newInstance(byte[] rawData, int offset, int
   * length) throws IllegalRawDataException}
   *
   * @see <a href="https://tools.ietf.org/html/rfc4960#section-3.2">RFC 4960</a>
   * @author Kaito Yamada
   * @since pcap4j 1.6.6
   */
  public interface SctpChunk extends Serializable {

    /** @return type */
    public SctpChunkType getType();

    /** @return length */
    public int length();

    /** @return raw data */
    public byte[] getRawData();
  }
}
