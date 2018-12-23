/*_##########################################################################
  _##
  _##  Copyright (C) 2016  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import static org.pcap4j.util.ByteArrays.*;

import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.List;
import org.pcap4j.util.ByteArrays;
import org.pcap4j.util.MacAddress;

/**
 * IEEE802.11 management frame
 *
 * @see <a href="http://standards.ieee.org/getieee802/download/802.11-2012.pdf">IEEE802.11</a>
 * @author Kaito Yamada
 * @since pcap4j 1.7.0
 */
public abstract class Dot11ManagementPacket extends AbstractPacket {

  /** */
  private static final long serialVersionUID = -3972573868672848666L;

  private final Integer fcs;

  /**
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @param headerLen headerLen
   */
  protected Dot11ManagementPacket(byte[] rawData, int offset, int length, int headerLen) {
    int remainingLen = length - headerLen;
    if (remainingLen >= 4) {
      this.fcs = ByteArrays.getInt(rawData, offset + headerLen, ByteOrder.LITTLE_ENDIAN);
    } else {
      this.fcs = null;
    }
  }

  /**
   * @param builder builder
   * @param header header
   */
  protected Dot11ManagementPacket(Builder builder, Dot11ManagementHeader header) {
    if (builder.correctChecksumAtBuild) {
      this.fcs = ByteArrays.calcCrc32Checksum(header.getRawData());
    } else {
      this.fcs = builder.fcs;
    }
  }

  @Override
  public abstract Dot11ManagementHeader getHeader();

  /** @return fcs. May be null. */
  public Integer getFcs() {
    return fcs;
  }

  @Override
  protected int calcLength() {
    int length = super.calcLength();
    if (fcs != null) {
      length += 4;
    }
    return length;
  }

  @Override
  protected byte[] buildRawData() {
    byte[] rawData = super.buildRawData();
    if (fcs != null) {
      System.arraycopy(
          ByteArrays.toByteArray(fcs, ByteOrder.LITTLE_ENDIAN), 0, rawData, rawData.length - 4, 4);
    }
    return rawData;
  }

  @Override
  protected String buildString() {
    StringBuilder sb = new StringBuilder();

    sb.append(getHeader().toString());
    if (fcs != null) {
      String ls = System.getProperty("line.separator");
      sb.append("[IEEE802.11 Management Packet FCS]")
          .append(ls)
          .append("  FCS: 0x")
          .append(ByteArrays.toHexString(fcs, ""))
          .append(ls);
    }

    return sb.toString();
  }

  @Override
  public abstract Builder getBuilder();

  /** @return true if this FCS is present and valid; false otherwise. */
  public boolean hasValidFcs() {
    if (fcs == null) {
      return false;
    }
    return ByteArrays.calcCrc32Checksum(getHeader().getRawData()) == fcs.intValue();
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 1.7.0
   */
  public abstract static class Builder extends AbstractBuilder
      implements ChecksumBuilder<Dot11ManagementPacket> {

    private Dot11FrameControl frameControl;
    private short duration;
    private MacAddress address1;
    private MacAddress address2;
    private MacAddress address3;
    private Dot11SequenceControl sequenceControl;
    private Dot11HtControl htControl;
    private Integer fcs;
    private boolean correctChecksumAtBuild;

    /** */
    public Builder() {}

    /** @param packet packet */
    protected Builder(Dot11ManagementPacket packet) {
      this.frameControl = packet.getHeader().frameControl;
      this.duration = packet.getHeader().duration;
      this.address1 = packet.getHeader().address1;
      this.address2 = packet.getHeader().address2;
      this.address3 = packet.getHeader().address3;
      this.sequenceControl = packet.getHeader().sequenceControl;
      this.htControl = packet.getHeader().htControl;
      this.fcs = packet.fcs;
    }

    /**
     * @param frameControl frameControl
     * @return this Builder object for method chaining.
     */
    public Builder frameControl(Dot11FrameControl frameControl) {
      this.frameControl = frameControl;
      return this;
    }

    /**
     * @param duration duration
     * @return this Builder object for method chaining.
     */
    public Builder duration(short duration) {
      this.duration = duration;
      return this;
    }

    /**
     * @param address1 address1
     * @return this Builder object for method chaining.
     */
    public Builder address1(MacAddress address1) {
      this.address1 = address1;
      return this;
    }

    /**
     * @param address2 address2
     * @return this Builder object for method chaining.
     */
    public Builder address2(MacAddress address2) {
      this.address2 = address2;
      return this;
    }

    /**
     * @param address3 address3
     * @return this Builder object for method chaining.
     */
    public Builder address3(MacAddress address3) {
      this.address3 = address3;
      return this;
    }

    /**
     * @param sequenceControl sequenceControl
     * @return this Builder object for method chaining.
     */
    public Builder sequenceControl(Dot11SequenceControl sequenceControl) {
      this.sequenceControl = sequenceControl;
      return this;
    }

    /**
     * @param htControl htControl
     * @return this Builder object for method chaining.
     */
    public Builder htControl(Dot11HtControl htControl) {
      this.htControl = htControl;
      return this;
    }

    /**
     * @param fcs fcs
     * @return this Builder object for method chaining.
     */
    public Builder fcs(Integer fcs) {
      this.fcs = fcs;
      return this;
    }

    @Override
    public Builder correctChecksumAtBuild(boolean correctChecksumAtBuild) {
      this.correctChecksumAtBuild = correctChecksumAtBuild;
      return this;
    }

    /** Call me at the top of {@link #build()}. */
    protected void checkForNull() {
      if (frameControl == null || address1 == null || address2 == null || address3 == null) {
        StringBuilder sb = new StringBuilder();
        sb.append("frameControl: ")
            .append(frameControl)
            .append(" address1: ")
            .append(address1)
            .append(" address2: ")
            .append(address2)
            .append(" address3: ")
            .append(address3);
        throw new NullPointerException(sb.toString());
      }
    }

    @Override
    public abstract Dot11ManagementPacket build();
  }

  /**
   * Header of IEEE802.11 management frame
   *
   * <pre style="white-space: pre;">
   *  0                             15
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   * |         Frame Control         |
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   * |         Duration              |
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   * |                               |
   * |          Address1             |
   * |                               |
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   * |                               |
   * |          Address2             |
   * |                               |
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   * |                               |
   * |          Address3             |
   * |                               |
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   * |       Sequence Control        |
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   * |         HT Control            |
   * |                               |
   * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   * </pre>
   *
   * @see <a href="http://standards.ieee.org/getieee802/download/802.11-2012.pdf">IEEE802.11</a>
   * @author Kaito Yamada
   * @since pcap4j 1.7.0
   */
  public abstract static class Dot11ManagementHeader extends AbstractHeader {

    /** */
    private static final long serialVersionUID = 615170086003609919L;

    private static final int FRAME_CONTROL_OFFSET = 0;
    private static final int FRAME_CONTROL_SIZE = SHORT_SIZE_IN_BYTES;
    private static final int DURATION_OFFSET = FRAME_CONTROL_OFFSET + FRAME_CONTROL_SIZE;
    private static final int DURATION_SIZE = SHORT_SIZE_IN_BYTES;
    private static final int ADDRESS1_OFFSET = DURATION_OFFSET + DURATION_SIZE;
    private static final int ADDRESS1_SIZE = MacAddress.SIZE_IN_BYTES;
    private static final int ADDRESS2_OFFSET = ADDRESS1_OFFSET + ADDRESS1_SIZE;
    private static final int ADDRESS2_SIZE = MacAddress.SIZE_IN_BYTES;
    private static final int ADDRESS3_OFFSET = ADDRESS2_OFFSET + ADDRESS2_SIZE;
    private static final int ADDRESS3_SIZE = MacAddress.SIZE_IN_BYTES;
    private static final int SEQUENCE_CONTROL_OFFSET = ADDRESS3_OFFSET + ADDRESS3_SIZE;
    private static final int SEQUENCE_CONTROL_SIZE = SHORT_SIZE_IN_BYTES;
    private static final int HT_CONTROL_OFFSET = SEQUENCE_CONTROL_OFFSET + SEQUENCE_CONTROL_SIZE;
    private static final int HT_CONTROL_SIZE = INT_SIZE_IN_BYTES;
    private static final int DOT11_HEADER_MIN_SIZE = HT_CONTROL_OFFSET;

    private final Dot11FrameControl frameControl;
    private final short duration;
    private final MacAddress address1;
    private final MacAddress address2;
    private final MacAddress address3;
    private final Dot11SequenceControl sequenceControl;
    private final Dot11HtControl htControl;

    /**
     * @param rawData rawData
     * @param offset offset
     * @param length length
     * @throws IllegalRawDataException if parsing the raw data fails.
     */
    protected Dot11ManagementHeader(byte[] rawData, int offset, int length)
        throws IllegalRawDataException {
      if (length < DOT11_HEADER_MIN_SIZE) {
        StringBuilder sb = new StringBuilder(200);
        sb.append("The data is too short to build a Dot11ManagementHeader (")
            .append(DOT11_HEADER_MIN_SIZE)
            .append(" bytes). data: ")
            .append(ByteArrays.toHexString(rawData, " "))
            .append(", offset: ")
            .append(offset)
            .append(", length: ")
            .append(length);
        throw new IllegalRawDataException(sb.toString());
      }

      this.frameControl =
          Dot11FrameControl.newInstance(rawData, offset + FRAME_CONTROL_OFFSET, length);
      this.duration =
          ByteArrays.getShort(rawData, offset + DURATION_OFFSET, ByteOrder.LITTLE_ENDIAN);
      this.address1 = ByteArrays.getMacAddress(rawData, offset + ADDRESS1_OFFSET);
      this.address2 = ByteArrays.getMacAddress(rawData, offset + ADDRESS2_OFFSET);
      this.address3 = ByteArrays.getMacAddress(rawData, offset + ADDRESS3_OFFSET);
      this.sequenceControl =
          Dot11SequenceControl.newInstance(
              rawData, offset + SEQUENCE_CONTROL_OFFSET, length - SEQUENCE_CONTROL_OFFSET);
      if (frameControl.isOrder()) {
        if (length < DOT11_HEADER_MIN_SIZE + HT_CONTROL_SIZE) {
          StringBuilder sb = new StringBuilder(200);
          sb.append("The data is too short to build a Dot11ManagementHeader (")
              .append(DOT11_HEADER_MIN_SIZE + HT_CONTROL_SIZE)
              .append(" bytes). data: ")
              .append(ByteArrays.toHexString(rawData, " "))
              .append(", offset: ")
              .append(offset)
              .append(", length: ")
              .append(length);
          throw new IllegalRawDataException(sb.toString());
        }
        this.htControl =
            Dot11HtControl.newInstance(
                rawData, offset + HT_CONTROL_OFFSET, length - HT_CONTROL_OFFSET);
      } else {
        this.htControl = null;
      }
    }

    /** @param builder builder */
    protected Dot11ManagementHeader(Builder builder) {
      this.frameControl = builder.frameControl;
      this.duration = builder.duration;
      this.address1 = builder.address1;
      this.address2 = builder.address2;
      this.address3 = builder.address3;
      this.sequenceControl = builder.sequenceControl;
      this.htControl = builder.htControl;
    }

    /** @return frameControl */
    public Dot11FrameControl getFrameControl() {
      return frameControl;
    }

    /** @return duration */
    public short getDuration() {
      return duration;
    }

    /** @return duration */
    public int getDurationAsInt() {
      return duration & 0xFFFF;
    }

    /** @return address1 */
    public MacAddress getAddress1() {
      return address1;
    }

    /** @return address2 */
    public MacAddress getAddress2() {
      return address2;
    }

    /** @return address3 */
    public MacAddress getAddress3() {
      return address3;
    }

    /** @return sequenceControl */
    public Dot11SequenceControl getSequenceControl() {
      return sequenceControl;
    }

    /** @return htControl. May be null. */
    public Dot11HtControl getHtControl() {
      return htControl;
    }

    @Override
    protected List<byte[]> getRawFields() {
      List<byte[]> rawFields = new ArrayList<byte[]>();
      rawFields.add(frameControl.getRawData());
      rawFields.add(ByteArrays.toByteArray(duration, ByteOrder.LITTLE_ENDIAN));
      rawFields.add(address1.getAddress());
      rawFields.add(address2.getAddress());
      rawFields.add(address3.getAddress());
      rawFields.add(sequenceControl.getRawData());
      if (htControl != null) {
        rawFields.add(htControl.getRawData());
      }
      return rawFields;
    }

    @Override
    public int calcLength() {
      if (htControl != null) {
        return DOT11_HEADER_MIN_SIZE + HT_CONTROL_SIZE;
      } else {
        return DOT11_HEADER_MIN_SIZE;
      }
    }

    /** @return the header name. */
    protected abstract String getHeaderName();

    @Override
    protected String buildString() {
      StringBuilder sb = new StringBuilder();
      String ls = System.getProperty("line.separator");

      sb.append("[")
          .append(getHeaderName())
          .append(" (")
          .append(length())
          .append(" bytes)]")
          .append(ls);
      sb.append("  Frame Control:").append(ls).append(frameControl.toString("    "));
      sb.append("  Duration: ").append(getDurationAsInt()).append(ls);
      sb.append("  Address1: ").append(address1).append(ls);
      sb.append("  Address2: ").append(address2).append(ls);
      sb.append("  Address3: ").append(address3).append(ls);
      sb.append("  Sequence Control: ").append(sequenceControl).append(ls);
      if (htControl != null) {
        sb.append("  HT Control:").append(ls).append(htControl.toString("    "));
      }

      return sb.toString();
    }

    @Override
    protected int calcHashCode() {
      final int prime = 31;
      int result = 17;
      result = prime * result + address1.hashCode();
      result = prime * result + address2.hashCode();
      result = prime * result + address3.hashCode();
      result = prime * result + duration;
      result = prime * result + frameControl.hashCode();
      result = prime * result + (htControl != null ? htControl.hashCode() : 0);
      result = prime * result + sequenceControl.hashCode();
      return result;
    }

    @Override
    public boolean equals(Object obj) {
      if (this == obj) return true;
      if (getClass() != obj.getClass()) return false;
      Dot11ManagementHeader other = (Dot11ManagementHeader) obj;
      if (!address1.equals(other.address1)) return false;
      if (!address2.equals(other.address2)) return false;
      if (!address3.equals(other.address3)) return false;
      if (duration != other.duration) return false;
      if (!frameControl.equals(other.frameControl)) return false;
      if (htControl == null) {
        if (other.htControl != null) {
          return false;
        }
      } else if (!htControl.equals(other.htControl)) return false;
      if (!sequenceControl.equals(other.sequenceControl)) return false;
      return true;
    }
  }
}
