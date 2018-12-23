/*_##########################################################################
  _##
  _##  Copyright (C) 2016  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import static org.pcap4j.util.ByteArrays.*;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import org.pcap4j.packet.factory.PacketFactories;
import org.pcap4j.packet.namednumber.LlcNumber;
import org.pcap4j.util.ByteArrays;

/**
 * LLC (Logical Link Control) Packet
 *
 * @see <a href="http://standards.ieee.org/about/get/802/802.2.html">IEEE 802.2</a>
 * @author Kaito Yamada
 * @since pcap4j 1.6.5
 */
public final class LlcPacket extends AbstractPacket {

  /** */
  private static final long serialVersionUID = -4394376906462242290L;

  private final LlcHeader header;
  private final Packet payload;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new LlcPacket object.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static LlcPacket newPacket(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    return new LlcPacket(rawData, offset, length);
  }

  private LlcPacket(byte[] rawData, int offset, int length) throws IllegalRawDataException {
    this.header = new LlcHeader(rawData, offset, length);

    int payloadLength = length - header.length();
    if (payloadLength > 0) {
      this.payload =
          PacketFactories.getFactory(Packet.class, LlcNumber.class)
              .newInstance(rawData, offset + header.length(), payloadLength, header.getDsap());
    } else {
      this.payload = null;
    }
  }

  private LlcPacket(Builder builder) {
    if (builder == null
        || builder.dsap == null
        || builder.ssap == null
        || builder.control == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("builder: ")
          .append(builder)
          .append(" builder.dsap: ")
          .append(builder.dsap)
          .append(" builder.ssap: ")
          .append(builder.ssap)
          .append(" builder.control: ")
          .append(builder.control);
      throw new NullPointerException(sb.toString());
    }

    this.payload = builder.payloadBuilder != null ? builder.payloadBuilder.build() : null;
    this.header = new LlcHeader(builder);
  }

  @Override
  public LlcHeader getHeader() {
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

  /**
   * @author Kaito Yamada
   * @since pcap4j 1.6.5
   */
  public static final class Builder extends AbstractBuilder {

    private LlcNumber dsap;
    private LlcNumber ssap;
    private LlcControl control;
    private Packet.Builder payloadBuilder;

    /** */
    public Builder() {}

    private Builder(LlcPacket packet) {
      this.dsap = packet.header.dsap;
      this.ssap = packet.header.ssap;
      this.control = packet.header.control;
      this.payloadBuilder = packet.payload != null ? packet.payload.getBuilder() : null;
    }

    /**
     * @param dsap dsap
     * @return this Builder object for method chaining.
     */
    public Builder dsap(LlcNumber dsap) {
      this.dsap = dsap;
      return this;
    }

    /**
     * @param ssap ssap
     * @return this Builder object for method chaining.
     */
    public Builder ssap(LlcNumber ssap) {
      this.ssap = ssap;
      return this;
    }

    /**
     * @see LlcControlInformation
     * @see LlcControlSupervisory
     * @see LlcControlUnnumbered
     * @param control control
     * @return this Builder object for method chaining.
     */
    public Builder control(LlcControl control) {
      this.control = control;
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
    public LlcPacket build() {
      return new LlcPacket(this);
    }
  }

  /**
   * LLC (Logical Link Control) Header
   *
   * <pre>{@code
   *   0                                                          15
   * +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
   * |           DSAP ( 8bits)       |       SSAP (8 bits)           |
   * +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
   * |                    Control (8 or 16 bits)                     |
   * +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
   * }</pre>
   *
   * @see <a href="http://standards.ieee.org/about/get/802/802.2.html">IEEE 802.2</a>
   * @author Kaito Yamada
   * @since pcap4j 1.6.5
   */
  public static final class LlcHeader extends AbstractHeader {

    /** */
    private static final long serialVersionUID = -6228127495653535606L;

    private static final int DSAP_OFFSET = 0;
    private static final int DSAP_SIZE = BYTE_SIZE_IN_BYTES;
    private static final int SSAP_OFFSET = DSAP_OFFSET + DSAP_SIZE;
    private static final int SSAP_SIZE = BYTE_SIZE_IN_BYTES;
    private static final int CONTROL_OFFSET = SSAP_OFFSET + SSAP_SIZE;

    private final LlcNumber dsap;
    private final LlcNumber ssap;
    private final LlcControl control;

    private LlcHeader(byte[] rawData, int offset, int length) throws IllegalRawDataException {
      if (length < CONTROL_OFFSET + 1) {
        StringBuilder sb = new StringBuilder(200);
        sb.append("The data is too short to build an LLC header(")
            .append(CONTROL_OFFSET + 1)
            .append(" bytes). data: ")
            .append(ByteArrays.toHexString(rawData, " "))
            .append(", offset: ")
            .append(offset)
            .append(", length: ")
            .append(length);
        throw new IllegalRawDataException(sb.toString());
      }

      this.dsap = LlcNumber.getInstance(rawData[DSAP_OFFSET + offset]);
      this.ssap = LlcNumber.getInstance(rawData[SSAP_OFFSET + offset]);

      byte ctrl = rawData[CONTROL_OFFSET + offset];
      if ((ctrl & 0x03) == 0x03) {
        this.control = LlcControlUnnumbered.newInstance(ctrl);
      } else {
        if (length < CONTROL_OFFSET + 2) {
          StringBuilder sb = new StringBuilder(200);
          sb.append("The data is too short to build an LLC header(")
              .append(CONTROL_OFFSET + 2)
              .append(" bytes). data: ")
              .append(ByteArrays.toHexString(rawData, " "))
              .append(", offset: ")
              .append(offset)
              .append(", length: ")
              .append(length);
          throw new IllegalRawDataException(sb.toString());
        }

        if ((ctrl & 0x03) == 0x01) {
          this.control =
              LlcControlSupervisory.newInstance(
                  ByteArrays.getShort(rawData, CONTROL_OFFSET + offset));
        } else {
          this.control =
              LlcControlInformation.newInstance(
                  ByteArrays.getShort(rawData, CONTROL_OFFSET + offset));
        }
      }
    }

    private LlcHeader(Builder builder) {
      this.dsap = builder.dsap;
      this.ssap = builder.ssap;
      this.control = builder.control;
    }

    /** @return dsap */
    public LlcNumber getDsap() {
      return dsap;
    }

    /** @return ssap */
    public LlcNumber getSsap() {
      return ssap;
    }

    /**
     * @return an instance of {@link LlcControlInformation}, {@link LlcControlSupervisory} or {@link
     *     LlcControlUnnumbered}.
     */
    public LlcControl getControl() {
      return control;
    }

    @Override
    protected List<byte[]> getRawFields() {
      List<byte[]> rawFields = new ArrayList<byte[]>();
      rawFields.add(ByteArrays.toByteArray(dsap.value()));
      rawFields.add(ByteArrays.toByteArray(ssap.value()));
      rawFields.add(control.getRawData());
      return rawFields;
    }

    @Override
    protected int calcLength() {
      return 2 + control.length();
    }

    @Override
    protected String buildString() {
      StringBuilder sb = new StringBuilder();
      String ls = System.getProperty("line.separator");

      sb.append("[Logical Link Control header (").append(length()).append(" bytes)]").append(ls);
      sb.append("  DSAP: ").append(dsap).append(ls);
      sb.append("  SSAP: ").append(ssap).append(ls);
      sb.append("  Control: ").append(control).append(ls);

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

      LlcHeader other = (LlcHeader) obj;
      return dsap.equals(other.dsap) && control.equals(other.control) && ssap.equals(other.ssap);
    }

    @Override
    protected int calcHashCode() {
      int result = 17;
      result = 31 * result + dsap.hashCode();
      result = 31 * result + ssap.hashCode();
      result = 31 * result + control.hashCode();
      return result;
    }
  }

  /**
   * The interface representing the Control field of an LLC header.
   *
   * @author Kaito Yamada
   * @since pcap4j 1.6.5
   */
  public interface LlcControl extends Serializable {

    /** @return length */
    public int length();

    /** @return raw data */
    public byte[] getRawData();
  }
}
