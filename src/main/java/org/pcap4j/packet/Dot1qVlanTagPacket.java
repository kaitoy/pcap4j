/*_##########################################################################
  _##
  _##  Copyright (C) 2012  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import static org.pcap4j.util.ByteArrays.SHORT_SIZE_IN_BYTES;
import java.util.ArrayList;
import java.util.List;
import org.pcap4j.packet.factory.PacketFactories;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.util.ByteArrays;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.11
 */
public final class Dot1qVlanTagPacket extends AbstractPacket {

  /**
   *
   */
  private static final long serialVersionUID = 1522789079803339400L;

  private final Dot1qVlanTagHeader header;
  private final Packet payload;

  /**
   *
   * @param rawData
   * @return
   * @throws PacketException
   */
  public static Dot1qVlanTagPacket newPacket(byte[] rawData){
    return new Dot1qVlanTagPacket(rawData);
  }

  private Dot1qVlanTagPacket(byte[] rawData) {
    this.header = new Dot1qVlanTagHeader(rawData);

    byte[] rawPayload
      = ByteArrays.getSubArray(
          rawData,
          header.length(),
          rawData.length - header.length()
        );

    this.payload
      = PacketFactories.getFactory(EtherType.class)
          .newPacket(rawPayload, header.getType());
  }

  private Dot1qVlanTagPacket(Builder builder) {
    if (
         builder == null
      || builder.type == null
      || builder.payloadBuilder == null
    ) {
      StringBuilder sb = new StringBuilder();
      sb.append("builder: ").append(builder)
        .append(" builder.type: ").append(builder.type)
        .append(" builder.payloadBuilder: ").append(builder.payloadBuilder);
      throw new NullPointerException(sb.toString());
    }

    this.payload = builder.payloadBuilder.build();
    this.header = new Dot1qVlanTagHeader(builder);
  }

  @Override
  public Dot1qVlanTagHeader getHeader() {
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
   * @since pcap4j 0.9.11
   */
  public static final class Builder extends AbstractBuilder {

    private byte priority;
    private boolean cfi;
    private short vid;
    private EtherType type;
    private Packet.Builder payloadBuilder;

    /**
     *
     */
    public Builder() {}

    private Builder(Dot1qVlanTagPacket packet) {
      this.priority = packet.header.priority;
      this.cfi = packet.header.cfi;
      this.vid = packet.header.vid;
      this.type = packet.header.type;
      this.payloadBuilder = packet.payload.getBuilder();
    }

    /**
     *
     * @param priority
     * @return
     */
    public Builder priority(byte priority) {
      this.priority = priority;
      return this;
    }

    /**
     * true: 1, false: 0
     *
     * @param cfi
     * @return
     */
    public Builder cfi(boolean cfi) {
      this.cfi = cfi;
      return this;
    }

    /**
     *
     * @param vid
     * @return
     */
    public Builder vid(short vid) {
      this.vid = vid;
      return this;
    }

    /**
     *
     * @param type
     * @return
     */
    public Builder type(EtherType type) {
      this.type = type;
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
    public Dot1qVlanTagPacket build() {
      return new Dot1qVlanTagPacket(this);
    }

  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 0.9.11
   */
  public static final class Dot1qVlanTagHeader extends AbstractHeader {

    /*
     *   0                                                          15
     * +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
     * |Priority   |CFI|                   VID                         |
     * +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
     * |                            Type                               |
     * +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
     */

    /**
     *
     */
    private static final long serialVersionUID = 7130569411806479522L;

    private static final int PRIORITY_AND_CFI_AND_VID_OFFSET
      = 0;
    private static final int PRIORITY_AND_CFI_AND_VID_SIZE
      = SHORT_SIZE_IN_BYTES;
    private static final int TYPE_OFFSET
      = PRIORITY_AND_CFI_AND_VID_OFFSET + PRIORITY_AND_CFI_AND_VID_SIZE;
    private static final int TYPE_SIZE
      = SHORT_SIZE_IN_BYTES;
    private static final int DOT1Q_TAG_HEADER_SIZE
      = TYPE_OFFSET + TYPE_SIZE;

    private final byte priority;
    private final boolean cfi;
    private final short vid;
    private final EtherType type;

    private Dot1qVlanTagHeader(byte[] rawData) {
      if (rawData.length < DOT1Q_TAG_HEADER_SIZE) {
        StringBuilder sb = new StringBuilder(110);
        sb.append("The data is too short to build an IEEE802.1Q Tag header(")
          .append(DOT1Q_TAG_HEADER_SIZE)
          .append(" bytes). data: ")
          .append(ByteArrays.toHexString(rawData, " "));
        throw new IllegalRawDataException(sb.toString());
      }

      short priorityAndCfiAndVid
        = ByteArrays.getShort(rawData, PRIORITY_AND_CFI_AND_VID_OFFSET);

      this.priority = (byte)(priorityAndCfiAndVid >>> 13);
      this.cfi = ((priorityAndCfiAndVid & 0x1000) >> 12) == 1;
      this.vid = (byte)(priorityAndCfiAndVid & 0x0FFF);
      this.type
        = EtherType.getInstance(ByteArrays.getShort(rawData, TYPE_OFFSET));
    }

    private Dot1qVlanTagHeader(Builder builder) {
      if ((builder.priority & 0xF8) != 0) {
        throw new IllegalArgumentException(
                "invalid priority: " + builder.priority
              );
      }
      if ((builder.vid & 0xF000) != 0) {
        throw new IllegalArgumentException("invalid vid: " + builder.vid);
      }

      this.priority = builder.priority;
      this.cfi = builder.cfi;
      this.vid = builder.vid;
      this.type = builder.type;
    }

    /**
     *
     * @return
     */
    public byte getPriority() {
      return priority;
    }

    /**
     * true: 1, false: 0
     *
     * @return
     */
    public boolean getCfi() {
      return cfi;
    }

    /**
     *
     * @return
     */
    public short getVid() {
      return vid;
    }

    /**
     *
     * @return
     */
    public int getVidAsInt() {
      return 0x0FFF & vid;
    }

    /**
     *
     * @return
     */
    public EtherType getType() {
      return type;
    }

    @Override
    protected List<byte[]> getRawFields() {
      List<byte[]> rawFields = new ArrayList<byte[]>();
      rawFields.add(
        ByteArrays.toByteArray(
          (short)((priority << 13) | ((cfi ? 1 : 0) << 12) | vid)
        )
      );
      rawFields.add(ByteArrays.toByteArray(type.value()));
      return rawFields;
    }

    @Override
    public int length() {
      return DOT1Q_TAG_HEADER_SIZE;
    }

    @Override
    protected String buildString() {
      StringBuilder sb = new StringBuilder();
      String ls = System.getProperty("line.separator");

      sb.append("[IEEE802.1Q Tag header (")
        .append(length())
        .append(" bytes)]")
        .append(ls);
      sb.append("  Priority: ")
        .append(priority)
        .append(ls);
      sb.append("  CFI: ")
        .append(cfi ? 1 : 0)
        .append(ls);
      sb.append("  VID: ")
        .append(getVidAsInt())
        .append(ls);
      sb.append("  Type: ")
        .append(type)
        .append(ls);

      return sb.toString();
    }

  }

}
