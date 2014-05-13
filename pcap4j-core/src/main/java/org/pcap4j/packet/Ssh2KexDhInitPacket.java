/*_##########################################################################
  _##
  _##  Copyright (C) 2014  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import java.util.ArrayList;
import java.util.List;
import org.pcap4j.packet.namednumber.Ssh2MessageNumber;
import org.pcap4j.util.ByteArrays;

/**
 * @author Kaito Yamada
 * @since pcap4j 1.0.1
 */
public final class Ssh2KexDhInitPacket extends AbstractPacket {

  /**
   *
   */
  private static final long serialVersionUID = -2349107611011582180L;

  private final Ssh2KexDhInitHeader header;

  /**
   *
   * @param rawData
   * @return a new Ssh2KexDhInitPacket object.
   * @throws IllegalRawDataException
   * @throws NullPointerException if the rawData argument is null.
   * @throws IllegalArgumentException if the rawData argument is empty.
   */
  public static Ssh2KexDhInitPacket newPacket(
    byte[] rawData
  ) throws IllegalRawDataException {
    if (rawData == null) {
      throw new NullPointerException("rawData must not be null.");
    }
    if (rawData.length == 0) {
      throw new IllegalArgumentException("rawData is empty.");
    }
    return new Ssh2KexDhInitPacket(rawData);
  }

  private Ssh2KexDhInitPacket(byte[] rawData) throws IllegalRawDataException {
    this.header = new Ssh2KexDhInitHeader(rawData);
  }

  private Ssh2KexDhInitPacket(Builder builder) {
    if (
         builder == null
      || builder.e == null
    ) {
      StringBuilder sb = new StringBuilder();
      sb.append("builder: ").append(builder)
        .append(" builder.e: ").append(builder.e);
      throw new NullPointerException(sb.toString());
    }

    this.header = new Ssh2KexDhInitHeader(builder);
  }

  @Override
  public Ssh2KexDhInitHeader getHeader() {
    return header;
  }

  @Override
  public Builder getBuilder() {
    return new Builder(this);
  }

  /**
   *
   * @author Kaito Yamada
   * @since pcap4j 1.0.1
   */
  public static final class Builder extends AbstractBuilder {

    private Ssh2MpInt e;

    /**
     *
     */
    public Builder() {}

    private Builder(Ssh2KexDhInitPacket packet) {
      this.e = packet.header.e;
    }

    /**
     *
     * @param e
     * @return this Builder object for method chaining.
     */
    public Builder e(Ssh2MpInt e) {
      this.e = e;
      return this;
    }

    @Override
    public Ssh2KexDhInitPacket build() {
      return new Ssh2KexDhInitPacket(this);
    }

  }

  /**
   *
   * @author Kaito Yamada
   * @version pcap4j 1.0.1
   */
  public static final class Ssh2KexDhInitHeader extends AbstractHeader {

    /*
     * http://tools.ietf.org/html/rfc4253
     *
     * byte      SSH_MSG_KEXDH_INIT
     * mpint     e
     */

    /**
     *
     */
    private static final long serialVersionUID = 4008432145902117221L;

    private final Ssh2MessageNumber messageNumber = Ssh2MessageNumber.SSH_MSG_KEXDH_INIT;
    private final Ssh2MpInt e;

    private Ssh2KexDhInitHeader(byte[] rawData) throws IllegalRawDataException {
      if (rawData.length < 5) {
        StringBuilder sb = new StringBuilder(80);
        sb.append("The data is too short to build an SSH2 KEX DH init header. data: ")
          .append(new String(rawData));
        throw new IllegalRawDataException(sb.toString());
      }

      if (!Ssh2MessageNumber.getInstance(rawData[0]).equals(Ssh2MessageNumber.SSH_MSG_KEXDH_INIT)) {
        StringBuilder sb = new StringBuilder(120);
        sb.append("The data is not an SSH2 KEX DH init message. data: ")
          .append(new String(rawData));
        throw new IllegalRawDataException(sb.toString());
      }

      this.e = new Ssh2MpInt(ByteArrays.getSubArray(rawData, 1));
    }

    private Ssh2KexDhInitHeader(Builder builder) {
      this.e = builder.e;
    }

    /**
     *
     * @return messageNumber
     */
    public Ssh2MessageNumber getMessageNumber() {
      return messageNumber;
    }

    /**
     *
     * @return e
     */
    public Ssh2MpInt getE() {
      return e;
    }

    @Override
    protected List<byte[]> getRawFields() {
      List<byte[]> rawFields = new ArrayList<byte[]>();
      rawFields.add(new byte[] {messageNumber.value()});
      rawFields.add(e.getRawData());
      return rawFields;
    }

    @Override
    protected int calcLength() { return e.length() + 1; }

    @Override
    protected String buildString() {
      StringBuilder sb = new StringBuilder();
      String ls = System.getProperty("line.separator");

      sb.append("[SSH2 KEX DH init Header (")
        .append(length())
        .append(" bytes)]")
        .append(ls);
      sb.append("  Message Number: ")
        .append(messageNumber)
        .append(ls);
      sb.append("  e: ")
        .append(e)
        .append(ls);

      return sb.toString();
    }

  }

}
