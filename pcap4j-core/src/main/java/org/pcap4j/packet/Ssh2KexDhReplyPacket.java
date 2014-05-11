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
public final class Ssh2KexDhReplyPacket extends AbstractPacket {

  /**
   *
   */
  private static final long serialVersionUID = 6507040765944406940L;

  private final Ssh2KexDhReplyHeader header;

  /**
   *
   * @param rawData
   * @return a new Ssh2KexDhReplyPacket object.
   * @throws IllegalRawDataException
   */
  public static Ssh2KexDhReplyPacket newPacket(
    byte[] rawData
  ) throws IllegalRawDataException {
    return new Ssh2KexDhReplyPacket(rawData);
  }

  private Ssh2KexDhReplyPacket(byte[] rawData) throws IllegalRawDataException {
    if (rawData == null) {
      throw new NullPointerException();
    }
    this.header = new Ssh2KexDhReplyHeader(rawData);
  }

  private Ssh2KexDhReplyPacket(Builder builder) {
    if (
         builder == null
      || builder.k_s == null
      || builder.f == null
      || builder.signatureOfH == null
    ) {
      StringBuilder sb = new StringBuilder();
      sb.append("builder: ").append(builder)
        .append(" builder.k_s: ").append(builder.k_s)
        .append(" builder.f: ").append(builder.f)
        .append(" builder.signatureOfH: ").append(builder.signatureOfH);
      throw new NullPointerException(sb.toString());
    }

    this.header = new Ssh2KexDhReplyHeader(builder);
  }

  @Override
  public Ssh2KexDhReplyHeader getHeader() {
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

    private Ssh2String k_s;
    private Ssh2MpInt f;
    private Ssh2String signatureOfH;

    /**
     *
     */
    public Builder() {}

    private Builder(Ssh2KexDhReplyPacket packet) {
      this.k_s = packet.header.k_s;
      this.f = packet.header.f;
      this.signatureOfH = packet.header.signatureOfH;
    }

    /**
     *
     * @param k_s
     * @return this Builder object for method chaining.
     */
    public Builder k_s(Ssh2String k_s) {
      this.k_s = k_s;
      return this;
    }

    /**
     *
     * @param f
     * @return this Builder object for method chaining.
     */
    public Builder f(Ssh2MpInt f) {
      this.f = f;
      return this;
    }

    /**
     *
     * @param signatureOfH
     * @return this Builder object for method chaining.
     */
    public Builder signatureOfH(Ssh2String signatureOfH) {
      this.signatureOfH = signatureOfH;
      return this;
    }

    @Override
    public Ssh2KexDhReplyPacket build() {
      return new Ssh2KexDhReplyPacket(this);
    }

  }

  /**
   *
   * @author Kaito Yamada
   * @version pcap4j 1.0.1
   */
  public static final class Ssh2KexDhReplyHeader extends AbstractHeader {

    /*
     * http://tools.ietf.org/html/rfc4253
     *
     * byte      SSH_MSG_KEXDH_REPLY
     * string    server public host key and certificates (K_S)
     * mpint     f
     * string    signature of H
     */

    /**
     *
     */
    private static final long serialVersionUID = 4008432145902117221L;

    private final Ssh2MessageNumber messageNumber = Ssh2MessageNumber.SSH_MSG_KEXDH_REPLY;
    private final Ssh2String k_s;
    private final Ssh2MpInt f;
    private final Ssh2String signatureOfH;

    private Ssh2KexDhReplyHeader(byte[] rawData) throws IllegalRawDataException {
      if (rawData.length < 13) {
        StringBuilder sb = new StringBuilder(80);
        sb.append("The data is too short to build an SSH2 KEX DH reply header. data: ")
          .append(new String(rawData));
        throw new IllegalRawDataException(sb.toString());
      }

      if (!Ssh2MessageNumber.getInstance(rawData[0]).equals(Ssh2MessageNumber.SSH_MSG_KEXDH_REPLY)) {
        StringBuilder sb = new StringBuilder(120);
        sb.append("The data is not an SSH2 KEX DH reply message. data: ")
          .append(new String(rawData));
        throw new IllegalRawDataException(sb.toString());
      }

      int offset = 1;
      this.k_s = new Ssh2String(ByteArrays.getSubArray(rawData, offset));
      offset += k_s.length();
      this.f = new Ssh2MpInt(ByteArrays.getSubArray(rawData, offset));
      offset += f.length();
      this.signatureOfH = new Ssh2String(ByteArrays.getSubArray(rawData, offset));
    }

    private Ssh2KexDhReplyHeader(Builder builder) {
      this.k_s = builder.k_s;
      this.f = builder.f;
      this.signatureOfH = builder.signatureOfH;
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
     * @return K_S
     */
    public Ssh2String getK_s() {
      return k_s;
    }

    /**
     *
     * @return f
     */
    public Ssh2MpInt getF() {
      return f;
    }

    /**
     *
     * @return signature of H
     */
    public Ssh2String getSignatureOfH() {
      return signatureOfH;
    }

    @Override
    protected List<byte[]> getRawFields() {
      List<byte[]> rawFields = new ArrayList<byte[]>();
      rawFields.add(new byte[] {messageNumber.value()});
      rawFields.add(k_s.getRawData());
      rawFields.add(f.getRawData());
      rawFields.add(signatureOfH.getRawData());
      return rawFields;
    }

    @Override
    protected int calcLength() { return getRawData().length; }

    @Override
    protected String buildString() {
      StringBuilder sb = new StringBuilder();
      String ls = System.getProperty("line.separator");

      sb.append("[SSH2 KEX DH reply Header (")
        .append(length())
        .append(" bytes)]")
        .append(ls);
      sb.append("  Message Number: ")
        .append(messageNumber)
        .append(ls);
      sb.append("  K_S: ")
        .append(k_s)
        .append(ls);
      sb.append("  f: ")
        .append(f)
        .append(ls);
      sb.append("  signature of H: ")
        .append(signatureOfH)
        .append(ls);

      return sb.toString();
    }

  }

}
