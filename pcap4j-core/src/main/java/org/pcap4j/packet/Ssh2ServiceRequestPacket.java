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
public final class Ssh2ServiceRequestPacket extends AbstractPacket {

  /**
   *
   */
  private static final long serialVersionUID = 6862963187041604290L;

  private final Ssh2ServiceRequestHeader header;

  /**
   *
   * @param rawData
   * @return a new Ssh2ServiceRequestPacket object.
   * @throws IllegalRawDataException
   * @throws NullPointerException if the rawData argument is null.
   * @throws IllegalArgumentException if the rawData argument is empty.
   */
  public static Ssh2ServiceRequestPacket newPacket(
    byte[] rawData
  ) throws IllegalRawDataException {
    if (rawData == null) {
      throw new NullPointerException("rawData must not be null.");
    }
    if (rawData.length == 0) {
      throw new IllegalArgumentException("rawData is empty.");
    }
    return new Ssh2ServiceRequestPacket(rawData);
  }

  private Ssh2ServiceRequestPacket(byte[] rawData) throws IllegalRawDataException {
    this.header = new Ssh2ServiceRequestHeader(rawData);
  }

  private Ssh2ServiceRequestPacket(Builder builder) {
    if (
         builder == null
      || builder.serviceName == null
    ) {
      StringBuilder sb = new StringBuilder();
      sb.append("builder: ").append(builder)
        .append(" builder.serviceName: ").append(builder.serviceName);
      throw new NullPointerException(sb.toString());
    }

    this.header = new Ssh2ServiceRequestHeader(builder);
  }

  @Override
  public Ssh2ServiceRequestHeader getHeader() {
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

    private Ssh2String serviceName;

    /**
     *
     */
    public Builder() {}

    private Builder(Ssh2ServiceRequestPacket packet) {
      this.serviceName = packet.header.serviceName;
    }

    /**
     *
     * @param serviceName
     * @return this Builder object for method chaining.
     */
    public Builder serviceName(Ssh2String serviceName) {
      this.serviceName = serviceName;
      return this;
    }

    @Override
    public Ssh2ServiceRequestPacket build() {
      return new Ssh2ServiceRequestPacket(this);
    }

  }

  /**
   *
   * @author Kaito Yamada
   * @version pcap4j 1.0.1
   */
  public static final class Ssh2ServiceRequestHeader extends AbstractHeader {

    /*
     * http://tools.ietf.org/html/rfc4253
     *
     * byte      SSH_MSG_SERVICE_REQUEST
     * string    service name
     */

    /**
     *
     */
    private static final long serialVersionUID = 8957656530972381650L;

    private final Ssh2MessageNumber messageNumber = Ssh2MessageNumber.SSH_MSG_SERVICE_REQUEST;
    private final Ssh2String serviceName;

    private Ssh2ServiceRequestHeader(byte[] rawData) throws IllegalRawDataException {
      if (rawData.length < 5) {
        StringBuilder sb = new StringBuilder(80);
        sb.append("The data is too short to build an SSH2 Service Request header. data: ")
          .append(new String(rawData));
        throw new IllegalRawDataException(sb.toString());
      }

      if (!Ssh2MessageNumber.getInstance(rawData[0]).equals(Ssh2MessageNumber.SSH_MSG_SERVICE_REQUEST)) {
        StringBuilder sb = new StringBuilder(120);
        sb.append("The data is not an SSH2 Service Request message. data: ")
          .append(new String(rawData));
        throw new IllegalRawDataException(sb.toString());
      }

      this.serviceName = new Ssh2String(ByteArrays.getSubArray(rawData, 1));
    }

    private Ssh2ServiceRequestHeader(Builder builder) {
      this.serviceName = builder.serviceName;
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
     * @return serviceName
     */
    public Ssh2String getServiceName() {
      return serviceName;
    }

    @Override
    protected List<byte[]> getRawFields() {
      List<byte[]> rawFields = new ArrayList<byte[]>();
      rawFields.add(new byte[] {messageNumber.value()});
      rawFields.add(serviceName.getRawData());
      return rawFields;
    }

    @Override
    protected int calcLength() { return serviceName.length() + 1; }

    @Override
    protected String buildString() {
      StringBuilder sb = new StringBuilder();
      String ls = System.getProperty("line.separator");

      sb.append("[SSH2 Service Request Header (")
        .append(length())
        .append(" bytes)]")
        .append(ls);
      sb.append("  Message Number: ")
        .append(messageNumber)
        .append(ls);
      sb.append("  service name: ")
        .append(serviceName)
        .append(ls);

      return sb.toString();
    }

  }

}
