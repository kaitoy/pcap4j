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

/**
 * @author Kaito Yamada
 * @since pcap4j 1.0.1
 */
public final class Ssh2NewKeysPacket extends AbstractPacket {

  /**
   *
   */
  private static final long serialVersionUID = -4355029035065046101L;

  private final Ssh2NewKeysHeader header;

  /**
   *
   * @param rawData
   * @return a new Ssh2NewKeysPacket object.
   * @throws IllegalRawDataException
   * @throws NullPointerException if the rawData argument is null.
   * @throws IllegalArgumentException if the rawData argument is empty.
   */
  public static Ssh2NewKeysPacket newPacket(byte[] rawData) throws IllegalRawDataException {
    if (rawData == null) {
      throw new NullPointerException("rawData must not be null.");
    }
    if (rawData.length == 0) {
      throw new IllegalArgumentException("rawData is empty.");
    }
    return new Ssh2NewKeysPacket(rawData);
  }

  private Ssh2NewKeysPacket(byte[] rawData) throws IllegalRawDataException {
    this.header = new Ssh2NewKeysHeader(rawData);
  }

  private Ssh2NewKeysPacket(Builder builder) {
    if (builder == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("builder: ").append(builder);
      throw new NullPointerException(sb.toString());
    }

    this.header = new Ssh2NewKeysHeader(builder);
  }

  @Override
  public Ssh2NewKeysHeader getHeader() {
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

    /**
     *
     */
    public Builder() {}

    private Builder(Ssh2NewKeysPacket packet) {
    }

    @Override
    public Ssh2NewKeysPacket build() {
      return new Ssh2NewKeysPacket(this);
    }

  }

  /**
   *
   * @author Kaito Yamada
   * @version pcap4j 1.0.1
   */
  public static final class Ssh2NewKeysHeader extends AbstractHeader {

    /*
     * http://tools.ietf.org/html/rfc4253
     *
     * byte      SSH_MSG_NEWKEYS
     */

    /**
     *
     */
    private static final long serialVersionUID = -6964593795610286838L;

    private final Ssh2MessageNumber messageNumber = Ssh2MessageNumber.SSH_MSG_NEWKEYS;

    private Ssh2NewKeysHeader(byte[] rawData) throws IllegalRawDataException {
      if (rawData.length < 1) {
        StringBuilder sb = new StringBuilder(120);
        sb.append("The data is too short to build an SSH2 New Keys header. data: ")
          .append(new String(rawData));
        throw new IllegalRawDataException(sb.toString());
      }

      if (!Ssh2MessageNumber.getInstance(rawData[0]).equals(Ssh2MessageNumber.SSH_MSG_KEXINIT)) {
        StringBuilder sb = new StringBuilder(120);
        sb.append("The data is not an SSH2 New Keys message. data: ")
          .append(new String(rawData));
        throw new IllegalRawDataException(sb.toString());
      }
    }

    private Ssh2NewKeysHeader(Builder builder) {
    }

    /**
     *
     * @return messageNumber
     */
    public Ssh2MessageNumber getMessageNumber() {
      return messageNumber;
    }

    @Override
    protected List<byte[]> getRawFields() {
      List<byte[]> rawFields = new ArrayList<byte[]>();
      rawFields.add(new byte[] {messageNumber.value()});
      return rawFields;
    }

    @Override
    public int length() { return 1; }

    @Override
    protected String buildString() {
      StringBuilder sb = new StringBuilder();
      String ls = System.getProperty("line.separator");

      sb.append("[SSH2 New Keys Header (")
        .append(length())
        .append(" bytes)]")
        .append(ls);
      sb.append("  Message Number: ")
        .append(messageNumber)
        .append(ls);

      return sb.toString();
    }

  }

}
