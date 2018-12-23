/*_##########################################################################
  _##
  _##  Copyright (C) 2014  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import java.io.ObjectStreamException;
import java.util.ArrayList;
import java.util.List;
import org.pcap4j.packet.namednumber.Ssh2MessageNumber;
import org.pcap4j.util.ByteArrays;

/**
 * @author Kaito Yamada
 * @since pcap4j 1.0.1
 */
public final class Ssh2NewKeysPacket extends AbstractPacket {

  /** */
  private static final long serialVersionUID = -4355029035065046101L;

  private static final Ssh2NewKeysPacket INSTANCE = new Ssh2NewKeysPacket();

  private final Ssh2NewKeysHeader header = Ssh2NewKeysHeader.getInstance();

  private Ssh2NewKeysPacket() {}

  /** @return the singleton instance of Ssh2NewKeysPacket. */
  public static Ssh2NewKeysPacket getInstance() {
    return INSTANCE;
  }

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return the singleton instance of Ssh2NewKeysPacket.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static Ssh2NewKeysPacket newPacket(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    Ssh2NewKeysHeader.checkRawData(rawData, offset, length);
    return INSTANCE;
  }

  @Override
  public Ssh2NewKeysHeader getHeader() {
    return header;
  }

  @Override
  public Builder getBuilder() {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean equals(Object obj) {
    return this.equals(obj);
  }

  @Override
  protected int calcHashCode() {
    return this.hashCode();
  }

  // Override deserializer to keep singleton
  @SuppressWarnings("static-method")
  private Object readResolve() throws ObjectStreamException {
    return INSTANCE;
  }

  /**
   * @author Kaito Yamada
   * @version pcap4j 1.0.1
   */
  public static final class Ssh2NewKeysHeader extends AbstractHeader {

    /*
     * http://tools.ietf.org/html/rfc4253
     *
     * byte      SSH_MSG_NEWKEYS
     */

    /** */
    private static final long serialVersionUID = -6964593795610286838L;

    private static final Ssh2NewKeysHeader INSTANCE = new Ssh2NewKeysHeader();

    private final Ssh2MessageNumber messageNumber = Ssh2MessageNumber.SSH_MSG_NEWKEYS;

    private Ssh2NewKeysHeader() {}

    private static void checkRawData(byte[] rawData, int offset, int length)
        throws IllegalRawDataException {
      if (length < 1) {
        StringBuilder sb = new StringBuilder(120);
        sb.append("The data is too short to build an SSH2 New Keys header. data: ")
            .append(new String(rawData))
            .append(", offset: ")
            .append(offset)
            .append(", length: ")
            .append(length);
        throw new IllegalRawDataException(sb.toString());
      }

      if (!Ssh2MessageNumber.getInstance(rawData[offset])
          .equals(Ssh2MessageNumber.SSH_MSG_KEXINIT)) {
        StringBuilder sb = new StringBuilder(120);
        sb.append("The data is not an SSH2 New Keys message. data: ")
            .append(new String(rawData))
            .append(", offset: ")
            .append(offset)
            .append(", length: ")
            .append(length);
        throw new IllegalRawDataException(sb.toString());
      }
    }

    private static Ssh2NewKeysHeader getInstance() {
      return INSTANCE;
    }

    /** @return messageNumber */
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
    public int length() {
      return 1;
    }

    @Override
    protected String buildString() {
      StringBuilder sb = new StringBuilder();
      String ls = System.getProperty("line.separator");

      sb.append("[SSH2 New Keys Header (").append(length()).append(" bytes)]").append(ls);
      sb.append("  Message Number: ").append(messageNumber).append(ls);

      return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
      return this.equals(obj);
    }

    @Override
    protected int calcHashCode() {
      return this.hashCode();
    }

    // Override deserializer to keep singleton
    @SuppressWarnings("static-method")
    private Object readResolve() throws ObjectStreamException {
      return INSTANCE;
    }
  }
}
