/*_##########################################################################
  _##
  _##  Copyright (C) 2014  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.pcap4j.packet.namednumber.Ssh2MessageNumber;
import org.pcap4j.util.ByteArrays;

/**
 * @author Kaito Yamada
 * @since pcap4j 1.0.1
 */
public final class Ssh2KexInitPacket extends AbstractPacket {

  /** */
  private static final long serialVersionUID = -2424080361918022468L;

  private final Ssh2KexInitHeader header;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new Ssh2KexInitPacket object.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static Ssh2KexInitPacket newPacket(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    return new Ssh2KexInitPacket(rawData, offset, length);
  }

  private Ssh2KexInitPacket(byte[] rawData, int offset, int length) throws IllegalRawDataException {
    this.header = new Ssh2KexInitHeader(rawData, offset, length);
  }

  private Ssh2KexInitPacket(Builder builder) {
    if (builder == null
        || builder.cookie == null
        || builder.kexAlgorithms == null
        || builder.serverHostKeyAlgorithms == null
        || builder.encryptionAlgorithmsClientToServer == null
        || builder.encryptionAlgorithmsServerToClient == null
        || builder.macAlgorithmsClientToServer == null
        || builder.macAlgorithmsServerToClient == null
        || builder.compressionAlgorithmsClientToServer == null
        || builder.compressionAlgorithmsServerToClient == null
        || builder.languagesClientToServer == null
        || builder.languagesServerToClient == null
        || builder.firstKexPacketFollows == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("builder: ")
          .append(builder)
          .append(" builder.cookie: ")
          .append(builder.cookie)
          .append(" builder.kexAlgorithms: ")
          .append(builder.kexAlgorithms)
          .append(" builder.serverHostKeyAlgorithms: ")
          .append(builder.serverHostKeyAlgorithms)
          .append(" builder.encryptionAlgorithmsClientToServer: ")
          .append(builder.encryptionAlgorithmsClientToServer)
          .append(" builder.encryptionAlgorithmsServerToClient: ")
          .append(builder.encryptionAlgorithmsServerToClient)
          .append(" builder.macAlgorithmsClientToServer: ")
          .append(builder.macAlgorithmsClientToServer)
          .append(" builder.macAlgorithmsServerToClient: ")
          .append(builder.macAlgorithmsServerToClient)
          .append(" builder.compressionAlgorithmsClientToServer: ")
          .append(builder.compressionAlgorithmsClientToServer)
          .append(" builder.compressionAlgorithmsServerToClient: ")
          .append(builder.compressionAlgorithmsServerToClient)
          .append(" builder.languagesClientToServer: ")
          .append(builder.languagesClientToServer)
          .append(" builder.languagesServerToClient: ")
          .append(builder.languagesServerToClient)
          .append(" builder.firstKexPacketFollows: ")
          .append(builder.firstKexPacketFollows);
      throw new NullPointerException(sb.toString());
    }

    this.header = new Ssh2KexInitHeader(builder);
  }

  @Override
  public Ssh2KexInitHeader getHeader() {
    return header;
  }

  @Override
  public Builder getBuilder() {
    return new Builder(this);
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 1.0.1
   */
  public static final class Builder extends AbstractBuilder {

    private byte[] cookie;
    private Ssh2NameList kexAlgorithms;
    private Ssh2NameList serverHostKeyAlgorithms;
    private Ssh2NameList encryptionAlgorithmsClientToServer;
    private Ssh2NameList encryptionAlgorithmsServerToClient;
    private Ssh2NameList macAlgorithmsClientToServer;
    private Ssh2NameList macAlgorithmsServerToClient;
    private Ssh2NameList compressionAlgorithmsClientToServer;
    private Ssh2NameList compressionAlgorithmsServerToClient;
    private Ssh2NameList languagesClientToServer;
    private Ssh2NameList languagesServerToClient;
    private Ssh2Boolean firstKexPacketFollows;
    private int reserved;

    /** */
    public Builder() {}

    private Builder(Ssh2KexInitPacket packet) {
      this.cookie = packet.header.cookie;
      this.kexAlgorithms = packet.header.kexAlgorithms;
      this.serverHostKeyAlgorithms = packet.header.serverHostKeyAlgorithms;
      this.encryptionAlgorithmsClientToServer = packet.header.encryptionAlgorithmsClientToServer;
      this.encryptionAlgorithmsServerToClient = packet.header.encryptionAlgorithmsServerToClient;
      this.macAlgorithmsClientToServer = packet.header.macAlgorithmsClientToServer;
      this.macAlgorithmsServerToClient = packet.header.macAlgorithmsServerToClient;
      this.compressionAlgorithmsClientToServer = packet.header.compressionAlgorithmsClientToServer;
      this.compressionAlgorithmsServerToClient = packet.header.compressionAlgorithmsServerToClient;
      this.languagesClientToServer = packet.header.languagesClientToServer;
      this.languagesServerToClient = packet.header.languagesServerToClient;
      this.firstKexPacketFollows = packet.header.firstKexPacketFollows;
      this.reserved = packet.header.reserved;
    }

    /**
     * @param cookie cookie
     * @return this Builder object for method chaining.
     */
    public Builder cookie(byte[] cookie) {
      this.cookie = cookie;
      return this;
    }

    /**
     * @param kexAlgorithms kexAlgorithms
     * @return this Builder object for method chaining.
     */
    public Builder kexAlgorithms(Ssh2NameList kexAlgorithms) {
      this.kexAlgorithms = kexAlgorithms;
      return this;
    }

    /**
     * @param serverHostKeyAlgorithms serverHostKeyAlgorithms
     * @return this Builder object for method chaining.
     */
    public Builder serverHostKeyAlgorithms(Ssh2NameList serverHostKeyAlgorithms) {
      this.serverHostKeyAlgorithms = serverHostKeyAlgorithms;
      return this;
    }

    /**
     * @param encryptionAlgorithmsClientToServer encryptionAlgorithmsClientToServer
     * @return this Builder object for method chaining.
     */
    public Builder encryptionAlgorithmsClientToServer(
        Ssh2NameList encryptionAlgorithmsClientToServer) {
      this.encryptionAlgorithmsClientToServer = encryptionAlgorithmsClientToServer;
      return this;
    }

    /**
     * @param encryptionAlgorithmsServerToClient encryptionAlgorithmsServerToClient
     * @return this Builder object for method chaining.
     */
    public Builder encryptionAlgorithmsServerToClient(
        Ssh2NameList encryptionAlgorithmsServerToClient) {
      this.encryptionAlgorithmsServerToClient = encryptionAlgorithmsServerToClient;
      return this;
    }

    /**
     * @param macAlgorithmsClientToServer macAlgorithmsClientToServer
     * @return this Builder object for method chaining.
     */
    public Builder macAlgorithmsClientToServer(Ssh2NameList macAlgorithmsClientToServer) {
      this.macAlgorithmsClientToServer = macAlgorithmsClientToServer;
      return this;
    }

    /**
     * @param macAlgorithmsServerToClient macAlgorithmsServerToClient
     * @return this Builder object for method chaining.
     */
    public Builder macAlgorithmsServerToClient(Ssh2NameList macAlgorithmsServerToClient) {
      this.macAlgorithmsServerToClient = macAlgorithmsServerToClient;
      return this;
    }

    /**
     * @param compressionAlgorithmsClientToServer compressionAlgorithmsClientToServer
     * @return this Builder object for method chaining.
     */
    public Builder compressionAlgorithmsClientToServer(
        Ssh2NameList compressionAlgorithmsClientToServer) {
      this.compressionAlgorithmsClientToServer = compressionAlgorithmsClientToServer;
      return this;
    }

    /**
     * @param compressionAlgorithmsServerToClient compressionAlgorithmsServerToClient
     * @return this Builder object for method chaining.
     */
    public Builder compressionAlgorithmsServerToClient(
        Ssh2NameList compressionAlgorithmsServerToClient) {
      this.compressionAlgorithmsServerToClient = compressionAlgorithmsServerToClient;
      return this;
    }

    /**
     * @param languagesClientToServer languagesClientToServer
     * @return this Builder object for method chaining.
     */
    public Builder languagesClientToServer(Ssh2NameList languagesClientToServer) {
      this.languagesClientToServer = languagesClientToServer;
      return this;
    }

    /**
     * @param languagesServerToClient languagesServerToClient
     * @return this Builder object for method chaining.
     */
    public Builder languagesServerToClient(Ssh2NameList languagesServerToClient) {
      this.languagesServerToClient = languagesServerToClient;
      return this;
    }

    /**
     * @param firstKexPacketFollows firstKexPacketFollows
     * @return this Builder object for method chaining.
     */
    public Builder firstKexPacketFollows(Ssh2Boolean firstKexPacketFollows) {
      this.firstKexPacketFollows = firstKexPacketFollows;
      return this;
    }

    /**
     * @param reserved reserved
     * @return this Builder object for method chaining.
     */
    public Builder reserved(int reserved) {
      this.reserved = reserved;
      return this;
    }

    @Override
    public Ssh2KexInitPacket build() {
      return new Ssh2KexInitPacket(this);
    }
  }

  /**
   * @author Kaito Yamada
   * @version pcap4j 1.0.1
   */
  public static final class Ssh2KexInitHeader extends AbstractHeader {

    /*
     * http://tools.ietf.org/html/rfc4253
     *
     * byte         SSH_MSG_KEXINIT
     * byte[16]     cookie (random bytes)
     * name-list    kex_algorithms
     * name-list    server_host_key_algorithms
     * name-list    encryption_algorithms_client_to_server
     * name-list    encryption_algorithms_server_to_client
     * name-list    mac_algorithms_client_to_server
     * name-list    mac_algorithms_server_to_client
     * name-list    compression_algorithms_client_to_server
     * name-list    compression_algorithms_server_to_client
     * name-list    languages_client_to_server
     * name-list    languages_server_to_client
     * boolean      first_kex_packet_follows
     * uint32       0 (reserved for future extension)
     */

    /** */
    private static final long serialVersionUID = -2780304573850816908L;

    private final Ssh2MessageNumber messageNumber = Ssh2MessageNumber.SSH_MSG_KEXINIT;
    private final byte[] cookie;
    private final Ssh2NameList kexAlgorithms;
    private final Ssh2NameList serverHostKeyAlgorithms;
    private final Ssh2NameList encryptionAlgorithmsClientToServer;
    private final Ssh2NameList encryptionAlgorithmsServerToClient;
    private final Ssh2NameList macAlgorithmsClientToServer;
    private final Ssh2NameList macAlgorithmsServerToClient;
    private final Ssh2NameList compressionAlgorithmsClientToServer;
    private final Ssh2NameList compressionAlgorithmsServerToClient;
    private final Ssh2NameList languagesClientToServer;
    private final Ssh2NameList languagesServerToClient;
    private final Ssh2Boolean firstKexPacketFollows;
    private final int reserved;

    private Ssh2KexInitHeader(byte[] rawData, int offset, int length)
        throws IllegalRawDataException {
      if (length < 62) {
        StringBuilder sb = new StringBuilder(120);
        sb.append("The data is too short to build an SSH2 KEX init header. data: ")
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
        sb.append("The data is not an SSH2 KEX init message. data: ")
            .append(new String(rawData))
            .append(", offset: ")
            .append(offset)
            .append(", length: ")
            .append(length);
        throw new IllegalRawDataException(sb.toString());
      }

      int currentOffset = 1 + offset;
      int remainingLength = length - 1;
      this.cookie = ByteArrays.getSubArray(rawData, currentOffset, 16);
      currentOffset += cookie.length;
      remainingLength -= cookie.length;
      this.kexAlgorithms = new Ssh2NameList(rawData, currentOffset, remainingLength);
      currentOffset += kexAlgorithms.length();
      remainingLength -= kexAlgorithms.length();
      this.serverHostKeyAlgorithms = new Ssh2NameList(rawData, currentOffset, remainingLength);
      currentOffset += serverHostKeyAlgorithms.length();
      remainingLength -= serverHostKeyAlgorithms.length();
      this.encryptionAlgorithmsClientToServer =
          new Ssh2NameList(rawData, currentOffset, remainingLength);
      currentOffset += encryptionAlgorithmsClientToServer.length();
      remainingLength -= encryptionAlgorithmsClientToServer.length();
      this.encryptionAlgorithmsServerToClient =
          new Ssh2NameList(rawData, currentOffset, remainingLength);
      currentOffset += encryptionAlgorithmsClientToServer.length();
      remainingLength -= encryptionAlgorithmsClientToServer.length();
      this.macAlgorithmsClientToServer = new Ssh2NameList(rawData, currentOffset, remainingLength);
      currentOffset += macAlgorithmsClientToServer.length();
      remainingLength -= macAlgorithmsClientToServer.length();
      this.macAlgorithmsServerToClient = new Ssh2NameList(rawData, currentOffset, remainingLength);
      currentOffset += macAlgorithmsServerToClient.length();
      remainingLength -= macAlgorithmsServerToClient.length();
      this.compressionAlgorithmsClientToServer =
          new Ssh2NameList(rawData, currentOffset, remainingLength);
      currentOffset += compressionAlgorithmsClientToServer.length();
      remainingLength -= compressionAlgorithmsClientToServer.length();
      this.compressionAlgorithmsServerToClient =
          new Ssh2NameList(rawData, currentOffset, remainingLength);
      currentOffset += compressionAlgorithmsServerToClient.length();
      remainingLength -= compressionAlgorithmsServerToClient.length();
      this.languagesClientToServer = new Ssh2NameList(rawData, currentOffset, remainingLength);
      currentOffset += languagesClientToServer.length();
      remainingLength -= languagesClientToServer.length();
      this.languagesServerToClient = new Ssh2NameList(rawData, currentOffset, remainingLength);
      currentOffset += languagesServerToClient.length();
      remainingLength -= languagesServerToClient.length();

      if (remainingLength < 5) {
        StringBuilder sb = new StringBuilder(120);
        sb.append("The data is too short to build an SSH2 KEX init header. data: ")
            .append(new String(rawData))
            .append(", offset: ")
            .append(offset)
            .append(", length: ")
            .append(length);
        throw new IllegalRawDataException(sb.toString());
      }

      this.firstKexPacketFollows = new Ssh2Boolean(rawData[currentOffset]);
      currentOffset += 1;
      this.reserved = ByteArrays.getInt(rawData, currentOffset);
    }

    private Ssh2KexInitHeader(Builder builder) {
      this.cookie = ByteArrays.clone(builder.cookie);
      if (cookie.length != 16) {
        StringBuilder sb = new StringBuilder(100);
        sb.append("cookie length must be 16. builder.cookie: ")
            .append(ByteArrays.toHexString(builder.cookie, " "));
        throw new IllegalArgumentException(sb.toString());
      }
      this.kexAlgorithms = builder.kexAlgorithms;
      this.serverHostKeyAlgorithms = builder.serverHostKeyAlgorithms;
      this.encryptionAlgorithmsClientToServer = builder.encryptionAlgorithmsClientToServer;
      this.encryptionAlgorithmsServerToClient = builder.encryptionAlgorithmsServerToClient;
      this.macAlgorithmsClientToServer = builder.macAlgorithmsClientToServer;
      this.macAlgorithmsServerToClient = builder.macAlgorithmsServerToClient;
      this.compressionAlgorithmsClientToServer = builder.compressionAlgorithmsClientToServer;
      this.compressionAlgorithmsServerToClient = builder.compressionAlgorithmsServerToClient;
      this.languagesClientToServer = builder.languagesClientToServer;
      this.languagesServerToClient = builder.languagesServerToClient;
      this.firstKexPacketFollows = builder.firstKexPacketFollows;
      this.reserved = builder.reserved;
    }

    /** @return messageNumber */
    public Ssh2MessageNumber getMessageNumber() {
      return messageNumber;
    }

    /** @return cookie */
    public byte[] getCookie() {
      return ByteArrays.clone(cookie);
    }

    /** @return kexAlgorithms */
    public Ssh2NameList getKexAlgorithms() {
      return kexAlgorithms;
    }

    /** @return serverHostKeyAlgorithms */
    public Ssh2NameList getServerHostKeyAlgorithms() {
      return serverHostKeyAlgorithms;
    }

    /** @return encryptionAlgorithmsClientToServer */
    public Ssh2NameList getEncryptionAlgorithmsClientToServer() {
      return encryptionAlgorithmsClientToServer;
    }

    /** @return encryptionAlgorithmsServerToClient */
    public Ssh2NameList getEncryptionAlgorithmsServerToClient() {
      return encryptionAlgorithmsServerToClient;
    }

    /** @return macAlgorithmsClientToServer */
    public Ssh2NameList getMacAlgorithmsClientToServer() {
      return macAlgorithmsClientToServer;
    }

    /** @return macAlgorithmsServerToClient */
    public Ssh2NameList getMacAlgorithmsServerToClient() {
      return macAlgorithmsServerToClient;
    }

    /** @return compressionAlgorithmsClientToServer */
    public Ssh2NameList getCompressionAlgorithmsClientToServer() {
      return compressionAlgorithmsClientToServer;
    }

    /** @return compressionAlgorithmsServerToClient */
    public Ssh2NameList getCompressionAlgorithmsServerToClient() {
      return compressionAlgorithmsServerToClient;
    }

    /** @return languagesClientToServer */
    public Ssh2NameList getLanguagesClientToServer() {
      return languagesClientToServer;
    }

    /** @return languagesServerToClient */
    public Ssh2NameList getLanguagesServerToClient() {
      return languagesServerToClient;
    }

    /** @return firstKexPacketFollows */
    public Ssh2Boolean getFirstKexPacketFollows() {
      return firstKexPacketFollows;
    }

    /** @return reserved */
    public int getReserved() {
      return reserved;
    }

    @Override
    protected List<byte[]> getRawFields() {
      List<byte[]> rawFields = new ArrayList<byte[]>();
      rawFields.add(new byte[] {messageNumber.value()});
      rawFields.add(cookie);
      rawFields.add(kexAlgorithms.getRawData());
      rawFields.add(serverHostKeyAlgorithms.getRawData());
      rawFields.add(encryptionAlgorithmsClientToServer.getRawData());
      rawFields.add(encryptionAlgorithmsServerToClient.getRawData());
      rawFields.add(macAlgorithmsClientToServer.getRawData());
      rawFields.add(macAlgorithmsServerToClient.getRawData());
      rawFields.add(compressionAlgorithmsClientToServer.getRawData());
      rawFields.add(compressionAlgorithmsServerToClient.getRawData());
      rawFields.add(languagesClientToServer.getRawData());
      rawFields.add(languagesServerToClient.getRawData());
      rawFields.add(firstKexPacketFollows.getRawData());
      rawFields.add(ByteArrays.toByteArray(reserved));
      return rawFields;
    }

    @Override
    protected int calcLength() {
      return getRawData().length;
    }

    @Override
    protected String buildString() {
      StringBuilder sb = new StringBuilder();
      String ls = System.getProperty("line.separator");

      sb.append("[SSH2 KEX init Header (").append(length()).append(" bytes)]").append(ls);
      sb.append("  Message Number: ").append(messageNumber).append(ls);
      sb.append("  cookie: ").append(ByteArrays.toHexString(cookie, " ")).append(ls);
      sb.append("  kex_algorithms: ").append(kexAlgorithms).append(ls);
      sb.append("  server_host_key_algorithms: ").append(serverHostKeyAlgorithms).append(ls);
      sb.append("  encryption_algorithms_client_to_server: ")
          .append(encryptionAlgorithmsClientToServer)
          .append(ls);
      sb.append("  encryption_algorithms_server_to_client: ")
          .append(encryptionAlgorithmsServerToClient)
          .append(ls);
      sb.append("  mac_algorithms_client_to_server: ")
          .append(macAlgorithmsClientToServer)
          .append(ls);
      sb.append("  mac_algorithms_server_to_client: ")
          .append(macAlgorithmsServerToClient)
          .append(ls);
      sb.append("  compression_algorithms_client_to_server: ")
          .append(compressionAlgorithmsClientToServer)
          .append(ls);
      sb.append("  compression_algorithms_server_to_client: ")
          .append(compressionAlgorithmsServerToClient)
          .append(ls);
      sb.append("  languages_client_to_server: ").append(languagesClientToServer).append(ls);
      sb.append("  languages_server_to_client: ").append(languagesServerToClient).append(ls);
      sb.append("  first_kex_packet_follows: ").append(firstKexPacketFollows).append(ls);
      sb.append("  reserved: ").append(ByteArrays.toHexString(reserved, " ")).append(ls);

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

      Ssh2KexInitHeader other = (Ssh2KexInitHeader) obj;
      return Arrays.equals(cookie, other.cookie)
          && kexAlgorithms.equals(other.kexAlgorithms)
          && serverHostKeyAlgorithms.equals(other.serverHostKeyAlgorithms)
          && encryptionAlgorithmsClientToServer.equals(other.encryptionAlgorithmsClientToServer)
          && encryptionAlgorithmsServerToClient.equals(other.encryptionAlgorithmsServerToClient)
          && macAlgorithmsClientToServer.equals(other.macAlgorithmsClientToServer)
          && macAlgorithmsServerToClient.equals(other.macAlgorithmsServerToClient)
          && compressionAlgorithmsClientToServer.equals(other.compressionAlgorithmsClientToServer)
          && compressionAlgorithmsServerToClient.equals(other.compressionAlgorithmsServerToClient)
          && languagesClientToServer.equals(other.languagesClientToServer)
          && languagesServerToClient.equals(other.languagesServerToClient)
          && firstKexPacketFollows.equals(other.firstKexPacketFollows)
          && reserved == other.reserved;
    }

    @Override
    protected int calcHashCode() {
      int result = 17;
      result = 31 * result + Arrays.hashCode(cookie);
      result = 31 * result + kexAlgorithms.hashCode();
      result = 31 * result + serverHostKeyAlgorithms.hashCode();
      result = 31 * result + encryptionAlgorithmsClientToServer.hashCode();
      result = 31 * result + encryptionAlgorithmsServerToClient.hashCode();
      result = 31 * result + macAlgorithmsClientToServer.hashCode();
      result = 31 * result + macAlgorithmsServerToClient.hashCode();
      result = 31 * result + compressionAlgorithmsClientToServer.hashCode();
      result = 31 * result + compressionAlgorithmsServerToClient.hashCode();
      result = 31 * result + languagesClientToServer.hashCode();
      result = 31 * result + languagesServerToClient.hashCode();
      result = 31 * result + firstKexPacketFollows.hashCode();
      result = 31 * result + reserved;
      return result;
    }
  }
}
