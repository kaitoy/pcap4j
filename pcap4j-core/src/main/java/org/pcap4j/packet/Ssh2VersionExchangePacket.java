/*_##########################################################################
  _##
  _##  Copyright (C) 2014  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import org.pcap4j.util.ByteArrays;

/**
 * @author Kaito Yamada
 * @since pcap4j 1.0.1
 */
public final class Ssh2VersionExchangePacket extends AbstractPacket {

  /** */
  private static final long serialVersionUID = 936170241296151065L;

  private final Ssh2VersionExchangeHeader header;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new Ssh2VersionExchangePacket object.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static Ssh2VersionExchangePacket newPacket(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    return new Ssh2VersionExchangePacket(rawData, offset, length);
  }

  private Ssh2VersionExchangePacket(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    this.header = new Ssh2VersionExchangeHeader(rawData, offset, length);
  }

  private Ssh2VersionExchangePacket(Builder builder) {
    if (builder == null
        || builder.protoVersion == null
        || builder.softwareVersion == null
        || builder.comments == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("builder: ")
          .append(builder)
          .append(" builder.protoVersion: ")
          .append(builder.protoVersion)
          .append(" builder.softwareVersion: ")
          .append(builder.softwareVersion)
          .append(" builder.comments: ")
          .append(builder.comments);
      throw new NullPointerException(sb.toString());
    }

    this.header = new Ssh2VersionExchangeHeader(builder);
  }

  @Override
  public Ssh2VersionExchangeHeader getHeader() {
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

    private List<String> messages;
    private String protoVersion;
    private String softwareVersion;
    private String comments;

    /** */
    public Builder() {}

    private Builder(Ssh2VersionExchangePacket packet) {
      this.messages = packet.header.messages;
      this.protoVersion = packet.header.protoVersion;
      this.softwareVersion = packet.header.softwareVersion;
      this.comments = packet.header.comments;
    }

    /**
     * @param messages messages
     * @return this Builder object for method chaining.
     */
    public Builder messages(List<String> messages) {
      this.messages = messages;
      return this;
    }

    /**
     * @param protoVersion protoVersion
     * @return this Builder object for method chaining.
     */
    public Builder protoVersion(String protoVersion) {
      this.protoVersion = protoVersion;
      return this;
    }

    /**
     * @param softwareVersion softwareVersion
     * @return this Builder object for method chaining.
     */
    public Builder softwareVersion(String softwareVersion) {
      this.softwareVersion = softwareVersion;
      return this;
    }

    /**
     * @param comments comments
     * @return this Builder object for method chaining.
     */
    public Builder comments(String comments) {
      this.comments = comments;
      return this;
    }

    @Override
    public Ssh2VersionExchangePacket build() {
      return new Ssh2VersionExchangePacket(this);
    }
  }

  /**
   * @author Kaito Yamada
   * @version pcap4j 1.0.1
   */
  public static final class Ssh2VersionExchangeHeader extends AbstractHeader {

    /*
     * http://tools.ietf.org/html/rfc4253
     *
     *   message CR LF
     *   message CR LF
     *       :
     *   SSH-protoversion-softwareversion SP comments CR LF
     *
     * The 'comments' string is OPTIONAL. If the 'comments' string is included, a 'space' character
     * (denoted above as SP, ASCII 32) MUST separate the 'softwareversion'
     * and 'comments' strings.  The identification MUST be terminated by a
     * single Carriage Return (CR) and a single Line Feed (LF) character
     * (ASCII 13 and 10, respectively).
     * The maximum length of the string is 255 characters, including the
     * Carriage Return and Line Feed.
     *
     * The server MAY send other lines of data before sending the version
     * string.  Each line SHOULD be terminated by a Carriage Return and Line
     * Feed.  Such lines MUST NOT begin with "SSH-", and SHOULD be encoded
     * in ISO-10646 UTF-8.
     *
     * Both the 'protoversion' and 'softwareversion' strings MUST consist of
     * printable US-ASCII characters, with the exception of whitespace
     * characters and the minus sign (-).
     */

    /** */
    private static final long serialVersionUID = -997040469918475251L;

    private final List<String> messages;
    private final String protoVersion;
    private final String softwareVersion;
    private final String comments;

    private Ssh2VersionExchangeHeader(byte[] rawData, int offset, int length)
        throws IllegalRawDataException {
      if (length < 9) {
        StringBuilder sb = new StringBuilder(120);
        sb.append("The data is too short to build an SSH2 version exchange header. data: ")
            .append(new String(rawData))
            .append(", offset: ")
            .append(offset)
            .append(", length: ")
            .append(length);
        throw new IllegalRawDataException(sb.toString());
      }

      String data;
      try {
        data = new String(rawData, offset, length, "UTF-8");
      } catch (UnsupportedEncodingException e) {
        throw new AssertionError("Never get here.");
      }
      String[] lines = data.split("\r\n", -1);
      this.messages = new ArrayList<String>();
      int versionIdx = -1;
      for (int i = 0; i < lines.length; i++) {
        if (lines[i].startsWith("SSH-")) {
          versionIdx = i;
          break;
        }
        messages.add(lines[i]);
      }

      if (versionIdx == -1) {
        StringBuilder sb = new StringBuilder(120);
        sb.append("The data doesn't include the version string. data: ").append(data);
        throw new IllegalRawDataException(sb.toString());
      }
      if (lines.length < versionIdx + 2) {
        StringBuilder sb = new StringBuilder(120);
        sb.append("The version string must be terminated by CR LF. data: ").append(data);
        throw new IllegalRawDataException(sb.toString());
      }

      data = lines[versionIdx].substring(4); // remove SSH-
      int hyphenIdx = data.indexOf("-");
      if (hyphenIdx == -1) {
        StringBuilder sb = new StringBuilder(120);
        sb.append("The data must start with SSH-protoversion-softwareversion. data: ").append(data);
        throw new IllegalRawDataException(sb.toString());
      }

      this.protoVersion = data.substring(0, hyphenIdx);

      data = data.substring(hyphenIdx + 1);
      int spIdx = data.indexOf(" ");
      if (spIdx != -1) {
        this.softwareVersion = data.substring(0, spIdx);
        this.comments = data.substring(spIdx + 1, data.length());
      } else {
        this.softwareVersion = data.substring(0, data.length());
        this.comments = "";
      }

      if (length() > 255) {
        StringBuilder sb = new StringBuilder(120);
        sb.append("The data is too long for an SSH version exchange header. data: ")
            .append(new String(rawData))
            .append(", offset: ")
            .append(offset)
            .append(", length: ")
            .append(length);
        throw new IllegalRawDataException(sb.toString());
      }
    }

    private Ssh2VersionExchangeHeader(Builder builder) {
      if (builder.messages != null) {
        this.messages = new ArrayList<String>(builder.messages);
      } else {
        this.messages = new ArrayList<String>();
      }
      this.protoVersion = builder.protoVersion;
      this.softwareVersion = builder.softwareVersion;
      this.comments = builder.comments;

      if (length() > 255) {
        StringBuilder sb = new StringBuilder(120);
        sb.append("The data is too long for an SSH version exchange header. data: ")
            .append("builder.messages: [");
        Iterator<String> iter = messages.iterator();
        while (iter.hasNext()) {
          String message = iter.next();
          sb.append(message);
          if (iter.hasNext()) {
            sb.append(", ");
          }
        }
        sb.append("]")
            .append(" builder.protoVersion: ")
            .append(builder.protoVersion)
            .append(" builder.softwareVersion: ")
            .append(builder.softwareVersion)
            .append(" builder.comments: ")
            .append(builder.comments);
        throw new IllegalArgumentException(sb.toString());
      }
    }

    /** @return a shallow copy of messages */
    public ArrayList<String> getMessages() {
      return new ArrayList<String>(messages);
    }

    /** @return protoVersion */
    public String getProtoVersion() {
      return protoVersion;
    }

    /** @return softwareVersion */
    public String getSoftwareVersion() {
      return softwareVersion;
    }

    /** @return comments */
    public String getComments() {
      return comments;
    }

    /** @return the entire message. */
    public String getEntireMessage() {
      StringBuilder sb = new StringBuilder(50);
      for (String message : messages) {
        sb.append(message).append("\r\n");
      }
      sb.append("SSH-").append(protoVersion).append("-").append(softwareVersion);
      if (comments.length() != 0) {
        sb.append(" ").append(comments);
      }
      sb.append("\r\n");

      return sb.toString();
    }

    @Override
    protected List<byte[]> getRawFields() {
      List<byte[]> rawFields = new ArrayList<byte[]>();
      rawFields.add(getEntireMessage().getBytes());
      return rawFields;
    }

    @Override
    protected int calcLength() {
      return getEntireMessage().length();
    }

    @Override
    protected String buildString() {
      StringBuilder sb = new StringBuilder();
      String ls = System.getProperty("line.separator");

      sb.append("[SSH2 Version Exchange Header (").append(length()).append(" bytes)]").append(ls);
      for (String line : getEntireMessage().split("\r\n")) {
        sb.append("  ").append(line).append(ls);
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

      Ssh2VersionExchangeHeader other = (Ssh2VersionExchangeHeader) obj;
      return protoVersion.equals(other.protoVersion)
          && softwareVersion.equals(other.softwareVersion)
          && comments.equals(other.comments)
          && messages.equals(other.messages);
    }

    @Override
    protected int calcHashCode() {
      int result = 17;
      result = 31 * result + messages.hashCode();
      result = 31 * result + protoVersion.hashCode();
      result = 31 * result + softwareVersion.hashCode();
      result = 31 * result + comments.hashCode();
      return result;
    }
  }
}
