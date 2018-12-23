/*_##########################################################################
  _##
  _##  Copyright (C) 2016  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import static org.pcap4j.util.ByteArrays.*;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.pcap4j.packet.namednumber.DnsOpCode;
import org.pcap4j.packet.namednumber.DnsRCode;
import org.pcap4j.util.ByteArrays;

/**
 * DNS packet.
 *
 * @see <a href="https://tools.ietf.org/html/rfc1035">RFC 1035</a>
 * @see <a
 *     href="http://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-12">DNS
 *     Header Flags</a>
 * @author Kaito Yamada
 * @since pcap4j 1.7.1
 */
public final class DnsPacket extends AbstractPacket {

  /** */
  private static final long serialVersionUID = 2804715680374557063L;

  private final DnsHeader header;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new DnsPacket object.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static DnsPacket newPacket(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    return new DnsPacket(rawData, offset, length);
  }

  private DnsPacket(byte[] rawData, int offset, int length) throws IllegalRawDataException {
    this.header = new DnsHeader(rawData, offset, length);
  }

  private DnsPacket(Builder builder) {
    if (builder == null || builder.opCode == null || builder.rCode == null) {
      StringBuilder sb = new StringBuilder();
      sb.append("builder: ")
          .append(builder)
          .append(" builder.opCode: ")
          .append(builder.opCode)
          .append(" builder.rCode: ")
          .append(builder.rCode);
      throw new NullPointerException(sb.toString());
    }

    this.header = new DnsHeader(builder);
  }

  @Override
  public DnsHeader getHeader() {
    return header;
  }

  @Override
  public Builder getBuilder() {
    return new Builder(this);
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 1.7.1
   */
  public static final class Builder extends AbstractBuilder {

    private short id;
    private boolean response;
    private DnsOpCode opCode;
    private boolean authoritativeAnswer;
    private boolean truncated;
    private boolean recursionDesired;
    private boolean recursionAvailable;
    private boolean reserved;
    private boolean authenticData;
    private boolean checkingDisabled;
    private DnsRCode rCode;
    private short qdCount;
    private short anCount;
    private short nsCount;
    private short arCount;
    private List<DnsQuestion> questions;
    private List<DnsResourceRecord> answers;
    private List<DnsResourceRecord> authorities;
    private List<DnsResourceRecord> additionalInfo;

    /** */
    public Builder() {}

    private Builder(DnsPacket packet) {
      this.id = packet.header.id;
      this.response = packet.header.response;
      this.opCode = packet.header.opCode;
      this.authoritativeAnswer = packet.header.authoritativeAnswer;
      this.truncated = packet.header.truncated;
      this.recursionDesired = packet.header.recursionDesired;
      this.recursionAvailable = packet.header.recursionAvailable;
      this.reserved = packet.header.reserved;
      this.authenticData = packet.header.authenticData;
      this.checkingDisabled = packet.header.checkingDisabled;
      this.rCode = packet.header.rCode;
      this.qdCount = packet.header.qdCount;
      this.anCount = packet.header.anCount;
      this.nsCount = packet.header.nsCount;
      this.arCount = packet.header.arCount;
      this.questions = packet.header.questions;
      this.answers = packet.header.answers;
      this.authorities = packet.header.authorities;
      this.additionalInfo = packet.header.additionalInfo;
    }

    /**
     * @param id id
     * @return this Builder object for method chaining.
     */
    public Builder id(short id) {
      this.id = id;
      return this;
    }

    /**
     * @param response response
     * @return this Builder object for method chaining.
     */
    public Builder response(boolean response) {
      this.response = response;
      return this;
    }

    /**
     * @param opCode opCode
     * @return this Builder object for method chaining.
     */
    public Builder opCode(DnsOpCode opCode) {
      this.opCode = opCode;
      return this;
    }

    /**
     * @param authoritativeAnswer authoritativeAnswer
     * @return this Builder object for method chaining.
     */
    public Builder authoritativeAnswer(boolean authoritativeAnswer) {
      this.authoritativeAnswer = authoritativeAnswer;
      return this;
    }

    /**
     * @param truncated truncated
     * @return this Builder object for method chaining.
     */
    public Builder truncated(boolean truncated) {
      this.truncated = truncated;
      return this;
    }

    /**
     * @param recursionDesired recursionDesired
     * @return this Builder object for method chaining.
     */
    public Builder recursionDesired(boolean recursionDesired) {
      this.recursionDesired = recursionDesired;
      return this;
    }

    /**
     * @param recursionAvailable recursionAvailable
     * @return this Builder object for method chaining.
     */
    public Builder recursionAvailable(boolean recursionAvailable) {
      this.recursionAvailable = recursionAvailable;
      return this;
    }

    /**
     * @param reserved reserved
     * @return this Builder object for method chaining.
     */
    public Builder reserved(boolean reserved) {
      this.reserved = reserved;
      return this;
    }

    /**
     * @param authenticData authenticData
     * @return this Builder object for method chaining.
     */
    public Builder authenticData(boolean authenticData) {
      this.authenticData = authenticData;
      return this;
    }

    /**
     * @param checkingDisabled checkingDisabled
     * @return this Builder object for method chaining.
     */
    public Builder checkingDisabled(boolean checkingDisabled) {
      this.checkingDisabled = checkingDisabled;
      return this;
    }

    /**
     * @param rCode rCode
     * @return this Builder object for method chaining.
     */
    public Builder rCode(DnsRCode rCode) {
      this.rCode = rCode;
      return this;
    }

    /**
     * @param qdCount qdCount
     * @return this Builder object for method chaining.
     */
    public Builder qdCount(short qdCount) {
      this.qdCount = qdCount;
      return this;
    }

    /**
     * @param anCount anCount
     * @return this Builder object for method chaining.
     */
    public Builder anCount(short anCount) {
      this.anCount = anCount;
      return this;
    }

    /**
     * @param nsCount nsCount
     * @return this Builder object for method chaining.
     */
    public Builder nsCount(short nsCount) {
      this.nsCount = nsCount;
      return this;
    }

    /**
     * @param arCount arCount
     * @return this Builder object for method chaining.
     */
    public Builder arCount(short arCount) {
      this.arCount = arCount;
      return this;
    }

    /**
     * @param questions questions
     * @return this Builder object for method chaining.
     */
    public Builder questions(List<DnsQuestion> questions) {
      this.questions = questions;
      return this;
    }

    /**
     * @param answers answers
     * @return this Builder object for method chaining.
     */
    public Builder answers(List<DnsResourceRecord> answers) {
      this.answers = answers;
      return this;
    }

    /**
     * @param authorities authorities
     * @return this Builder object for method chaining.
     */
    public Builder authorities(List<DnsResourceRecord> authorities) {
      this.authorities = authorities;
      return this;
    }

    /**
     * @param additionalInfo additionalInfo
     * @return this Builder object for method chaining.
     */
    public Builder additionalInfo(List<DnsResourceRecord> additionalInfo) {
      this.additionalInfo = additionalInfo;
      return this;
    }

    @Override
    public DnsPacket build() {
      return new DnsPacket(this);
    }
  }

  /**
   * DNS header
   *
   * <pre style="white-space: pre;">
   * +---------------------+
   * |        Header       |
   * +---------------------+
   * |       Question      | the question for the name server
   * +---------------------+
   * |        Answer       | RRs answering the question
   * +---------------------+
   * |      Authority      | RRs pointing toward an authority
   * +---------------------+
   * |      Additional     | RRs holding additional information
   * +---------------------+
   *
   * Header:
   *                                 1  1  1  1  1  1
   *   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
   * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   * |                      ID                       |
   * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   * |QR|   Opcode  |AA|TC|RD|RA| Z|AD|CD|   RCODE   |
   * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   * |                    QDCOUNT                    |
   * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   * |                    ANCOUNT                    |
   * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   * |                    NSCOUNT                    |
   * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   * |                    ARCOUNT                    |
   * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   * </pre>
   *
   * @see <a href="https://tools.ietf.org/html/rfc1035">RFC 1035</a>
   * @see <a href="https://tools.ietf.org/html/rfc2535">RFC 2535</a>
   * @author Kaito Yamada
   * @version pcap4j 1.7.1
   */
  public static final class DnsHeader extends AbstractHeader {

    /** */
    private static final long serialVersionUID = -2779530760536525672L;

    private static final int ID_OFFSET = 0;
    private static final int ID_SIZE = SHORT_SIZE_IN_BYTES;
    private static final int FLAGS_OFFSET = ID_OFFSET + ID_SIZE;
    private static final int FLAGS_SIZE = SHORT_SIZE_IN_BYTES;
    private static final int QDCOUNT_OFFSET = FLAGS_OFFSET + FLAGS_SIZE;
    private static final int QDCOUNT_SIZE = SHORT_SIZE_IN_BYTES;
    private static final int ANCOUNT_OFFSET = QDCOUNT_OFFSET + QDCOUNT_SIZE;
    private static final int ANCOUNT_SIZE = SHORT_SIZE_IN_BYTES;
    private static final int NSCOUNT_OFFSET = ANCOUNT_OFFSET + ANCOUNT_SIZE;
    private static final int NSCOUNT_SIZE = SHORT_SIZE_IN_BYTES;
    private static final int ARCOUNT_OFFSET = NSCOUNT_OFFSET + NSCOUNT_SIZE;
    private static final int ARCOUNT_SIZE = SHORT_SIZE_IN_BYTES;
    private static final int DNS_MIN_HEADER_SIZE = ARCOUNT_OFFSET + ARCOUNT_SIZE;

    private final short id;
    private final boolean response;
    private final DnsOpCode opCode;
    private final boolean authoritativeAnswer;
    private final boolean truncated;
    private final boolean recursionDesired;
    private final boolean recursionAvailable;
    private final boolean reserved;
    private final boolean authenticData;
    private final boolean checkingDisabled;
    private final DnsRCode rCode;
    private final short qdCount;
    private final short anCount;
    private final short nsCount;
    private final short arCount;
    private final List<DnsQuestion> questions;
    private final List<DnsResourceRecord> answers;
    private final List<DnsResourceRecord> authorities;
    private final List<DnsResourceRecord> additionalInfo;

    private DnsHeader(byte[] rawData, int offset, int length) throws IllegalRawDataException {
      if (length < DNS_MIN_HEADER_SIZE) {
        StringBuilder sb = new StringBuilder(200);
        sb.append("The data is too short to build a DnsHeader (")
            .append(DNS_MIN_HEADER_SIZE)
            .append(" bytes). data: ")
            .append(ByteArrays.toHexString(rawData, " "))
            .append(", offset: ")
            .append(offset)
            .append(", length: ")
            .append(length);
        throw new IllegalRawDataException(sb.toString());
      }

      this.id = ByteArrays.getShort(rawData, ID_OFFSET + offset);
      short flags = ByteArrays.getShort(rawData, FLAGS_OFFSET + offset);
      this.response = (flags & 0x8000) != 0;
      this.opCode = DnsOpCode.getInstance((byte) ((flags >> 11) & 0x0F));
      this.authoritativeAnswer = (flags & 0x0400) != 0;
      this.truncated = (flags & 0x0200) != 0;
      this.recursionDesired = (flags & 0x0100) != 0;
      this.recursionAvailable = (flags & 0x0080) != 0;
      this.reserved = (flags & 0x0040) != 0;
      this.authenticData = (flags & 0x0020) != 0;
      this.checkingDisabled = (flags & 0x0010) != 0;
      this.rCode = DnsRCode.getInstance((byte) (flags & 0x0F));
      this.qdCount = ByteArrays.getShort(rawData, QDCOUNT_OFFSET + offset);
      this.anCount = ByteArrays.getShort(rawData, ANCOUNT_OFFSET + offset);
      this.nsCount = ByteArrays.getShort(rawData, NSCOUNT_OFFSET + offset);
      this.arCount = ByteArrays.getShort(rawData, ARCOUNT_OFFSET + offset);

      int qdCnt = getQdCountAsInt();
      int anCnt = getAnCountAsInt();
      int nsCnt = getNsCountAsInt();
      int arCnt = getArCountAsInt();
      this.questions = new ArrayList<DnsQuestion>(qdCnt);
      this.answers = new ArrayList<DnsResourceRecord>(anCnt);
      this.authorities = new ArrayList<DnsResourceRecord>(nsCnt);
      this.additionalInfo = new ArrayList<DnsResourceRecord>(arCnt);

      int cursor = DNS_MIN_HEADER_SIZE;
      for (int i = 0; i < qdCnt; i++) {
        int remainingLen = length - cursor;
        if (remainingLen == 0) {
          StringBuilder sb = new StringBuilder(200);
          sb.append("The data is too short to build a question in DnsHeader. data: ")
              .append(ByteArrays.toHexString(rawData, " "))
              .append(", offset: ")
              .append(offset)
              .append(", length: ")
              .append(length)
              .append(", cursor: ")
              .append(cursor);
          throw new IllegalRawDataException(sb.toString());
        }
        DnsQuestion question = DnsQuestion.newInstance(rawData, offset + cursor, remainingLen);
        questions.add(question);
        cursor += question.length();
      }
      for (int i = 0; i < anCnt; i++) {
        int remainingLen = length - cursor;
        if (remainingLen == 0) {
          StringBuilder sb = new StringBuilder(200);
          sb.append("The data is too short to build an answer in DnsHeader. data: ")
              .append(ByteArrays.toHexString(rawData, " "))
              .append(", offset: ")
              .append(offset)
              .append(", length: ")
              .append(length)
              .append(", cursor: ")
              .append(cursor);
          throw new IllegalRawDataException(sb.toString());
        }
        DnsResourceRecord answer =
            DnsResourceRecord.newInstance(rawData, offset + cursor, remainingLen);
        answers.add(answer);
        cursor += answer.length();
      }
      for (int i = 0; i < nsCnt; i++) {
        int remainingLen = length - cursor;
        if (remainingLen == 0) {
          StringBuilder sb = new StringBuilder(200);
          sb.append("The data is too short to build an authority in DnsHeader. data: ")
              .append(ByteArrays.toHexString(rawData, " "))
              .append(", offset: ")
              .append(offset)
              .append(", length: ")
              .append(length)
              .append(", cursor: ")
              .append(cursor);
          throw new IllegalRawDataException(sb.toString());
        }
        DnsResourceRecord authority =
            DnsResourceRecord.newInstance(rawData, offset + cursor, remainingLen);
        authorities.add(authority);
        cursor += authority.length();
      }
      for (int i = 0; i < arCnt; i++) {
        int remainingLen = length - cursor;
        if (remainingLen == 0) {
          StringBuilder sb = new StringBuilder(200);
          sb.append("The data is too short to build additional info in DnsHeader. data: ")
              .append(ByteArrays.toHexString(rawData, " "))
              .append(", offset: ")
              .append(offset)
              .append(", length: ")
              .append(length)
              .append(", cursor: ")
              .append(cursor);
          throw new IllegalRawDataException(sb.toString());
        }
        DnsResourceRecord info =
            DnsResourceRecord.newInstance(rawData, offset + cursor, remainingLen);
        additionalInfo.add(info);
        cursor += info.length();
      }
    }

    private DnsHeader(Builder builder) {
      this.id = builder.id;
      this.response = builder.response;
      this.opCode = builder.opCode;
      this.authoritativeAnswer = builder.authoritativeAnswer;
      this.truncated = builder.truncated;
      this.recursionDesired = builder.recursionDesired;
      this.recursionAvailable = builder.recursionAvailable;
      this.reserved = builder.reserved;
      this.authenticData = builder.authenticData;
      this.checkingDisabled = builder.checkingDisabled;
      this.rCode = builder.rCode;
      this.qdCount = builder.qdCount;
      this.anCount = builder.anCount;
      this.nsCount = builder.nsCount;
      this.arCount = builder.arCount;
      if (builder.questions != null) {
        if (builder.questions.size() > 65535) {
          throw new IllegalArgumentException(
              "The number of questions must be less than 65536. builder.questions.size(): "
                  + builder.questions.size());
        }
        this.questions = new ArrayList<DnsQuestion>(builder.questions);
      } else {
        this.questions = Collections.emptyList();
      }
      if (builder.answers != null) {
        if (builder.answers.size() > 65535) {
          throw new IllegalArgumentException(
              "The number of answers must be less than 65536. builder.answers.size(): "
                  + builder.answers.size());
        }
        this.answers = new ArrayList<DnsResourceRecord>(builder.answers);
      } else {
        this.answers = Collections.emptyList();
      }
      if (builder.authorities != null) {
        if (builder.authorities.size() > 65535) {
          throw new IllegalArgumentException(
              "The number of authorities must be less than 65536. builder.authorities.size(): "
                  + builder.authorities.size());
        }
        this.authorities = new ArrayList<DnsResourceRecord>(builder.authorities);
      } else {
        this.authorities = Collections.emptyList();
      }
      if (builder.additionalInfo != null) {
        if (builder.additionalInfo.size() > 65535) {
          throw new IllegalArgumentException(
              "The number of additionalInfo elements must be less than 65536."
                  + " builder.additionalInfo.size(): "
                  + builder.additionalInfo.size());
        }
        this.additionalInfo = new ArrayList<DnsResourceRecord>(builder.additionalInfo);
      } else {
        this.additionalInfo = Collections.emptyList();
      }
    }

    /** @return id */
    public short getId() {
      return id;
    }

    /** @return true if the QR bit is set to 1; false otherwise. */
    public boolean isResponse() {
      return response;
    }

    /** @return opCode */
    public DnsOpCode getOpCode() {
      return opCode;
    }

    /** @return true if the AA bit is set to 1; false otherwise. */
    public boolean isAuthoritativeAnswer() {
      return authoritativeAnswer;
    }

    /** @return true if the TC bit is set to 1; false otherwise. */
    public boolean isTruncated() {
      return truncated;
    }

    /** @return true if the RD bit is set to 1; false otherwise. */
    public boolean isRecursionDesired() {
      return recursionDesired;
    }

    /** @return true if the RA bit is set to 1; false otherwise. */
    public boolean isRecursionAvailable() {
      return recursionAvailable;
    }

    /** @return true if the Z bit is set to 1; false otherwise. */
    public boolean getReservedBit() {
      return reserved;
    }

    /** @return true if the AD bit is set to 1; false otherwise. */
    public boolean isAuthenticData() {
      return authenticData;
    }

    /** @return true if the CD bit is set to 1; false otherwise. */
    public boolean isCheckingDisabled() {
      return checkingDisabled;
    }

    /** @return rCode */
    public DnsRCode getrCode() {
      return rCode;
    }

    /** @return qdCount */
    public short getQdCount() {
      return qdCount;
    }

    /** @return qdCount */
    public int getQdCountAsInt() {
      return qdCount & 0xFFFF;
    }

    /** @return anCount */
    public short getAnCount() {
      return anCount;
    }

    /** @return anCount */
    public int getAnCountAsInt() {
      return anCount & 0xFFFF;
    }

    /** @return nsCount */
    public short getNsCount() {
      return nsCount;
    }

    /** @return nsCount */
    public int getNsCountAsInt() {
      return nsCount & 0xFFFF;
    }

    /** @return arCount */
    public short getArCount() {
      return arCount;
    }

    /** @return arCount */
    public int getArCountAsInt() {
      return arCount & 0xFFFF;
    }

    /** @return questions */
    public List<DnsQuestion> getQuestions() {
      return new ArrayList<DnsQuestion>(questions);
    }

    /** @return answers */
    public List<DnsResourceRecord> getAnswers() {
      return new ArrayList<DnsResourceRecord>(answers);
    }

    /** @return authorities */
    public List<DnsResourceRecord> getAuthorities() {
      return new ArrayList<DnsResourceRecord>(authorities);
    }

    /** @return additionalInfo */
    public List<DnsResourceRecord> getAdditionalInfo() {
      return new ArrayList<DnsResourceRecord>(additionalInfo);
    }

    @Override
    protected List<byte[]> getRawFields() {
      List<byte[]> rawFields = new ArrayList<byte[]>();

      rawFields.add(ByteArrays.toByteArray(id));

      byte[] flags = new byte[2];
      flags[0] = (byte) (opCode.value() << 3);
      if (response) {
        flags[0] |= 0x80;
      }
      if (authoritativeAnswer) {
        flags[0] |= 0x04;
      }
      if (truncated) {
        flags[0] |= 0x02;
      }
      if (recursionDesired) {
        flags[0] |= 0x01;
      }
      flags[1] = rCode.value();
      if (recursionAvailable) {
        flags[1] |= 0x80;
      }
      if (reserved) {
        flags[1] |= 0x40;
      }
      if (authenticData) {
        flags[1] |= 0x20;
      }
      if (checkingDisabled) {
        flags[1] |= 0x10;
      }
      rawFields.add(flags);

      rawFields.add(ByteArrays.toByteArray(qdCount));
      rawFields.add(ByteArrays.toByteArray(anCount));
      rawFields.add(ByteArrays.toByteArray(nsCount));
      rawFields.add(ByteArrays.toByteArray(arCount));

      for (DnsQuestion question : questions) {
        rawFields.add(question.getRawData());
      }
      for (DnsResourceRecord answer : answers) {
        rawFields.add(answer.getRawData());
      }
      for (DnsResourceRecord authority : authorities) {
        rawFields.add(authority.getRawData());
      }
      for (DnsResourceRecord info : additionalInfo) {
        rawFields.add(info.getRawData());
      }

      return rawFields;
    }

    @Override
    public int length() {
      int len = DNS_MIN_HEADER_SIZE;
      for (DnsQuestion question : questions) {
        len += question.length();
      }
      for (DnsResourceRecord answer : answers) {
        len += answer.length();
      }
      for (DnsResourceRecord authority : authorities) {
        len += authority.length();
      }
      for (DnsResourceRecord info : additionalInfo) {
        len += info.length();
      }
      return len;
    }

    @Override
    protected String buildString() {
      StringBuilder sb = new StringBuilder();
      String ls = System.getProperty("line.separator");

      sb.append("[DNS Header (").append(length()).append(" bytes)]").append(ls);
      sb.append("  ID: ").append("0x" + ByteArrays.toHexString(id, "")).append(ls);
      sb.append("  QR: ").append(response ? "response" : "query").append(ls);
      sb.append("  OPCODE: ").append(opCode).append(ls);
      sb.append("  Authoritative Answer: ").append(authoritativeAnswer).append(ls);
      sb.append("  Truncated: ").append(truncated).append(ls);
      sb.append("  Recursion Desired: ").append(recursionDesired).append(ls);
      sb.append("  Recursion Available: ").append(recursionAvailable).append(ls);
      sb.append("  Reserved Bit: ").append(reserved ? 1 : 0).append(ls);
      sb.append("  Authentic Data: ").append(authenticData).append(ls);
      sb.append("  Checking Disabled: ").append(checkingDisabled).append(ls);
      sb.append("  RCODE: ").append(rCode).append(ls);
      sb.append("  QDCOUNT: ").append(qdCount).append(ls);
      sb.append("  ANCOUNT: ").append(anCount).append(ls);
      sb.append("  NSCOUNT: ").append(nsCount).append(ls);
      sb.append("  ARCOUNT: ").append(arCount).append(ls);

      byte[] headerRawData = getRawData();
      for (DnsQuestion question : questions) {
        sb.append("  Question:").append(ls).append(question.toString("    ", headerRawData));
      }
      for (DnsResourceRecord answer : answers) {
        sb.append("  Answer:").append(ls).append(answer.toString("    ", headerRawData));
      }
      for (DnsResourceRecord authority : authorities) {
        sb.append("  Authority:").append(ls).append(authority.toString("    ", headerRawData));
      }
      for (DnsResourceRecord info : additionalInfo) {
        sb.append("  Additional:").append(ls).append(info.toString("    ", headerRawData));
      }

      return sb.toString();
    }

    @Override
    public boolean equals(Object obj) {
      if (this == obj) {
        return true;
      }
      if (!super.equals(obj)) {
        return false;
      }
      if (getClass() != obj.getClass()) {
        return false;
      }
      DnsHeader other = (DnsHeader) obj;
      if (!additionalInfo.equals(other.additionalInfo)) {
        return false;
      }
      if (anCount != other.anCount) {
        return false;
      }
      if (!answers.equals(other.answers)) {
        return false;
      }
      if (arCount != other.arCount) {
        return false;
      }
      if (authenticData != other.authenticData) {
        return false;
      }
      if (authoritativeAnswer != other.authoritativeAnswer) {
        return false;
      }
      if (!authorities.equals(other.authorities)) {
        return false;
      }
      if (checkingDisabled != other.checkingDisabled) {
        return false;
      }
      if (id != other.id) {
        return false;
      }
      if (nsCount != other.nsCount) {
        return false;
      }
      if (!opCode.equals(other.opCode)) {
        return false;
      }
      if (qdCount != other.qdCount) {
        return false;
      }
      if (!questions.equals(other.questions)) {
        return false;
      }
      if (!rCode.equals(other.rCode)) {
        return false;
      }
      if (recursionAvailable != other.recursionAvailable) {
        return false;
      }
      if (recursionDesired != other.recursionDesired) {
        return false;
      }
      if (reserved != other.reserved) {
        return false;
      }
      if (response != other.response) {
        return false;
      }
      if (truncated != other.truncated) {
        return false;
      }
      return true;
    }

    @Override
    protected int calcHashCode() {
      final int prime = 31;
      int result = 17;
      result = prime * result + additionalInfo.hashCode();
      result = prime * result + anCount;
      result = prime * result + answers.hashCode();
      result = prime * result + arCount;
      result = prime * result + (authenticData ? 1231 : 1237);
      result = prime * result + (authoritativeAnswer ? 1231 : 1237);
      result = prime * result + authorities.hashCode();
      result = prime * result + (checkingDisabled ? 1231 : 1237);
      result = prime * result + id;
      result = prime * result + nsCount;
      result = prime * result + opCode.hashCode();
      result = prime * result + qdCount;
      result = prime * result + questions.hashCode();
      result = prime * result + rCode.hashCode();
      result = prime * result + (recursionAvailable ? 1231 : 1237);
      result = prime * result + (recursionDesired ? 1231 : 1237);
      result = prime * result + (reserved ? 1231 : 1237);
      result = prime * result + (response ? 1231 : 1237);
      result = prime * result + (truncated ? 1231 : 1237);
      return result;
    }
  }
}
