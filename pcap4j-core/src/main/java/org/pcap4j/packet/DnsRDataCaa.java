/*_##########################################################################
  _##
  _##  Copyright (C) 2017  Pcap4J.org
  _##
  _##########################################################################
 */

package org.pcap4j.packet;

import org.pcap4j.packet.DnsResourceRecord.DnsRData;
import org.pcap4j.util.ByteArrays;

/**
 * DNS CAA RDATA
 *
 * <pre style="white-space: pre;">
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                  FLAG                         |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * /                  TAG                          /
 * /                                               /
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * /                  VALUE                        /
 * /                                               /
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *
 * where:
 *
 * FLAG            One octet containing bit flags for record. See rfc for details.
 *
 * TAG             The property identifier, a sequence of US-ASCII characters.
 *
 * VALUE           A sequence of octets representing the property value.
 *
 * </pre>
 *
 * @see <a href="https://tools.ietf.org/html/rfc6844">RFC 6844</a>
 * @author Paulo Pacheco
 * @since pcap4j 1.7.2
 */
public final class DnsRDataCaa implements DnsRData {

    private final int flag;
    private final String tag;
    private final String value;

    private static final int CAA_RR_MIN_LEN = 6 /* Do not accept empty tag values */;

    /** A serial UID for serialization. */
    private static final long serialVersionUID = -1015182073420031158L;

    /**
     * A static factory method.
     * This method validates the arguments by {@link ByteArrays#validateBounds(byte[], int, int)},
     * which may throw exceptions undocumented here.
     *
     * @param rawData rawData
     * @param offset offset
     * @param length length
     * @return a new DnsRDataCaa object.
     * @throws IllegalRawDataException if parsing the raw data fails.
     */
    public static DnsRDataCaa newInstance(
            byte[] rawData, int offset, int length
            ) throws IllegalRawDataException {
        ByteArrays.validateBounds(rawData, offset, length);
        return new DnsRDataCaa(rawData, offset, length);
    }

    private DnsRDataCaa(byte[] rawData, int offset, int length) throws IllegalRawDataException {

        if (length < CAA_RR_MIN_LEN) {
            throw new IllegalRawDataException("The data is too short to build a DnsRDataCaa");
        }

        this.flag = ByteArrays.getByte(rawData, offset) & 0xFF;

        /* Reading single property entry consisting of a tag-value pair. */

        /* Read tag */
        int cursor = 1;
        int tagLen = rawData[offset + cursor] & 0xFF;
        cursor++; /* tag len */
        this.tag = new String(rawData, offset + cursor, tagLen);
        cursor+=tagLen;

        /* Read value */
        this.value = new String(rawData, offset + cursor, length - cursor);
    }

    private DnsRDataCaa(Builder builder) {
        if (builder == null || builder.tag == null || builder.value == null) {
            StringBuilder sb = new StringBuilder();
            sb.append("builder: ").append(builder)
            .append(" builder.tag: ").append(builder.tag)
            .append(" builder.value: ").append(builder.value);
            throw new NullPointerException(sb.toString());
        }

        if (builder.flag > 255 || builder.flag < 0) {
            StringBuilder sb = new StringBuilder();
            sb.append("Invalid value for flag: ").append(builder.flag);
            throw new IllegalArgumentException(sb.toString());
        }

        this.flag = builder.flag;

        /* TODO: validate if tag follows rfc rules.

         Tag values MAY contain US-ASCII characters 'a' through 'z', 'A'
         through 'Z', and the numbers 0 through 9.  Tag values SHOULD NOT
         contain any other characters.  Matching of tag values is case
         insensitive.

         Tag values submitted for registration by IANA MUST NOT contain any
         characters other than the (lowercase) US-ASCII characters 'a'
         through 'z' and the numbers 0 through 9.
         */
        this.tag = builder.tag;
        this.value = builder.value;
    }

    @Override
    public int length() {
        return 1 /* flag */ + 1 /* tag len */ + tag.length() +
               + value.length();
    }

    @Override
    public byte[] getRawData() {
        int len = this.length();
        byte rawData[] = new byte[len];

        rawData[0] = (byte) this.flag;
        rawData[1] = (byte) this.tag.length();
        int cursor = 2;

        System.arraycopy(this.tag.getBytes(), 0, rawData, cursor, this.tag.length());
        cursor += this.tag.length();

        System.arraycopy(this.value.getBytes(), 0, rawData, cursor, this.value.length());

        return rawData;
    }

    /**
     * @return a new Builder object populated with this object's fields.
     */
    public Builder getBuilder() { return new Builder(this); }


    @Override
    public String toString(String indent) {

        String ls = System.getProperty("line.separator");

        StringBuilder sb = new StringBuilder();
        sb.append(indent).append("CAA RDATA:").append(ls);
        sb.append(indent);
        sb.append("  CAA: ");
        sb.append(this.flag);
        sb.append(" ");
        sb.append(this.tag);
        sb.append(" ");
        sb.append(this.value);
        sb.append(ls);

        return sb.toString();
    }

    @Override
    public String toString() {
      return toString("");
    }

    @Override
    public String toString(String indent, byte[] headerRawData) {
        // TODO Auto-generated method stub.
        // I don't know where this is called with headerRawData
        return toString(indent);
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + flag;
        result = prime * result + ((tag == null) ? 0 : tag.hashCode());
        result = prime * result + ((value == null) ? 0 : value.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        DnsRDataCaa other = (DnsRDataCaa) obj;
        if (flag != other.flag)
            return false;
        if (tag == null) {
            if (other.tag != null)
                return false;
        } else if (!tag.equals(other.tag))
            return false;
        if (value == null) {
            if (other.value != null)
                return false;
        } else if (!value.equals(other.value))
            return false;
        return true;
    }

    /**
     * @author Paulo Pacheco
     * @since pcap4j 1.7.2
     */
    public static final class Builder {

        private int flag;
        private String tag;
        private String value;

        public Builder() { flag = 0; }

        private Builder(DnsRDataCaa obj) {
            this.flag = obj.flag;
            this.tag = obj.tag;
            this.value = obj.value;
        }

        /**
         * @param flaf flag
         * @return this Builder object for method chaining.
         */
        public Builder flag(int flag) {
            this.flag = flag;
            return this;
        }

        /**
         * @param flaf flag
         * @return this Builder object for method chaining.
         */
        public Builder flag(byte flag) {
            this.flag = flag & 0xFF;
            return this;
        }

        /**
         * @param tag tag
         * @return this Builder object for method chaining.
         */
        public Builder tag(String tag) {
            this.tag = tag;
            return this;
        }

        /**
         * @param value value
         * @return this Builder object for method chaining.
         */
        public Builder value(String value) {
            this.value = value;
            return this;
        }

        /**
         * @return a new DnsRDataCaa object.
         */
        public DnsRDataCaa build() {
            return new DnsRDataCaa(this);
        }
    }
}
