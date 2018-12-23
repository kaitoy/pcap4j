/*_##########################################################################
  _##
  _##  Copyright (C) 2014  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import org.pcap4j.util.ByteArrays;

/**
 * @author Kaito Yamada
 * @since pcap4j 1.0.1
 */
public final class Ssh2NameList implements Serializable {

  /*
   * http://www.ietf.org/rfc/rfc4251.txt
   *
   * A string containing a comma-separated list of names.  A name-list
   * is represented as a uint32 containing its length (number of bytes
   * that follow) followed by a comma-separated list of zero or more
   * names.  A name MUST have a non-zero length, and it MUST NOT
   * contain a comma (",").  As this is a list of names, all of the
   * elements contained are names and MUST be in US-ASCII.
   * Terminating null characters MUST NOT be used, neither
   * for the individual names, nor for the list as a whole.
   */

  /** */
  private static final long serialVersionUID = 8625201821104360377L;

  private final int length;
  private final List<String> list;

  /** @param list list */
  public Ssh2NameList(List<String> list) {
    if (list == null) {
      throw new NullPointerException("list may not be null");
    }

    this.list = new ArrayList<String>(list);
    this.length = calcLength();
  }

  /** @param names names */
  public Ssh2NameList(String... names) {
    this.list = new ArrayList<String>();
    for (String name : names) {
      list.add(name);
    }
    this.length = calcLength();
  }

  /**
   * Constructor. This method validates the arguments by {@link ByteArrays#validateBounds(byte[],
   * int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public Ssh2NameList(byte[] rawData, int offset, int length) throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);

    if (length < 4) {
      StringBuilder sb = new StringBuilder(100);
      sb.append("The rawData length must be more than 3. rawData: ")
          .append(ByteArrays.toHexString(rawData, " "))
          .append(", offset: ")
          .append(offset)
          .append(", length: ")
          .append(length);
      throw new IllegalRawDataException(sb.toString());
    }

    this.length = ByteArrays.getInt(rawData, offset);
    if (this.length < 0) {
      StringBuilder sb = new StringBuilder(120);
      sb.append(
              "A name-list the length of which is longer than 2147483647 is not supported. length: ")
          .append(this.length & 0xFFFFFFFFL);
      throw new IllegalRawDataException(sb.toString());
    }
    if (length - 4 < this.length) {
      StringBuilder sb = new StringBuilder(110);
      sb.append("The data is too short to build an Ssh2NameList (")
          .append(this.length + 4)
          .append(" bytes). data: ")
          .append(ByteArrays.toHexString(rawData, " "))
          .append(", offset: ")
          .append(offset)
          .append(", length: ")
          .append(length);
      throw new IllegalRawDataException(sb.toString());
    }

    String nameList = new String(rawData, 4 + offset, this.length);
    this.list = Arrays.asList(nameList.split(","));
  }

  private int calcLength() {
    int len = 0;
    Iterator<String> iter = list.iterator();
    while (iter.hasNext()) {
      String name = iter.next();
      len += name.length();
      if (iter.hasNext()) {
        len++;
      }
    }

    return len;
  }

  /** @return value of the length field */
  public int getLength() {
    return length;
  }

  /** @return list */
  public List<String> getList() {
    return new ArrayList<String>(list);
  }

  /** @return length */
  public int length() {
    return getRawData().length;
  }

  /** @return rawData */
  public byte[] getRawData() {
    String csv = toString();
    byte[] rawData = new byte[csv.length() + 4];
    System.arraycopy(ByteArrays.toByteArray(length), 0, rawData, 0, ByteArrays.INT_SIZE_IN_BYTES);
    System.arraycopy(csv.getBytes(), 0, rawData, 4, csv.length());

    return rawData;
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder(length);
    Iterator<String> iter = list.iterator();
    while (iter.hasNext()) {
      String name = iter.next();
      sb.append(name);
      if (iter.hasNext()) {
        sb.append(",");
      }
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

    Ssh2NameList other = (Ssh2NameList) obj;
    return length == other.length && list.equals(other.list);
  }

  @Override
  public int hashCode() {
    int result = 17;
    result = 31 * result + length;
    result = 31 * result + list.hashCode();
    return result;
  }
}
