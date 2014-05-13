/*_##########################################################################
  _##
  _##  Copyright (C) 2014  Kaito Yamada
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

  /**
   *
   */
  private static final long serialVersionUID = 8625201821104360377L;

  private final int length;
  private final List<String> list;

  /**
   *
   * @param list
   */
  public Ssh2NameList(List<String> list) {
    if (list == null) {
      throw new NullPointerException("list may not be null");
    }

    this.list = new ArrayList<String>(list);
    this.length = calcLength();
  }

  /**
   *
   * @param names
   */
  public Ssh2NameList(String... names) {
    this.list = new ArrayList<String>();
    for (String name: names) {
      list.add(name);
    }
    this.length = calcLength();
  }

  /**
   *
   * @param rawData
   * @throws IllegalRawDataException
   * @throws NullPointerException if the rawData argument is null.
   * @throws IllegalArgumentException if the rawData argument is empty.
   */
  public Ssh2NameList(byte[] rawData) throws IllegalRawDataException {
    if (rawData == null) {
      throw new NullPointerException("rawData must not be null.");
    }
    if (rawData.length == 0) {
      throw new IllegalArgumentException("rawData is empty.");
    }

    if (rawData.length < 4) {
      StringBuilder sb = new StringBuilder(100);
      sb.append("The rawData length must be more than 3. rawData: ")
        .append(ByteArrays.toHexString(rawData, " "));
      throw new IllegalRawDataException(sb.toString());
    }

    this.length = ByteArrays.getInt(rawData, 0);
    if (length < 0) {
      StringBuilder sb = new StringBuilder(120);
      sb.append("A name-list the length of which is longer than 2147483647 is not supported. length: ")
        .append(length & 0xFFFFFFFFL);
      throw new IllegalRawDataException(sb.toString());
    }

    String nameList = new String(ByteArrays.getSubArray(rawData, 4, length));
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

  /**
   *
   * @return value of the length field
   */
  public int getLength() {
    return length;
  }

  /**
   *
   * @return list
   */
  public List<String> getList() {
    return new ArrayList<String>(list);
  }

  /**
   *
   * @return length
   */
  public int length() {
    return getRawData().length;
  }

  /**
   *
   * @return rawData
   */
  public byte[] getRawData() {
    String csv = toString();
    byte[] rawData = new byte[csv.length() + 4];
    System.arraycopy(
      ByteArrays.toByteArray(length), 0,
      rawData, 0, ByteArrays.INT_SIZE_IN_BYTES
    );
    System.arraycopy(
      csv.getBytes(), 0,
      rawData, 4, csv.length()
    );

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

}
