/*_##########################################################################
  _##
  _##  Copyright (C) 2014  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.util;

import java.io.Serializable;
import java.util.Arrays;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * @author Kaito Yamada
 * @since pcap4j 1.0.1
 */
public class LinkLayerAddress implements Serializable {

  /** */
  private static final long serialVersionUID = -2832879271594305200L;

  /** */
  protected static final Pattern HEX_SEPARATOR_PATTERN = Pattern.compile("([^0-9a-fA-F])");

  private final byte[] address;

  /** @param address address */
  protected LinkLayerAddress(byte[] address) {
    this.address = address;
  }

  /**
   * @param address address
   * @return a new LinkLayerAddress object.
   */
  public static LinkLayerAddress getByAddress(byte[] address) {
    return new LinkLayerAddress(ByteArrays.clone(address));
  }

  /**
   * @param name name
   * @return a new LinkLayerAddress object.
   */
  public static LinkLayerAddress getByName(String name) {
    Matcher m = HEX_SEPARATOR_PATTERN.matcher(name);
    m.find();
    return getByName(name, m.group(1));
  }

  /**
   * @param name name
   * @param separator separator
   * @return a new LinkLayerAddress object.
   */
  public static LinkLayerAddress getByName(String name, String separator) {
    return getByAddress(ByteArrays.parseByteArray(name, separator));
  }

  /** @return address */
  public byte[] getAddress() {
    return ByteArrays.clone(address);
  }

  /** @return length */
  public int length() {
    return address.length;
  }

  @Override
  public String toString() {
    return ByteArrays.toHexString(address, ":");
  }

  @Override
  public boolean equals(Object obj) {
    if (obj == this) {
      return true;
    }
    if (!(obj instanceof LinkLayerAddress)) {
      return false;
    }
    return Arrays.equals(((LinkLayerAddress) obj).getAddress(), address);
  }

  @Override
  public int hashCode() {
    return Arrays.hashCode(address);
  }
}
