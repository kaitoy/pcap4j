/*_##########################################################################
  _##
  _##  Copyright (C) 2011-2014  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.util;

import java.util.regex.Matcher;
import org.pcap4j.packet.namednumber.Oui;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.1
 */
public final class MacAddress extends LinkLayerAddress {

  /** */
  private static final long serialVersionUID = -8222662646993989547L;

  /** */
  public static final MacAddress ETHER_BROADCAST_ADDRESS =
      MacAddress.getByAddress(
          new byte[] {(byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255});

  /** */
  public static final int SIZE_IN_BYTES = 6;

  private MacAddress(byte[] address) {
    super(address);
  }

  /**
   * @param address address
   * @return a new MacAddress object.
   */
  public static MacAddress getByAddress(byte[] address) {
    if (address.length != SIZE_IN_BYTES) {
      throw new IllegalArgumentException(
          ByteArrays.toHexString(address, ":")
              + " is invalid for address. The length must be "
              + SIZE_IN_BYTES);
    }
    return new MacAddress(ByteArrays.clone(address));
  }

  /**
   * @param name name
   * @return a new MacAddress object.
   */
  public static MacAddress getByName(String name) {
    Matcher m = HEX_SEPARATOR_PATTERN.matcher(name);
    m.find();
    return getByName(name, m.group(1));
  }

  /**
   * @param name name
   * @param separator separator
   * @return a new MacAddress object.
   */
  public static MacAddress getByName(String name, String separator) {
    return getByAddress(ByteArrays.parseByteArray(name, separator));
  }

  /** @return OUI */
  public Oui getOui() {
    return Oui.getInstance(ByteArrays.getInt(getAddress(), 0) >>> 8);
  }

  /**
   * @return true if the MAC address represented by this object is a unicast address; otherwise
   *     false.
   */
  public boolean isUnicast() {
    return (getAddress()[0] & 1) == 0;
  }

  /**
   * @return true if the MAC address represented by this object is a globally unique address;
   *     otherwise false.
   */
  public boolean isGloballyUnique() {
    return (getAddress()[0] & 2) == 0;
  }
}
