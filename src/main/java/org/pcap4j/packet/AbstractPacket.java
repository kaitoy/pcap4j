/*_##########################################################################
  _##
  _##  Copyright (C) 2011  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import java.util.Arrays;
import java.util.Iterator;
import org.pcap4j.util.ByteArrays;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.1
 */
public abstract class AbstractPacket implements Packet {

  /**
   *
   * @return
   */
  public abstract Header getHeader();

  /**
   *
   * @return
   */
  public abstract Packet getPayload();

  /**
   *
   * @return
   */
  public boolean isValid() {
    if (getPayload() != null) {
      if (!getPayload().isValid()) {
        return false;
      }
    }

    if (getHeader() == null) {
      return false;
    }
    else {
      return getHeader().isValid();
    }
  }

  /**
   *
   * @return
   */
  public int length() {
    int length = 0;

    if (getHeader() != null) {
      length += getHeader().length();
    }
    if (getPayload() != null) {
      length += getPayload().length();
    }

    return length;
  }

  /**
   *
   * @return
   */
  public byte[] getRawData() {
    byte[] rawData = new byte[length()];
    Header header = getHeader();
    Packet payload = getPayload();

    int dstPos = 0;
    if (header != null) {
      System.arraycopy(
        getHeader().getRawData(), 0, rawData, 0, header.length()
      );
      dstPos += header.length();
    }
    if (payload != null) {
      System.arraycopy(
        getPayload().getRawData(), 0, rawData, dstPos, payload.length()
      );
      dstPos += payload.length();
    }

    return rawData;
  }

  /**
   *
   * @return
   */
  public Iterator<Packet> iterator() {
    return new PacketIterator(this);
  }

  /**
   *
   * @param packetClass
   * @return
   */
  public <T extends Packet> T get(Class<T> packetClass) {
    for (Packet next: this) {
      if (packetClass.isInstance(next)) {
        return packetClass.cast(next);
      }
    }
    return null;
  }

  /**
   *
   * @param packetClass
   * @return
   */
  public <T extends Packet> boolean contains(Class<T> packetClass) {
    return get(packetClass) != null;
  }

  /**
   *
   * @return
   */
  public String toHexString() {
    return ByteArrays.toHexString(getRawData(), ":");
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();

    if (getHeader() != null) {
      sb.append(getHeader().toString());
    }

    if (getPayload() != null) {
      sb.append(getPayload().toString());
    }

    return sb.toString();
  }

  @Override
  public boolean equals(Object obj) {
    if (obj == this) {
      return true;
    }
    if (!obj.getClass().getName().equals(getClass().getName())) {
      return false;
    }
    return (getClass().cast(obj)).toHexString().equals(toHexString());
  }

  @Override
  public int hashCode() {
    return Arrays.hashCode(getRawData());
  }

  /**
   *
   * @author Kaito Yamada
   * @version pcap4j 0.9.1
   */
  public abstract class AbstractHeader implements Header {

    /**
     *
     * @return
     */
    public boolean isValid() { return true; }

    /**
     *
     * @return
     */
    public int length() { return getRawData().length; }

    /**
     *
     * @return
     */
    public abstract byte[] getRawData();

    /**
     *
     * @return
     */
    public String toHexString() {
      return ByteArrays.toHexString(getRawData(), ":");
    }

    @Override
    public String toString() {
      return toHexString();
    }

    @Override
    public boolean equals(Object obj) {
      if (obj == this) {
        return true;
      }
      if (!obj.getClass().getName().equals(getClass().getName())) {
        return false;
      }
      return (getClass().cast(obj)).toHexString().equals(toHexString());
    }

    @Override
    public int hashCode() {
      return Arrays.hashCode(getRawData());
    }

  }

}
