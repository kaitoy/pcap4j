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

public abstract class AbstractPacket implements Packet {

  public abstract Header getHeader();

  public void setHeader() {
    throw new UnsupportedOperationException();
  }

  public abstract Packet getPayload();
  public abstract void setPayload(Packet payload);

  public void validate() {
    if (getPayload() != null) {
      getPayload().validate();
    }
    if (getHeader() != null) {
      getHeader().validate();
    }
  }

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

  public Iterator<Packet> iterator() {
    return new PacketIterator(this);
  }

  public <T extends Packet> T get(Class<T> packetClass) {
    for (Packet next: this) {
      if (packetClass.isInstance(next)) {
        return packetClass.cast(next);
      }
    }
    return null;
  }

  public <T extends Packet> boolean contains(Class<T> packetClass) {
    return get(packetClass) != null;
  }

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

  public abstract class AbstractHeader implements Header {

    public void validate() {}

    public boolean isValid() { return true; }

    public int length() { return getRawData().length; }

    public abstract byte[] getRawData();

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
