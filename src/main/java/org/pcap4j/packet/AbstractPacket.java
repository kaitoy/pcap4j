/*_##########################################################################
  _##
  _##  Copyright (C) 2011-2012  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import java.util.Arrays;
import java.util.Iterator;
import java.util.List;

import org.pcap4j.util.ByteArrays;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.1
 */
public abstract class AbstractPacket implements Packet {

  private volatile Boolean valid = null;
  private final Object validLock = new Object();
  private volatile Integer length = null;
  private final Object lengthLock = new Object();
  private volatile byte[] rawData = null;
  private final Object rawDataLock = new Object();
  private volatile String hexString = null;
  private final Object hexStringLock = new Object();
  private volatile String string = null;
  private final Object stringLock = new Object();
  private volatile Integer hashCode = null;
  private final Object hashCodeLock = new Object();

  public Header getHeader() { return null; }

  public Packet getPayload() { return null; }

  /**
   *
   * @return
   */
  protected boolean verify() {
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

  public boolean isValid() {
    Boolean result = valid;
    if (result == null) {
      synchronized (validLock) {
        result = valid;
        if (result == null) {
          valid = result = verify();
        }
      }
    }
    return result.booleanValue();
  }

  /**
   *
   * @return
   */
  protected int measureLength() {
    int length = 0;

    if (getHeader() != null) {
      length += getHeader().length();
    }
    if (getPayload() != null) {
      length += getPayload().length();
    }

    return length;
  }

  public int length() {
    Integer result = length;
    if (result == null) {
      synchronized (lengthLock) {
        result = length;
        if (result == null) {
          length = result = measureLength();
        }
      }
    }
    return result.intValue();
  }

  /**
   *
   * @return
   */
  protected byte[] buildRawData() {
    byte[] rd = new byte[length()];
    Header header = getHeader();
    Packet payload = getPayload();

    int dstPos = 0;
    if (header != null) {
      System.arraycopy(
        getHeader().getRawData(), 0, rd, 0, header.length()
      );
      dstPos += header.length();
    }
    if (payload != null) {
      System.arraycopy(
        getPayload().getRawData(), 0, rd, dstPos, payload.length()
      );
      dstPos += payload.length();
    }

    return rd;
  }

  public byte[] getRawData() {
    byte[] result = rawData;
    if (result == null) {
      synchronized (rawDataLock) {
        result = rawData;
        if (result == null) {
          rawData = result = buildRawData();
        }
      }
    }

    byte[] copy = new byte[result.length];
    System.arraycopy(result, 0, copy, 0, copy.length);
    return copy;
  }

  public Iterator<Packet> iterator() {
    return new PacketIterator(this);
  }

  public <T extends Packet> T get(Class<T> clazz) {
    for (Packet next: this) {
      if (clazz.isInstance(next)) {
        return clazz.cast(next);
      }
    }
    return null;
  }

  public <T extends Packet> boolean contains(Class<T> clazz) {
    return get(clazz) != null;
  }

  public abstract Builder getBuilder();

  /**
   *
   * @return
   */
  protected String buildHexString() {
    return ByteArrays.toHexString(getRawData(), ":");
  }

  /**
   *
   * @return
   */
 public String toHexString() {
   String result = hexString;
   if (result == null) {
     synchronized (hexStringLock) {
       result = hexString;
       if (result == null) {
         hexString = result = buildHexString();
       }
     }
   }
   return result;
 }

 /**
  *
  * @return
  */
  protected String buildString() {
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
  public String toString() {
    String result = string;
    if (result == null) {
      synchronized (stringLock) {
        result = string;
        if (result == null) {
          string = result = buildString();
        }
      }
    }
    return result;
  }

  @Override
  public boolean equals(Object obj) {
    if (obj == this) {
      return true;
    }
    if (!obj.getClass().getName().equals(getClass().getName())) {
      return false;
    }
    return (getClass().cast(obj)).getRawData().equals(getRawData());
  }

  /**
   *
   * @return
   */
  protected int calcHashCode() {
    return Arrays.hashCode(getRawData());
  }

  @Override
  public int hashCode() {
    Integer result = hashCode;
    if (result == null) {
      synchronized (hashCodeLock) {
        result = hashCode;
        if (result == null) {
          hashCode = result = calcHashCode();
        }
      }
    }
    return result.intValue();
  }

  /**
   *
   * @author Kaito Yamada
   * @version pcap4j 0.9.1
   */
  public abstract class AbstractHeader implements Header {

    private volatile Boolean valid = null;
    private final Object validLock = new Object();
    private volatile Integer length = null;
    private final Object lengthLock = new Object();
    private volatile byte[] rawData = null;
    private final Object rawDataLock = new Object();
    private volatile String hexString = null;
    private final Object hexStringLock = new Object();
    private volatile String string = null;
    private final Object stringLock = new Object();
    private volatile Integer hashCode = null;
    private final Object hashCodeLock = new Object();

    /**
     *
     * @return
     */
    protected boolean verify() { return true; }

    public boolean isValid() {
      Boolean result = valid;
      if (result == null) {
        synchronized (validLock) {
          result = valid;
          if (result == null) {
            valid = result = verify();
          }
        }
      }
      return result.booleanValue();
    }

    protected abstract List<byte[]> getRawFields();

    /**
     *
     * @return
     */
    protected int measureLength() {
      int length = 0;
      for (byte[] rawField: getRawFields()) {
        length += rawField.length;
      }
      return length;
    }

    public int length() {
      Integer result = length;
      if (result == null) {
        synchronized (lengthLock) {
          result = length;
          if (result == null) {
            length = result = measureLength();
          }
        }
      }
      return result.intValue();
    }

    /**
     *
     * @return
     */
    protected byte[] buildRawData() {
      List<byte[]> rawFields = getRawFields();

      int length = 0;
      for (byte[] rawField: rawFields) {
        length += rawField.length;
      }

      byte[] rawData = new byte[length];
      int destPos = 0;
      for (byte[] rawField: rawFields) {
        System.arraycopy(
          rawField, 0,
          rawData, destPos, rawField.length
        );
        destPos += rawField.length;
      }

      return rawData;
    }

    public byte[] getRawData() {
      byte[] result = rawData;
      if (result == null) {
        synchronized (rawDataLock) {
          result = rawData;
          if (result == null) {
            rawData = result = buildRawData();
          }
        }
      }

      byte[] copy = new byte[result.length];
      System.arraycopy(result, 0, copy, 0, copy.length);
      return copy;
    }

    /**
     *
     * @return
     */
    protected String buildHexString() {
      return ByteArrays.toHexString(getRawData(), ":");
    }

    /**
     *
     * @return
     */
    public String toHexString() {
      String result = hexString;
      if (result == null) {
        synchronized (hexStringLock) {
          result = hexString;
          if (result == null) {
            hexString = result = buildHexString();
          }
        }
      }
      return result;
    }

    /**
     *
     * @return
     */
    protected String buildString() {
      return toHexString();
    }

    @Override
    public String toString() {
      String result = string;
      if (result == null) {
        synchronized (stringLock) {
          result = string;
          if (result == null) {
            string = result = buildString();
          }
        }
      }
      return result;
    }

    @Override
    public boolean equals(Object obj) {
      if (obj == this) {
        return true;
      }
      if (obj.getClass().getName().equals(getClass().getName())) {
        return false;
      }
      return (getClass().cast(obj)).getRawData().equals(getRawData());
    }

    /**
     *
     * @return
     */
    protected int buildHashCode() {
      return Arrays.hashCode(getRawData());
    }

    @Override
    public int hashCode() {
      Integer result = hashCode;
      if (result == null) {
        synchronized (hashCodeLock) {
          result = hashCode;
          if (result == null) {
            hashCode = result = buildHashCode();
          }
        }
      }
      return result.intValue();
    }

  }

}
