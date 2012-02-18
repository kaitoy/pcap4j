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
import org.pcap4j.util.ValueCache;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.1
 */
public abstract class AbstractPacket implements Packet {

  /**
   *
   */
  private static final long serialVersionUID = -3016622134481071576L;

  private final ValueCache<Boolean> validCache = new ValueCache<Boolean>();
  private final ValueCache<Integer> lengthCache = new ValueCache<Integer>();
  private final ValueCache<byte[]> rawDataCache = new ValueCache<byte[]>();
  private final ValueCache<String> hexStringCache = new ValueCache<String>();
  private final ValueCache<String> stringCache = new ValueCache<String>();
  private final ValueCache<Integer> hashCodeCache = new ValueCache<Integer>();

  //public static Packet newPacket(byte[] rawData); /* necessary */

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
    Boolean result = validCache.getValue();
    if (result == null) {
      synchronized (validCache) {
        result = validCache.getValue();
        if (result == null) {
          result = verify();
          validCache.setValue(result);
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
    Integer result = lengthCache.getValue();
    if (result == null) {
      synchronized (lengthCache) {
        result = lengthCache.getValue();
        if (result == null) {
          result = measureLength();
          lengthCache.setValue(result);
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
    byte[] result = rawDataCache.getValue();
    if (result == null) {
      synchronized (rawDataCache) {
        result = rawDataCache.getValue();
        if (result == null) {
          result = buildRawData();
          rawDataCache.setValue(result);
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
   String result = hexStringCache.getValue();
   if (result == null) {
     synchronized (hexStringCache) {
       result = hexStringCache.getValue();
       if (result == null) {
         result = buildHexString();
         hexStringCache.setValue(result);
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
    String result = stringCache.getValue();
    if (result == null) {
      synchronized (stringCache) {
        result = stringCache.getValue();
        if (result == null) {
          result = buildString();
          stringCache.setValue(result);
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
    Integer result = hashCodeCache.getValue();
    if (result == null) {
      synchronized (hashCodeCache) {
        result = hashCodeCache.getValue();
        if (result == null) {
          result = calcHashCode();
          hashCodeCache.setValue(result);
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

    /**
     *
     */
    private static final long serialVersionUID = -8916517326403680608L;

    // caches
    private final ValueCache<Boolean> validCache = new ValueCache<Boolean>();
    private final ValueCache<Integer> lengthCache = new ValueCache<Integer>();
    private final ValueCache<byte[]> rawDataCache = new ValueCache<byte[]>();
    private final ValueCache<String> hexStringCache = new ValueCache<String>();
    private final ValueCache<String> stringCache = new ValueCache<String>();
    private final ValueCache<Integer> hashCodeCache = new ValueCache<Integer>();

    /**
     *
     * @return
     */
    protected boolean verify() { return true; }

    public boolean isValid() {
      Boolean result = validCache.getValue();
      if (result == null) {
        synchronized (validCache) {
          result = validCache.getValue();
          if (result == null) {
            result = verify();
            validCache.setValue(result);
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
      Integer result = lengthCache.getValue();
      if (result == null) {
        synchronized (lengthCache) {
          result = lengthCache.getValue();
          if (result == null) {
            result = measureLength();
            lengthCache.setValue(result);
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
      byte[] result = rawDataCache.getValue();
      if (result == null) {
        synchronized (rawDataCache) {
          result = rawDataCache.getValue();
          if (result == null) {
            result = buildRawData();
            rawDataCache.setValue(result);
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
      String result = hexStringCache.getValue();
      if (result == null) {
        synchronized (hexStringCache) {
          result = hexStringCache.getValue();
          if (result == null) {
            result = buildHexString();
            hexStringCache.setValue(result);
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
      String result = stringCache.getValue();
      if (result == null) {
        synchronized (stringCache) {
          result = stringCache.getValue();
          if (result == null) {
            result = buildString();
            stringCache.setValue(result);
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
      Integer result = hashCodeCache.getValue();
      if (result == null) {
        synchronized (hashCodeCache) {
          result = hashCodeCache.getValue();
          if (result == null) {
            result = buildHashCode();
            hashCodeCache.setValue(result);
          }
        }
      }
      return result.intValue();
    }

  }

}
