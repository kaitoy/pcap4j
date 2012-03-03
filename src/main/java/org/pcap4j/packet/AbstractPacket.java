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
import org.pcap4j.util.LazyValue;
import org.pcap4j.util.LazyValue.BuildValueCommand;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.1
 */
public abstract class AbstractPacket implements Packet {

  /**
   *
   */
  private static final long serialVersionUID = -3016622134481071576L;

  private final LazyValue<Boolean> validCache;
  private final LazyValue<Integer> lengthCache;
  private final LazyValue<byte[]> rawDataCache;
  private final LazyValue<String> hexStringCache;
  private final LazyValue<String> stringCache;
  private final LazyValue<Integer> hashCodeCache;

  public AbstractPacket() {
    this.validCache
      = new LazyValue<Boolean>(
          new BuildValueCommand<Boolean>() {
            public Boolean buildValue() {
              return verify();
            }
          }
        );
    this.lengthCache
    = new LazyValue<Integer>(
        new BuildValueCommand<Integer>() {
          public Integer buildValue() {
            return measureLength();
          }
        }
      );
    this.rawDataCache
      = new LazyValue<byte[]>(
          new BuildValueCommand<byte[]>() {
            public byte[] buildValue() {
              return buildRawData();
            }
          }
        );
    this.hexStringCache
      = new LazyValue<String>(
          new BuildValueCommand<String>() {
            public String buildValue() {
              return buildHexString();
            }
          }
        );
    this.stringCache
      = new LazyValue<String>(
          new BuildValueCommand<String>() {
            public String buildValue() {
              return buildString();
            }
          }
        );
    this.hashCodeCache
      = new LazyValue<Integer>(
          new BuildValueCommand<Integer>() {
            public Integer buildValue() {
              return calcHashCode();
            }
          }
        );
  }

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
    return validCache.getValue();
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
    return lengthCache.getValue();
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
    byte[] rawData = rawDataCache.getValue();

    byte[] copy = new byte[rawData.length];
    System.arraycopy(rawData, 0, copy, 0, copy.length);
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
   return hexStringCache.getValue();
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
    return stringCache.getValue();
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
    return hashCodeCache.getValue();
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

    private final LazyValue<Boolean> validCache;
    private final LazyValue<Integer> lengthCache;
    private final LazyValue<byte[]> rawDataCache;
    private final LazyValue<String> hexStringCache;
    private final LazyValue<String> stringCache;
    private final LazyValue<Integer> hashCodeCache;

    public AbstractHeader() {
      this.validCache
        = new LazyValue<Boolean>(
            new BuildValueCommand<Boolean>() {
              public Boolean buildValue() {
                return verify();
              }
            }
          );
      this.lengthCache
        = new LazyValue<Integer>(
            new BuildValueCommand<Integer>() {
              public Integer buildValue() {
                return measureLength();
              }
            }
          );
      this.rawDataCache
        = new LazyValue<byte[]>(
            new BuildValueCommand<byte[]>() {
              public byte[] buildValue() {
                return buildRawData();
              }
            }
          );
      this.hexStringCache
        = new LazyValue<String>(
            new BuildValueCommand<String>() {
              public String buildValue() {
                return buildHexString();
              }
            }
          );
      this.stringCache
        = new LazyValue<String>(
            new BuildValueCommand<String>() {
              public String buildValue() {
                return buildString();
              }
            }
          );
      this.hashCodeCache
        = new LazyValue<Integer>(
            new BuildValueCommand<Integer>() {
              public Integer buildValue() {
                return calcHashCode();
              }
            }
          );
    }

    /**
     *
     * @return
     */
    protected boolean verify() { return true; }

    public boolean isValid() {
      return validCache.getValue();
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
      return lengthCache.getValue();
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
      byte[] rawData = rawDataCache.getValue();

      byte[] copy = new byte[rawData.length];
      System.arraycopy(rawData, 0, copy, 0, copy.length);
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
      return hexStringCache.getValue();
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
      return stringCache.getValue();
    }

    @Override
    public boolean equals(Object obj) {
      if (obj == this) { return true; }
      if (!this.getClass().isInstance(obj)) { return false; }
      return Arrays.equals(getClass().cast(obj).getRawData(), getRawData());
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
      return hashCodeCache.getValue();
    }

  }

}
