/*_##########################################################################
  _##
  _##  Copyright (C) 2011-2019 Pcap4J.org
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
 * Abstract immutable packet class. If you use {@link
 * org.pcap4j.packet.factory.propertiesbased.PropertiesBasedPacketFactory
 * PropertiesBasedPacketFactory}, this subclass must implement the following method: {@code public
 * static Packet newPacket(byte[] rawData, int offset, int length) throws IllegalRawDataException}
 *
 * @author Kaito Yamada
 * @since pcap4j 0.9.1
 */
public abstract class AbstractPacket implements Packet {

  /** */
  private static final long serialVersionUID = -3016622134481071576L;

  private final LazyValue<Integer> lengthCache;
  private final LazyValue<byte[]> rawDataCache;
  private final LazyValue<String> hexStringCache;
  private final LazyValue<String> stringCache;
  private final LazyValue<Integer> hashCodeCache;

  /** */
  public AbstractPacket() {
    this.lengthCache =
        new LazyValue<Integer>(
            new BuildValueCommand<Integer>() {
              @Override
              public Integer buildValue() {
                return calcLength();
              }
            });
    this.rawDataCache =
        new LazyValue<byte[]>(
            new BuildValueCommand<byte[]>() {
              @Override
              public byte[] buildValue() {
                return buildRawData();
              }
            });
    this.hexStringCache =
        new LazyValue<String>(
            new BuildValueCommand<String>() {
              @Override
              public String buildValue() {
                return buildHexString();
              }
            });
    this.stringCache =
        new LazyValue<String>(
            new BuildValueCommand<String>() {
              @Override
              public String buildValue() {
                return buildString();
              }
            });
    this.hashCodeCache =
        new LazyValue<Integer>(
            new BuildValueCommand<Integer>() {
              @Override
              public Integer buildValue() {
                return calcHashCode();
              }
            });
  }

  /**
   * Returns the Header object representing this packet's header. This subclass have to override
   * this method if the packet represented by the subclass has a header.
   */
  @Override
  public Header getHeader() {
    return null;
  }

  /**
   * Returns the Packet object representing this packet's payload. This subclass have to override
   * this method if the packet represented by the subclass has a payload.
   */
  @Override
  public Packet getPayload() {
    return null;
  }

  /**
   * This method calculates the value {@link #length length()} will return by adding up the header
   * length and the payload length. If you write this subclass which represents a packet with extra
   * parts (e.g. a trailer), you need to override this method.
   *
   * @return a calculated length
   */
  protected int calcLength() {
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
   * Returns the packet length in bytes. This method calls {@link #calcLength calcLength()} and
   * caches the return value when it is called for the first time, and then, this method returns the
   * cached value from the second time.
   */
  @Override
  public int length() {
    return lengthCache.getValue();
  }

  /**
   * This method builds the value {@link #getRawData getRawData()} will return by concatenating the
   * header's raw data and the payload's raw data. If you write this subclass which represents a
   * packet with extra parts (e.g. a trailer), you need to override this method.
   *
   * @return a raw data built
   */
  protected byte[] buildRawData() {
    byte[] rd = new byte[length()];
    Header header = getHeader();
    Packet payload = getPayload();

    int dstPos = 0;
    if (header != null) {
      System.arraycopy(getHeader().getRawData(), 0, rd, 0, header.length());
      dstPos += header.length();
    }
    if (payload != null) {
      System.arraycopy(getPayload().getRawData(), 0, rd, dstPos, payload.length());
      dstPos += payload.length();
    }

    return rd;
  }

  /**
   * Returns this packet's raw data. This method calls {@link #buildRawData buildRawData()} and
   * caches the return value when it is called for the first time, and then, this method returns the
   * cached value from the second time. More correctly, this method returns a copy of the cached
   * value, so that the cache can't be changed.
   */
  @Override
  public byte[] getRawData() {
    byte[] rawData = rawDataCache.getValue();

    byte[] copy = new byte[rawData.length];
    System.arraycopy(rawData, 0, copy, 0, copy.length);
    return copy;
  }

  @Override
  public Iterator<Packet> iterator() {
    return new PacketIterator(this);
  }

  @Override
  public <T extends Packet> T get(Class<T> clazz) {
    for (Packet p : this) {
      if (clazz.isInstance(p)) {
        return clazz.cast(p);
      }
    }
    return null;
  }

  @Override
  public Packet getOuterOf(Class<? extends Packet> clazz) {
    for (Packet p : this) {
      if (clazz.isInstance(p.getPayload())) {
        return p;
      }
    }
    return null;
  }

  @Override
  public <T extends Packet> boolean contains(Class<T> clazz) {
    return get(clazz) != null;
  }

  @Override
  public abstract Builder getBuilder();

  /**
   * This method builds the value {@link #toHexString toHexString()} will return using the return
   * value of {@link #getRawData getRawData()}. Each octet in this return value is separated by a
   * white space. (e.g. 00 01 02 03 aa bb cc)
   *
   * @return a hex string representation of this object
   */
  protected String buildHexString() {
    return ByteArrays.toHexString(getRawData(), " ");
  }

  /**
   * Returns the hex string representation of this object. This method calls {@link #buildHexString
   * buildHexString()} and caches the return value when it is called for the first time, and then,
   * this method returns the cached value from the second time.
   *
   * @return a hex string representation of this object
   */
  public String toHexString() {
    return hexStringCache.getValue();
  }

  /**
   * This method builds the value {@link #toString toString()} will return by concatenating the
   * header's string representation and the payload's string representation. If you write this
   * subclass which represents a packet with extra parts (e.g. a trailer), you need to override this
   * method.
   *
   * @return a string representation of this object
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

  /**
   * Returns a string representation of the object. This method calls {@link #buildString
   * buildString()} and caches the return value when it is called for the first time, and then, this
   * method returns the cached value from the second time.
   */
  @Override
  public String toString() {
    return stringCache.getValue();
  }

  /**
   * Indicates whether some other object is "equal to" this one. This method firstly compares this
   * packet's header using the header's equals(Object) method, then compares this packet's payload
   * using the payload's equals(Object) method. If you write this subclass with fields which
   * represent somethings other than header or payload, you need to override this method.
   */
  @Override
  public boolean equals(Object obj) {
    if (obj == this) {
      return true;
    }
    if (!this.getClass().isInstance(obj)) {
      return false;
    }

    Packet other = (Packet) obj;

    if (this.getHeader() == null || other.getHeader() == null) {
      if (!(this.getHeader() == null && other.getHeader() == null)) {
        return false;
      }
    } else {
      if (!this.getHeader().equals(other.getHeader())) {
        return false;
      }
    }

    if (this.getPayload() == null || other.getPayload() == null) {
      if (!(this.getPayload() == null && other.getPayload() == null)) {
        return false;
      } else {
        return true;
      }
    } else {
      return this.getPayload().equals(other.getPayload());
    }
  }

  /**
   * This method calculates the value {@link #hashCode hashCode()} will return using the header's
   * hash code and the payload's hash code. If you write this subclass which represents a packet
   * with extra parts (e.g. a trailer), you need to override this method.
   *
   * @return a calculated hash code value for the object
   */
  protected int calcHashCode() {
    int result = 17;
    if (getHeader() != null) {
      result = 31 * result + getHeader().hashCode();
    }
    if (getPayload() != null) {
      result = 31 * result + getPayload().hashCode();
    }
    return result;
  }

  /**
   * Returns a hash code value for the object. This method calls {@link #calcHashCode
   * calcHashCode()} and caches the return value when it is called for the first time, and then,
   * this method returns the cached value from the second time.
   */
  @Override
  public int hashCode() {
    return hashCodeCache.getValue();
  }

  /**
   * Abstract packet builder class.
   *
   * @author Kaito Yamada
   * @version pcap4j 0.9.9
   */
  public abstract static class AbstractBuilder implements Builder {

    @Override
    public Iterator<Builder> iterator() {
      return new BuilderIterator(this);
    }

    @Override
    public <T extends Builder> T get(Class<T> clazz) {
      for (Builder b : this) {
        if (clazz.isInstance(b)) {
          return clazz.cast(b);
        }
      }
      return null;
    }

    @Override
    public Builder getOuterOf(Class<? extends Builder> clazz) {
      for (Builder b : this) {
        if (clazz.isInstance(b.getPayloadBuilder())) {
          return b;
        }
      }
      return null;
    }

    @Override
    public AbstractBuilder payloadBuilder(Builder payloadBuilder) {
      throw new UnsupportedOperationException();
    }

    @Override
    public Builder getPayloadBuilder() {
      return null;
    }

    @Override
    public abstract Packet build();
  }

  /**
   * Abstract immutable header class.
   *
   * @author Kaito Yamada
   * @version pcap4j 0.9.1
   */
  public abstract static class AbstractHeader implements Header {

    /** */
    private static final long serialVersionUID = -8916517326403680608L;

    private final LazyValue<Integer> lengthCache;
    private final LazyValue<byte[]> rawDataCache;
    private final LazyValue<String> hexStringCache;
    private final LazyValue<String> stringCache;
    private final LazyValue<Integer> hashCodeCache;

    /** */
    protected AbstractHeader() {
      this.lengthCache =
          new LazyValue<Integer>(
              new BuildValueCommand<Integer>() {
                @Override
                public Integer buildValue() {
                  return calcLength();
                }
              });
      this.rawDataCache =
          new LazyValue<byte[]>(
              new BuildValueCommand<byte[]>() {
                @Override
                public byte[] buildValue() {
                  return buildRawData();
                }
              });
      this.hexStringCache =
          new LazyValue<String>(
              new BuildValueCommand<String>() {
                @Override
                public String buildValue() {
                  return buildHexString();
                }
              });
      this.stringCache =
          new LazyValue<String>(
              new BuildValueCommand<String>() {
                @Override
                public String buildValue() {
                  return buildString();
                }
              });
      this.hashCodeCache =
          new LazyValue<Integer>(
              new BuildValueCommand<Integer>() {
                @Override
                public Integer buildValue() {
                  return calcHashCode();
                }
              });
    }

    /**
     * Returns a list of byte arrays which represents this header's fields. This method is called by
     * {@link #calcLength calcLength()} and {@link #buildRawData buildRawData()}.
     *
     * @return a list of byte arrays which represents this header's fields
     */
    protected abstract List<byte[]> getRawFields();

    /**
     * This method calculates the value {@link #length length()} will return by adding up the
     * lengths of byte arrays in the list {@link #getRawFields getRawFields()} returns.
     *
     * @return a calculated length
     */
    protected int calcLength() {
      int length = 0;
      for (byte[] rawField : getRawFields()) {
        length += rawField.length;
      }
      return length;
    }

    /**
     * Returns the header length in bytes. This method calls {@link #calcLength calcLength()} and
     * caches the return value when it is called for the first time, and then, this method returns
     * the cached value from the second time.
     */
    @Override
    public int length() {
      return lengthCache.getValue();
    }

    /**
     * This method builds the value {@link #getRawData getRawData()} will return by concatenating
     * the byte arrays in the list {@link #getRawFields getRawFields()} returns.
     *
     * @return a raw data built
     */
    protected byte[] buildRawData() {
      return ByteArrays.concatenate(getRawFields());
    }

    /**
     * Returns this header's raw data. This method calls {@link #buildRawData buildRawData()} and
     * caches the return value when it is called for the first time, and then, this method returns
     * the cached value from the second time. More correctly, this method returns a copy of the
     * cached value, so that the cache can't be changed.
     */
    @Override
    public byte[] getRawData() {
      byte[] rawData = rawDataCache.getValue();

      byte[] copy = new byte[rawData.length];
      System.arraycopy(rawData, 0, copy, 0, copy.length);
      return copy;
    }

    /**
     * This method builds the value {@link #toHexString toHexString()} will return using the return
     * value of {@link #getRawData getRawData()}. Each octet in this return value is separated by a
     * white space. (e.g. 00 01 02 03 aa bb cc)
     *
     * @return a hex string representation of this object
     */
    protected String buildHexString() {
      return ByteArrays.toHexString(getRawData(), " ");
    }

    /**
     * Returns the hex string representation of this object. This method calls {@link
     * #buildHexString buildHexString()} and caches the return value when it is called for the first
     * time, and then, this method returns the cached value from the second time.
     *
     * @return a hex string representation of this object
     */
    public String toHexString() {
      return hexStringCache.getValue();
    }

    /**
     * This method builds the value {@link #toString toString()} will return.
     *
     * @return a string representation of this object
     */
    protected String buildString() {
      StringBuilder sb = new StringBuilder();
      String ls = System.getProperty("line.separator");

      sb.append("[A header (").append(length()).append(" bytes)]").append(ls);
      sb.append("  Hex stream: ").append(ByteArrays.toHexString(getRawData(), " ")).append(ls);

      return sb.toString();
    }

    /**
     * Returns a string representation of the object. This method calls {@link #buildString
     * buildString()} and caches the return value when it is called for the first time, and then,
     * this method returns the cached value from the second time.
     */
    @Override
    public String toString() {
      return stringCache.getValue();
    }

    /**
     * Indicates whether some other object is "equal to" this one using return values of {@link
     * #getRawData getRawData()}. This method should be overridden so that it does more strict
     * comparisons more efficiently.
     */
    @Override
    public boolean equals(Object obj) {
      if (obj == this) {
        return true;
      }
      if (!this.getClass().isInstance(obj)) {
        return false;
      }
      return Arrays.equals(getClass().cast(obj).getRawData(), getRawData());
    }

    /**
     * This method builds the value {@link #hashCode hashCode()} will return using the byte array
     * {@link #getRawData getRawData()} returns. This method may be better to be overridden for
     * performance reason.
     *
     * @return a calculated hash code value for the object
     */
    protected int calcHashCode() {
      return Arrays.hashCode(getRawData());
    }

    /**
     * Returns a hash code value for the object. This method calls {@link #calcHashCode
     * calcHashCode()} and caches the return value when it is called for the first time, and then,
     * this method returns the cached value from the second time.
     */
    @Override
    public int hashCode() {
      return hashCodeCache.getValue();
    }
  }
}
