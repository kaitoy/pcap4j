/*_##########################################################################
  _##
  _##  Copyright (C) 2011-2019 Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import java.io.Serializable;

/**
 * The interface representing a packet which consists of a header and a payload. If you use {@link
 * org.pcap4j.packet.factory.propertiesbased.PropertiesBasedPacketFactory
 * PropertiesBasedPacketFactory}, classes which implement this interface must implement the
 * following method: {@code public static Packet newPacket(byte[] rawData, int offset, int length)
 * throws IllegalRawDataException}
 *
 * @author Kaito Yamada
 * @since pcap4j 0.9.1
 */
public interface Packet extends Iterable<Packet>, Serializable {

  /**
   * Returns the Header object representing this packet's header.
   *
   * @return the Header object representing this packet's header. May be null if the header doesn't
   *     exist
   */
  public Header getHeader();

  /**
   * Returns the Packet object representing this packet's payload.
   *
   * @return the Packet object representing this packet's payload. May be null if the payload
   *     doesn't exist
   */
  public Packet getPayload();

  /**
   * Returns the packet length in bytes.
   *
   * @return the length of the byte stream of the packet represented by this object in bytes
   */
  public int length();

  /**
   * Returns this packet's raw data.
   *
   * @return this packet's raw data, namely the byte stream which is actually sent through real
   *     network
   */
  public byte[] getRawData();

  /**
   * Traverses this packet and its payload to find an object of the specified packet class and
   * returns the object. If there are more than one objects of the specified class in this object,
   * this method returns the most outer one of them.
   *
   * @param <T> packet
   * @param clazz the packet class of the object to get
   * @return a packet object if found; otherwise null
   */
  public <T extends Packet> T get(Class<T> clazz);

  /**
   * Returns the outer packet object of a packet object {@link #get get(clazz)} returns.
   *
   * @param clazz the packet class of the object whose outer packet object is what you want to get
   * @return a packet object if found; otherwise null
   */
  public Packet getOuterOf(Class<? extends Packet> clazz);

  /**
   * Returns true if this packet is or its payload includes an object of specified packet class;
   * false otherwise.
   *
   * @param <T> packet
   * @param clazz the packet class of the object to search for
   * @return true if this packet is or its payload includes an object of specified packet class;
   *     false otherwise
   */
  public <T extends Packet> boolean contains(Class<T> clazz);

  /**
   * Returns a new Builder object populated with this object's fields' values.
   *
   * @return a new Builder object populated with this object's fields values
   */
  public Builder getBuilder();

  /**
   * This interface is designed to be implemented by builder classes for packet objects.
   *
   * @author Kaito Yamada
   * @since pcap4j 0.9.1
   */
  public interface Builder extends Iterable<Builder> {

    /**
     * Traverses this builder and its payload builder to find an object of the specified builder
     * class and returns the object. If there are more than one objects of the specified class in
     * this object, this method returns the most outer one of them.
     *
     * @param <T> builder
     * @param clazz the builder class of the object to get
     * @return a builder object if found; otherwise null
     */
    public <T extends Builder> T get(Class<T> clazz);

    /**
     * Returns the outer builder object of a builder object {@link #get get(clazz)} returns.
     *
     * @param clazz the builder class of the object whose outer builder object is what you want to
     *     get
     * @return a builder object if found; otherwise null
     */
    public Builder getOuterOf(Class<? extends Builder> clazz);

    /**
     * Set the payload builder.
     *
     * @param payloadBuilder a Builder object to set
     * @return this Builder object for method chaining
     */
    public Builder payloadBuilder(Builder payloadBuilder);

    /**
     * Get the payload builder of this object.
     *
     * @return the payload builder of this object
     */
    public Builder getPayloadBuilder();

    /**
     * Build a packet object using values set to this object.
     *
     * @return a new Packet object
     */
    public Packet build();
  }

  /**
   * The interface representing a packet's header.
   *
   * @author Kaito Yamada
   * @since pcap4j 0.9.1
   */
  public interface Header extends Serializable {

    /**
     * Returns the header length in bytes.
     *
     * @return the length of the byte stream of the header represented by this object in bytes
     */
    public int length();

    /**
     * Returns the raw data of this packet's header.
     *
     * @return the raw data of this packet's header, namely a piece of the byte stream which is
     *     actually sent through real network
     */
    public byte[] getRawData();
  }
}
