/*_##########################################################################
  _##
  _##  Copyright (C) 2011-2012  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import java.io.Serializable;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.1
 */
public interface Packet extends Iterable<Packet>, Serializable {

  // /* must implement if use PropertiesBasedPacketFactory */
  // public static Packet newPacket(byte[] rawData);

  /**
   *
   * @return Header
   */
  public Header getHeader();

  /**
   *
   * @return payload
   */
  public Packet getPayload();

  /**
   *
   * @return length
   */
  public int length();

  /**
   *
   * @return raw data
   */
  public byte[] getRawData();

  /**
   *
   * @param clazz
   * @return packet
   */
  public <T extends Packet> T get(Class<T> clazz);

  /**
   *
   * @param clazz
   * @return packet
   */
  public Packet getOuterOf(Class<? extends Packet> clazz);

  /**
   *
   * @param clazz
   * @return true if the packet represented by this object includes a packet
   *         represented by specified class; false otherwise.
   */
  public <T extends Packet> boolean contains(Class<T> clazz);

  /**
   *
   * @return a new Builder object populated with this object's fields.
   */
  public Builder getBuilder();

  /**
   * @author Kaito Yamada
   * @since pcap4j 0.9.1
   */
  public interface Builder extends Iterable<Builder> {

    /**
     *
     * @param clazz
     * @return this Builder object for method chaining.
     */
    public <T extends Builder> T get(Class<T> clazz);

    /**
     *
     * @param clazz
     * @return this Builder object for method chaining.
     */
    public Builder getOuterOf(Class<? extends Builder> clazz);

    /**
     *
     * @param payloadBuilder
     * @return this Builder object for method chaining.
     */
    public Builder payloadBuilder(Builder payloadBuilder);

    /**
     *
     * @return this Builder object for method chaining.
     */
    public Builder getPayloadBuilder();

    /**
     *
     * @return a new Packet object.
     */
    public Packet build();

  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 0.9.1
   */
  public interface Header extends Serializable {

    /**
     *
     * @return length
     */
    public int length();

    /**
     *
     * @return raw data
     */
    public byte[] getRawData();

  }

}
