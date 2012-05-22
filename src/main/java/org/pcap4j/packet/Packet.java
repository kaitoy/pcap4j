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

  // public static Packet newPacket(byte[] rawData); /* necessary */

  /**
   *
   * @return
   */
  public Header getHeader();

  /**
   *
   * @return
   */
  public Packet getPayload();

  /**
   *
   * @return
   */
  public boolean isValid();

  /**
   *
   * @return
   */
  public int length();

  /**
   *
   * @return
   */
  public byte[] getRawData();

  /**
   *
   * @param clazz
   * @return
   */
  public <T extends Packet> T get(Class<T> clazz);

  /**
   *
   * @param clazz
   * @return
   */
  public Packet getOuterOf(Class<? extends Packet> clazz);

  /**
   *
   * @param clazz
   * @return
   */
  public <T extends Packet> boolean contains(Class<T> clazz);

  /**
   *
   * @return
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
     * @return
     */
    public <T extends Builder> T get(Class<T> clazz);

    /**
     *
     * @param clazz
     * @return
     */
    public Builder getOuterOf(Class<? extends Builder> clazz);

    /**
     * setter
     */
    public Builder payloadBuilder(Builder payloadBuilder);

    /**
     *
     * @return
     */
    public Builder getPayloadBuilder();

    /**
     *
     * @return
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
     * @return
     */
    public boolean isValid();

    /**
     *
     * @return
     */
    public int length();

    /**
     *
     * @return
     */
    public byte[] getRawData();

  }

}
