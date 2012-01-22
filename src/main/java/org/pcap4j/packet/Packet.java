/*_##########################################################################
  _##
  _##  Copyright (C) 2011  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.1
 */
public interface Packet extends Iterable<Packet> {

  // public Packet(byte[] rawData); /* mandatory */

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
  public <T extends Packet> boolean contains(Class<T> clazz);

}
