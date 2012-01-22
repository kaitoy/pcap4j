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
public interface Header {

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
   * @return
   */
  public String toHexString();

}
