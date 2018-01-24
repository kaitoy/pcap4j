/*_##########################################################################
  _##
  _##  Copyright (C) 2016  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

/**
 * A class implementing this interface is instantiated when a dissection of packet's raw data
 * fails due to an IllegalRawDataException.
 *
 * @author Kaito Yamada
 * @since pcap4j 2.0.0
 */
public interface IllegalRawDataHolder {

  /**
   * @return illegal raw data
   */
  public byte[] getRawData();

  /**
   * @return an IllegalRawDataException which caused this to be instantiated.
   */
  public IllegalRawDataException getCause();

}
