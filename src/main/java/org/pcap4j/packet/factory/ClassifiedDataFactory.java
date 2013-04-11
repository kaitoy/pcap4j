/*_##########################################################################
  _##
  _##  Copyright (C) 2012 Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory;

import org.pcap4j.packet.namednumber.NamedNumber;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.11
 */
public interface ClassifiedDataFactory <T, N extends NamedNumber<?>>{

  // /* must implement. called by ClassifiedDataFactories. */
  // public static ClassifiedDataFactory getInstance();

  /**
   *
   * @param rawData
   * @param number
   * @return
   */
  public T newData(byte[] rawData, N number);

  /**
   *
   * @param rawData
   * @return
   */
  public T newData(byte[] rawData);

}
