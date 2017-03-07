/*_##########################################################################
  _##
  _##  Copyright (C) 2016  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory;

import java.io.ObjectStreamException;

import org.pcap4j.packet.IllegalRadiotapData;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.RadiotapPacket.RadiotapData;
import org.pcap4j.packet.namednumber.RadiotapPresentBitNumber;

/**
 * @author Kaito Yamada
 * @since pcap4j 1.6.5
 */
public final class
PropertiesBasedRadiotapDataFactory
extends AbstractPropertiesBasedFactory<RadiotapData, RadiotapPresentBitNumber> {

  private static final PropertiesBasedRadiotapDataFactory INSTANCE
    = new PropertiesBasedRadiotapDataFactory();

  private PropertiesBasedRadiotapDataFactory() {}

  /**
   *
   * @return the singleton instance of PropertiesBasedRadiotapDataFactory.
   */
  public static PropertiesBasedRadiotapDataFactory getInstance() {
    return INSTANCE;
  }

  @Override
  protected Class<? extends RadiotapData> getTargetClass(RadiotapPresentBitNumber num) {
    return PacketFactoryPropertiesLoader.getInstance().getRadiotapDataFieldClass(num);
  }

  @Override
  protected Class<? extends RadiotapData> getUnknownClass() {
    return PacketFactoryPropertiesLoader.getInstance().getUnknownRadiotapDataFieldClass();
  }

  @Override
  protected String getStaticFactoryMethodName() {
    return "newInstance";
  }

  @Override
  protected RadiotapData newIllegalData(
    byte[] rawData, int offset, int length, IllegalRawDataException cause
  ) {
    return IllegalRadiotapData.newInstance(rawData, offset, length, cause);
  }

}
