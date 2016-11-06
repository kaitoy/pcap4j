/*_##########################################################################
  _##
  _##  Copyright (C) 2012-2016  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory;

import java.io.ObjectStreamException;

import org.pcap4j.packet.IllegalPacket;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.namednumber.NamedNumber;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.14
 */
public final class PropertiesBasedPacketFactory
extends AbstractPropertiesBasedFactory<Packet, NamedNumber<?, ?>> {

  private static final PropertiesBasedPacketFactory INSTANCE = new PropertiesBasedPacketFactory();

  private PropertiesBasedPacketFactory() {};

  /**
   * @return the singleton instance of PropertiesBasedPacketFactory.
   */
  public static PropertiesBasedPacketFactory getInstance() { return INSTANCE; }

  @Override
  protected Class<? extends Packet> getTargetClass(NamedNumber<?, ?> number) {
    return PacketFactoryPropertiesLoader.getInstance().getPacketClass(number);
  }

  @Override
  protected Class<? extends Packet> getUnknownClass() {
    return PacketFactoryPropertiesLoader.getInstance().getUnknownPacketClass();
  }

  @Override
  protected String getStaticFactoryMethodName() {
    return "newPacket";
  }

  @Override
  protected Packet newIllegalData(byte[] rawData, int offset, int length) {
    return IllegalPacket.newPacket(rawData, offset, length);
  }

  // Override deserializer to keep singleton
  @SuppressWarnings("static-method")
  private Object readResolve() throws ObjectStreamException {
    return INSTANCE;
  }

}
