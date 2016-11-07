/*_##########################################################################
  _##
  _##  Copyright (C) 2012-2016  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory;

import java.io.ObjectStreamException;

import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.IllegalTcpOption;
import org.pcap4j.packet.TcpPacket.TcpOption;
import org.pcap4j.packet.namednumber.TcpOptionKind;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.14
 */
public final class
PropertiesBasedTcpOptionFactory
extends AbstractPropertiesBasedFactory<TcpOption, TcpOptionKind> {

  private static final PropertiesBasedTcpOptionFactory INSTANCE
    = new PropertiesBasedTcpOptionFactory();

  private PropertiesBasedTcpOptionFactory() {}

  /**
   * @return the singleton instance of PropertiesBasedTcpOptionFactory.
   */
  public static PropertiesBasedTcpOptionFactory getInstance() { return INSTANCE; }

  @Override
  protected Class<? extends TcpOption> getTargetClass(TcpOptionKind number) {
    return PacketFactoryPropertiesLoader.getInstance().getTcpOptionClass(number);
  }

  @Override
  protected Class<? extends TcpOption> getUnknownClass() {
    return PacketFactoryPropertiesLoader.getInstance().getUnknownTcpOptionClass();
  }

  @Override
  protected String getStaticFactoryMethodName() {
    return "newInstance";
  }

  @Override
  protected TcpOption newIllegalData(
    byte[] rawData, int offset, int length, IllegalRawDataException cause
  ) {
    return IllegalTcpOption.newInstance(rawData, offset, length, cause);
  }

  // Override deserializer to keep singleton
  @SuppressWarnings("static-method")
  private Object readResolve() throws ObjectStreamException {
    return INSTANCE;
  }

}
