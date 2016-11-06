/*_##########################################################################
  _##
  _##  Copyright (C) 2016  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory;

import java.io.ObjectStreamException;

import org.pcap4j.packet.IllegalSctpChunk;
import org.pcap4j.packet.SctpPacket.SctpChunk;
import org.pcap4j.packet.namednumber.SctpChunkType;

/**
 * @author Kaito Yamada
 * @since pcap4j 1.6.6
 */
public final class PropertiesBasedSctpChunkFactory
extends AbstractPropertiesBasedFactory<SctpChunk, SctpChunkType> {

  private static final PropertiesBasedSctpChunkFactory INSTANCE
    = new PropertiesBasedSctpChunkFactory();

  private PropertiesBasedSctpChunkFactory() {}

  /**
   * @return the singleton instance of PropertiesBasedSctpChunkFactory.
   */
  public static PropertiesBasedSctpChunkFactory getInstance() { return INSTANCE; }

  @Override
  protected Class<? extends SctpChunk> getTargetClass(SctpChunkType number) {
    return PacketFactoryPropertiesLoader.getInstance().getSctpChunkClass(number);
  }

  @Override
  protected Class<? extends SctpChunk> getUnknownClass() {
    return PacketFactoryPropertiesLoader.getInstance().getUnknownSctpChunkClass();
  }

  @Override
  protected String getStaticFactoryMethodName() {
    return "newInstance";
  }

  @Override
  protected SctpChunk newIllegalData(byte[] rawData, int offset, int length) {
    return IllegalSctpChunk.newInstance(rawData, offset, length);
  }

  // Override deserializer to keep singleton
  @SuppressWarnings("static-method")
  private Object readResolve() throws ObjectStreamException {
    return INSTANCE;
  }

}
