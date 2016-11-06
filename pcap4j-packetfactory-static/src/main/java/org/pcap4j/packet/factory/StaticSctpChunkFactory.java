/*_##########################################################################
  _##
  _##  Copyright (C) 2016  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory;

import java.io.ObjectStreamException;

import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.IllegalSctpChunk;
import org.pcap4j.packet.SctpPacket.SctpChunk;
import org.pcap4j.packet.UnknownSctpChunk;
import org.pcap4j.packet.namednumber.SctpChunkType;

/**
 * @author Kaito Yamada
 * @since pcap4j 1.6.6
 */
public final class StaticSctpChunkFactory implements PacketFactory<SctpChunk, SctpChunkType> {

  private static final StaticSctpChunkFactory INSTANCE = new StaticSctpChunkFactory();

  private StaticSctpChunkFactory() {}

  /**
   *
   * @return the singleton instance of StaticSctpChunkFactory.
   */
  public static StaticSctpChunkFactory getInstance() {
    return INSTANCE;
  }

  @Override
  public SctpChunk newInstance(byte[] rawData, int offset, int length, SctpChunkType... numbers) {
    if (rawData == null) {
      throw new NullPointerException("rawData is null.");
    }

    try {
//      for (SctpChunkType num: numbers) {
//        switch (Byte.toUnsignedInt(num.value())) {
//          case 0:
//            return SctpChunkPayloadData.newInstance(rawData, offset, length);
//        }
//      }
      return UnknownSctpChunk.newInstance(rawData, offset, length);
    } catch (IllegalRawDataException e) {
      return IllegalSctpChunk.newInstance(rawData, offset, length);
    }
  }

  // Override deserializer to keep singleton
  @SuppressWarnings("static-method")
  private Object readResolve() throws ObjectStreamException {
    return INSTANCE;
  }

}
