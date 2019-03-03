/*_##########################################################################
  _##
  _##  Copyright (C) 2016-2019 Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory.statik;

import java.util.HashMap;
import java.util.Map;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.IllegalSctpChunk;
import org.pcap4j.packet.SctpPacket.SctpChunk;
import org.pcap4j.packet.UnknownSctpChunk;
import org.pcap4j.packet.factory.PacketFactory;
import org.pcap4j.packet.namednumber.SctpChunkType;

/**
 * @author Kaito Yamada
 * @since pcap4j 1.6.6
 */
public final class StaticSctpChunkFactory implements PacketFactory<SctpChunk, SctpChunkType> {

  private static final StaticSctpChunkFactory INSTANCE = new StaticSctpChunkFactory();
  private final Map<SctpChunkType, Instantiater> instantiaters =
      new HashMap<SctpChunkType, Instantiater>();

  private StaticSctpChunkFactory() {
    //    instantiaters.put(
    //      SctpChunkType.DATA, new Instantiater() {
    //        @Override
    //        public SctpChunk newInstance(
    //          byte[] rawData, int offset, int length
    //        ) throws IllegalRawDataException {
    //          return SctpChunkPayloadData.newInstance(rawData, offset, length);
    //        }
    //        @Override
    //        public Class<SctpChunkPayloadData> getTargetClass() {
    //          return SctpChunkPayloadData.class;
    //        }
    //      }
    //    );
  }

  /** @return the singleton instance of StaticSctpChunkFactory. */
  public static StaticSctpChunkFactory getInstance() {
    return INSTANCE;
  }

  @Override
  public SctpChunk newInstance(byte[] rawData, int offset, int length, SctpChunkType number) {
    if (rawData == null || number == null) {
      StringBuilder sb = new StringBuilder(40);
      sb.append("rawData: ").append(rawData).append(" number: ").append(number);
      throw new NullPointerException(sb.toString());
    }

    try {
      Instantiater instantiater = instantiaters.get(number);
      if (instantiater != null) {
        return instantiater.newInstance(rawData, offset, length);
      }
    } catch (IllegalRawDataException e) {
      return IllegalSctpChunk.newInstance(rawData, offset, length);
    }

    return newInstance(rawData, offset, length);
  }

  @Override
  public SctpChunk newInstance(byte[] rawData, int offset, int length) {
    try {
      return UnknownSctpChunk.newInstance(rawData, offset, length);
    } catch (IllegalRawDataException e) {
      return IllegalSctpChunk.newInstance(rawData, offset, length);
    }
  }

  @Override
  public Class<? extends SctpChunk> getTargetClass(SctpChunkType number) {
    if (number == null) {
      throw new NullPointerException("number must not be null.");
    }
    Instantiater instantiater = instantiaters.get(number);
    return instantiater != null ? instantiater.getTargetClass() : getTargetClass();
  }

  @Override
  public Class<? extends SctpChunk> getTargetClass() {
    return UnknownSctpChunk.class;
  }

  private static interface Instantiater {

    public SctpChunk newInstance(byte[] rawData, int offset, int length)
        throws IllegalRawDataException;

    public Class<? extends SctpChunk> getTargetClass();
  }
}
