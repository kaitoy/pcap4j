/*_##########################################################################
  _##
  _##  Copyright (C) 2016-2017  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory;

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

  /**
   * This method is a variant of {@link #newInstance(byte[], int, int, SctpChunkType...)}
   * and exists only for performance reason.
   *
   * @param rawData see {@link PacketFactory#newInstance}.
   * @param offset see {@link PacketFactory#newInstance}.
   * @param length see {@link PacketFactory#newInstance}.
   * @return see {@link PacketFactory#newInstance}.
   */
  public SctpChunk newInstance(byte[] rawData, int offset, int length) {
    try {
      return UnknownSctpChunk.newInstance(rawData, offset, length);
    } catch (IllegalRawDataException e) {
      return IllegalSctpChunk.newInstance(rawData, offset, length, e);
    }
  }

  /**
   * This method is a variant of {@link #newInstance(byte[], int, int, SctpChunkType...)}
   * and exists only for performance reason.
   *
   * @param rawData see {@link PacketFactory#newInstance}.
   * @param offset see {@link PacketFactory#newInstance}.
   * @param length see {@link PacketFactory#newInstance}.
   * @param number see {@link PacketFactory#newInstance}.
   * @return see {@link PacketFactory#newInstance}.
   */
  public SctpChunk newInstance(byte[] rawData, int offset, int length, SctpChunkType number) {
    try {
//      switch (Byte.toUnsignedInt(number.value())) {
//        case 0:
//          return SctpChunkPayloadData.newInstance(rawData, offset, length);
//      }
      return UnknownSctpChunk.newInstance(rawData, offset, length);
    } catch (IllegalRawDataException e) {
      return IllegalSctpChunk.newInstance(rawData, offset, length, e);
    }
  }

  /**
   * This method is a variant of {@link #newInstance(byte[], int, int, SctpChunkType...)}
   * and exists only for performance reason.
   *
   * @param rawData see {@link PacketFactory#newInstance}.
   * @param offset see {@link PacketFactory#newInstance}.
   * @param length see {@link PacketFactory#newInstance}.
   * @param number1 see {@link PacketFactory#newInstance}.
   * @param number2 see {@link PacketFactory#newInstance}.
   * @return see {@link PacketFactory#newInstance}.
   */
  public SctpChunk newInstance(
    byte[] rawData, int offset, int length, SctpChunkType number1, SctpChunkType number2
  ) {
    try {
//      switch (Byte.toUnsignedInt(number1.value())) {
//        case 0:
//          return SctpChunkPayloadData.newInstance(rawData, offset, length);
//      }
//
//      switch (Byte.toUnsignedInt(number2.value())) {
//        case 0:
//          return SctpChunkPayloadData.newInstance(rawData, offset, length);
//      }
      return UnknownSctpChunk.newInstance(rawData, offset, length);
    } catch (IllegalRawDataException e) {
      return IllegalSctpChunk.newInstance(rawData, offset, length, e);
    }
  }

  @Override
  public SctpChunk newInstance(byte[] rawData, int offset, int length, SctpChunkType... numbers) {
    try {
//      for (SctpChunkType num: numbers) {
//        switch (Byte.toUnsignedInt(num.value())) {
//          case 0:
//            return SctpChunkPayloadData.newInstance(rawData, offset, length);
//        }
//      }
      return UnknownSctpChunk.newInstance(rawData, offset, length);
    } catch (IllegalRawDataException e) {
      return IllegalSctpChunk.newInstance(rawData, offset, length, e);
    }
  }

}
