/*_##########################################################################
  _##
  _##  Copyright (C) 2016-2019 Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory.statik;

import org.pcap4j.packet.IllegalRadiotapData;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.RadiotapDataAMpduStatus;
import org.pcap4j.packet.RadiotapDataAntenna;
import org.pcap4j.packet.RadiotapDataAntennaNoise;
import org.pcap4j.packet.RadiotapDataAntennaSignal;
import org.pcap4j.packet.RadiotapDataChannel;
import org.pcap4j.packet.RadiotapDataDbAntennaNoise;
import org.pcap4j.packet.RadiotapDataDbAntennaSignal;
import org.pcap4j.packet.RadiotapDataDbTxAttenuation;
import org.pcap4j.packet.RadiotapDataDbmTxPower;
import org.pcap4j.packet.RadiotapDataFhss;
import org.pcap4j.packet.RadiotapDataFlags;
import org.pcap4j.packet.RadiotapDataLockQuality;
import org.pcap4j.packet.RadiotapDataMcs;
import org.pcap4j.packet.RadiotapDataRate;
import org.pcap4j.packet.RadiotapDataRxFlags;
import org.pcap4j.packet.RadiotapDataTsft;
import org.pcap4j.packet.RadiotapDataTxAttenuation;
import org.pcap4j.packet.RadiotapDataVht;
import org.pcap4j.packet.RadiotapPacket.RadiotapData;
import org.pcap4j.packet.UnknownRadiotapData;
import org.pcap4j.packet.factory.PacketFactory;
import org.pcap4j.packet.namednumber.RadiotapPresentBitNumber;

/**
 * @author Kaito Yamada
 * @since pcap4j 1.6.5
 */
public final class StaticRadiotapDataFieldFactory
    implements PacketFactory<RadiotapData, RadiotapPresentBitNumber> {

  private static final StaticRadiotapDataFieldFactory INSTANCE =
      new StaticRadiotapDataFieldFactory();

  private StaticRadiotapDataFieldFactory() {}

  /** @return the singleton instance of StaticRadiotapDataFieldFactory. */
  public static StaticRadiotapDataFieldFactory getInstance() {
    return INSTANCE;
  }

  /**
   * This method is a variant of {@link #newInstance(byte[], int, int, RadiotapPresentBitNumber...)}
   * and exists only for performance reason.
   *
   * @param rawData see {@link PacketFactory#newInstance}.
   * @param offset see {@link PacketFactory#newInstance}.
   * @param length see {@link PacketFactory#newInstance}.
   * @return see {@link PacketFactory#newInstance}.
   */
  public RadiotapData newInstance(byte[] rawData, int offset, int length) {
    return UnknownRadiotapData.newInstance(rawData, offset, length);
  }

  /**
   * This method is a variant of {@link #newInstance(byte[], int, int, RadiotapPresentBitNumber...)}
   * and exists only for performance reason.
   *
   * @param rawData see {@link PacketFactory#newInstance}.
   * @param offset see {@link PacketFactory#newInstance}.
   * @param length see {@link PacketFactory#newInstance}.
   * @param number see {@link PacketFactory#newInstance}.
   * @return see {@link PacketFactory#newInstance}.
   */
  public RadiotapData newInstance(
      byte[] rawData, int offset, int length, RadiotapPresentBitNumber number) {
    try {
      switch (number.value()) {
        case 0:
          return RadiotapDataTsft.newInstance(rawData, offset, length);
        case 1:
          return RadiotapDataFlags.newInstance(rawData, offset, length);
        case 2:
          return RadiotapDataRate.newInstance(rawData, offset, length);
        case 3:
          return RadiotapDataChannel.newInstance(rawData, offset, length);
        case 4:
          return RadiotapDataFhss.newInstance(rawData, offset, length);
        case 5:
          return RadiotapDataAntennaSignal.newInstance(rawData, offset, length);
        case 6:
          return RadiotapDataAntennaNoise.newInstance(rawData, offset, length);
        case 7:
          return RadiotapDataLockQuality.newInstance(rawData, offset, length);
        case 8:
          return RadiotapDataTxAttenuation.newInstance(rawData, offset, length);
        case 9:
          return RadiotapDataDbTxAttenuation.newInstance(rawData, offset, length);
        case 10:
          return RadiotapDataDbmTxPower.newInstance(rawData, offset, length);
        case 11:
          return RadiotapDataAntenna.newInstance(rawData, offset, length);
        case 12:
          return RadiotapDataDbAntennaSignal.newInstance(rawData, offset, length);
        case 13:
          return RadiotapDataDbAntennaNoise.newInstance(rawData, offset, length);
        case 14:
          return RadiotapDataRxFlags.newInstance(rawData, offset, length);
        case 19:
          return RadiotapDataMcs.newInstance(rawData, offset, length);
        case 20:
          return RadiotapDataAMpduStatus.newInstance(rawData, offset, length);
        case 21:
          return RadiotapDataVht.newInstance(rawData, offset, length);
      }
      return UnknownRadiotapData.newInstance(rawData, offset, length);
    } catch (IllegalRawDataException e) {
      return IllegalRadiotapData.newInstance(rawData, offset, length, e);
    }
  }

  /**
   * This method is a variant of {@link #newInstance(byte[], int, int, RadiotapPresentBitNumber...)}
   * and exists only for performance reason.
   *
   * @param rawData see {@link PacketFactory#newInstance}.
   * @param offset see {@link PacketFactory#newInstance}.
   * @param length see {@link PacketFactory#newInstance}.
   * @param number1 see {@link PacketFactory#newInstance}.
   * @param number2 see {@link PacketFactory#newInstance}.
   * @return see {@link PacketFactory#newInstance}.
   */
  public RadiotapData newInstance(
      byte[] rawData,
      int offset,
      int length,
      RadiotapPresentBitNumber number1,
      RadiotapPresentBitNumber number2) {
    try {
      switch (number1.value()) {
        case 0:
          return RadiotapDataTsft.newInstance(rawData, offset, length);
        case 1:
          return RadiotapDataFlags.newInstance(rawData, offset, length);
        case 2:
          return RadiotapDataRate.newInstance(rawData, offset, length);
        case 3:
          return RadiotapDataChannel.newInstance(rawData, offset, length);
        case 4:
          return RadiotapDataFhss.newInstance(rawData, offset, length);
        case 5:
          return RadiotapDataAntennaSignal.newInstance(rawData, offset, length);
        case 6:
          return RadiotapDataAntennaNoise.newInstance(rawData, offset, length);
        case 7:
          return RadiotapDataLockQuality.newInstance(rawData, offset, length);
        case 8:
          return RadiotapDataTxAttenuation.newInstance(rawData, offset, length);
        case 9:
          return RadiotapDataDbTxAttenuation.newInstance(rawData, offset, length);
        case 10:
          return RadiotapDataDbmTxPower.newInstance(rawData, offset, length);
        case 11:
          return RadiotapDataAntenna.newInstance(rawData, offset, length);
        case 12:
          return RadiotapDataDbAntennaSignal.newInstance(rawData, offset, length);
        case 13:
          return RadiotapDataDbAntennaNoise.newInstance(rawData, offset, length);
        case 14:
          return RadiotapDataRxFlags.newInstance(rawData, offset, length);
        case 19:
          return RadiotapDataMcs.newInstance(rawData, offset, length);
        case 20:
          return RadiotapDataAMpduStatus.newInstance(rawData, offset, length);
        case 21:
          return RadiotapDataVht.newInstance(rawData, offset, length);
      }

      switch (number2.value()) {
        case 0:
          return RadiotapDataTsft.newInstance(rawData, offset, length);
        case 1:
          return RadiotapDataFlags.newInstance(rawData, offset, length);
        case 2:
          return RadiotapDataRate.newInstance(rawData, offset, length);
        case 3:
          return RadiotapDataChannel.newInstance(rawData, offset, length);
        case 4:
          return RadiotapDataFhss.newInstance(rawData, offset, length);
        case 5:
          return RadiotapDataAntennaSignal.newInstance(rawData, offset, length);
        case 6:
          return RadiotapDataAntennaNoise.newInstance(rawData, offset, length);
        case 7:
          return RadiotapDataLockQuality.newInstance(rawData, offset, length);
        case 8:
          return RadiotapDataTxAttenuation.newInstance(rawData, offset, length);
        case 9:
          return RadiotapDataDbTxAttenuation.newInstance(rawData, offset, length);
        case 10:
          return RadiotapDataDbmTxPower.newInstance(rawData, offset, length);
        case 11:
          return RadiotapDataAntenna.newInstance(rawData, offset, length);
        case 12:
          return RadiotapDataDbAntennaSignal.newInstance(rawData, offset, length);
        case 13:
          return RadiotapDataDbAntennaNoise.newInstance(rawData, offset, length);
        case 14:
          return RadiotapDataRxFlags.newInstance(rawData, offset, length);
        case 19:
          return RadiotapDataMcs.newInstance(rawData, offset, length);
        case 20:
          return RadiotapDataAMpduStatus.newInstance(rawData, offset, length);
        case 21:
          return RadiotapDataVht.newInstance(rawData, offset, length);
      }
      return UnknownRadiotapData.newInstance(rawData, offset, length);
    } catch (IllegalRawDataException e) {
      return IllegalRadiotapData.newInstance(rawData, offset, length, e);
    }
  }

  @Override
  public RadiotapData newInstance(
      byte[] rawData, int offset, int length, RadiotapPresentBitNumber... numbers) {
    try {
      for (RadiotapPresentBitNumber num : numbers) {
        switch (num.value()) {
          case 0:
            return RadiotapDataTsft.newInstance(rawData, offset, length);
          case 1:
            return RadiotapDataFlags.newInstance(rawData, offset, length);
          case 2:
            return RadiotapDataRate.newInstance(rawData, offset, length);
          case 3:
            return RadiotapDataChannel.newInstance(rawData, offset, length);
          case 4:
            return RadiotapDataFhss.newInstance(rawData, offset, length);
          case 5:
            return RadiotapDataAntennaSignal.newInstance(rawData, offset, length);
          case 6:
            return RadiotapDataAntennaNoise.newInstance(rawData, offset, length);
          case 7:
            return RadiotapDataLockQuality.newInstance(rawData, offset, length);
          case 8:
            return RadiotapDataTxAttenuation.newInstance(rawData, offset, length);
          case 9:
            return RadiotapDataDbTxAttenuation.newInstance(rawData, offset, length);
          case 10:
            return RadiotapDataDbmTxPower.newInstance(rawData, offset, length);
          case 11:
            return RadiotapDataAntenna.newInstance(rawData, offset, length);
          case 12:
            return RadiotapDataDbAntennaSignal.newInstance(rawData, offset, length);
          case 13:
            return RadiotapDataDbAntennaNoise.newInstance(rawData, offset, length);
          case 14:
            return RadiotapDataRxFlags.newInstance(rawData, offset, length);
          case 19:
            return RadiotapDataMcs.newInstance(rawData, offset, length);
          case 20:
            return RadiotapDataAMpduStatus.newInstance(rawData, offset, length);
          case 21:
            return RadiotapDataVht.newInstance(rawData, offset, length);
        }
      }
      return UnknownRadiotapData.newInstance(rawData, offset, length);
    } catch (IllegalRawDataException e) {
      return IllegalRadiotapData.newInstance(rawData, offset, length, e);
    }
  }
}
