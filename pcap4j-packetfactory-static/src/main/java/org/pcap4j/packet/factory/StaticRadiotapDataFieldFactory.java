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
import org.pcap4j.packet.namednumber.RadiotapPresentBitNumber;

/**
 * @author Kaito Yamada
 * @since pcap4j 1.6.5
 */
public final class StaticRadiotapDataFieldFactory
implements PacketFactory<RadiotapData, RadiotapPresentBitNumber> {

  private static final StaticRadiotapDataFieldFactory INSTANCE
    = new StaticRadiotapDataFieldFactory();

  private StaticRadiotapDataFieldFactory() {}

  /**
   * @return the singleton instance of StaticRadiotapDataFieldFactory.
   */
  public static StaticRadiotapDataFieldFactory getInstance() {
    return INSTANCE;
  }

  @Override
  public RadiotapData newInstance(
    byte[] rawData, int offset, int length, RadiotapPresentBitNumber... numbers
  ) {
    if (rawData == null) {
      throw new NullPointerException("rawData is null.");
    }

    try {
      for (RadiotapPresentBitNumber num: numbers) {
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

  // Override deserializer to keep singleton
  @SuppressWarnings("static-method")
  private Object readResolve() throws ObjectStreamException {
    return INSTANCE;
  }

}
