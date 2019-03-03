/*_##########################################################################
  _##
  _##  Copyright (C) 2016-2019 Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory.statik;

import java.util.HashMap;
import java.util.Map;
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
  private final Map<RadiotapPresentBitNumber, Instantiater> instantiaters =
      new HashMap<RadiotapPresentBitNumber, Instantiater>();

  private StaticRadiotapDataFieldFactory() {
    instantiaters.put(
        RadiotapPresentBitNumber.TSFT,
        new Instantiater() {
          @Override
          public RadiotapData newInstance(byte[] rawData, int offset, int length)
              throws IllegalRawDataException {
            return RadiotapDataTsft.newInstance(rawData, offset, length);
          }

          @Override
          public Class<RadiotapDataTsft> getTargetClass() {
            return RadiotapDataTsft.class;
          }
        });
    instantiaters.put(
        RadiotapPresentBitNumber.FLAGS,
        new Instantiater() {
          @Override
          public RadiotapData newInstance(byte[] rawData, int offset, int length)
              throws IllegalRawDataException {
            return RadiotapDataFlags.newInstance(rawData, offset, length);
          }

          @Override
          public Class<RadiotapDataFlags> getTargetClass() {
            return RadiotapDataFlags.class;
          }
        });
    instantiaters.put(
        RadiotapPresentBitNumber.RATE,
        new Instantiater() {
          @Override
          public RadiotapData newInstance(byte[] rawData, int offset, int length)
              throws IllegalRawDataException {
            return RadiotapDataRate.newInstance(rawData, offset, length);
          }

          @Override
          public Class<RadiotapDataRate> getTargetClass() {
            return RadiotapDataRate.class;
          }
        });
    instantiaters.put(
        RadiotapPresentBitNumber.CHANNEL,
        new Instantiater() {
          @Override
          public RadiotapData newInstance(byte[] rawData, int offset, int length)
              throws IllegalRawDataException {
            return RadiotapDataChannel.newInstance(rawData, offset, length);
          }

          @Override
          public Class<RadiotapDataChannel> getTargetClass() {
            return RadiotapDataChannel.class;
          }
        });
    instantiaters.put(
        RadiotapPresentBitNumber.FHSS,
        new Instantiater() {
          @Override
          public RadiotapData newInstance(byte[] rawData, int offset, int length)
              throws IllegalRawDataException {
            return RadiotapDataFhss.newInstance(rawData, offset, length);
          }

          @Override
          public Class<RadiotapDataFhss> getTargetClass() {
            return RadiotapDataFhss.class;
          }
        });
    instantiaters.put(
        RadiotapPresentBitNumber.ANTENNA_SIGNAL,
        new Instantiater() {
          @Override
          public RadiotapData newInstance(byte[] rawData, int offset, int length)
              throws IllegalRawDataException {
            return RadiotapDataAntennaSignal.newInstance(rawData, offset, length);
          }

          @Override
          public Class<RadiotapDataAntennaSignal> getTargetClass() {
            return RadiotapDataAntennaSignal.class;
          }
        });
    instantiaters.put(
        RadiotapPresentBitNumber.ANTENNA_NOISE,
        new Instantiater() {
          @Override
          public RadiotapData newInstance(byte[] rawData, int offset, int length)
              throws IllegalRawDataException {
            return RadiotapDataAntennaNoise.newInstance(rawData, offset, length);
          }

          @Override
          public Class<RadiotapDataAntennaNoise> getTargetClass() {
            return RadiotapDataAntennaNoise.class;
          }
        });
    instantiaters.put(
        RadiotapPresentBitNumber.LOCK_QUALITY,
        new Instantiater() {
          @Override
          public RadiotapData newInstance(byte[] rawData, int offset, int length)
              throws IllegalRawDataException {
            return RadiotapDataLockQuality.newInstance(rawData, offset, length);
          }

          @Override
          public Class<RadiotapDataLockQuality> getTargetClass() {
            return RadiotapDataLockQuality.class;
          }
        });
    instantiaters.put(
        RadiotapPresentBitNumber.TX_ATTENUATION,
        new Instantiater() {
          @Override
          public RadiotapData newInstance(byte[] rawData, int offset, int length)
              throws IllegalRawDataException {
            return RadiotapDataTxAttenuation.newInstance(rawData, offset, length);
          }

          @Override
          public Class<RadiotapDataTxAttenuation> getTargetClass() {
            return RadiotapDataTxAttenuation.class;
          }
        });
    instantiaters.put(
        RadiotapPresentBitNumber.DB_TX_ATTENUATION,
        new Instantiater() {
          @Override
          public RadiotapData newInstance(byte[] rawData, int offset, int length)
              throws IllegalRawDataException {
            return RadiotapDataDbTxAttenuation.newInstance(rawData, offset, length);
          }

          @Override
          public Class<RadiotapDataDbTxAttenuation> getTargetClass() {
            return RadiotapDataDbTxAttenuation.class;
          }
        });
    instantiaters.put(
        RadiotapPresentBitNumber.DBM_TX_POWER,
        new Instantiater() {
          @Override
          public RadiotapData newInstance(byte[] rawData, int offset, int length)
              throws IllegalRawDataException {
            return RadiotapDataDbmTxPower.newInstance(rawData, offset, length);
          }

          @Override
          public Class<RadiotapDataDbmTxPower> getTargetClass() {
            return RadiotapDataDbmTxPower.class;
          }
        });
    instantiaters.put(
        RadiotapPresentBitNumber.ANTENNA,
        new Instantiater() {
          @Override
          public RadiotapData newInstance(byte[] rawData, int offset, int length)
              throws IllegalRawDataException {
            return RadiotapDataAntenna.newInstance(rawData, offset, length);
          }

          @Override
          public Class<RadiotapDataAntenna> getTargetClass() {
            return RadiotapDataAntenna.class;
          }
        });
    instantiaters.put(
        RadiotapPresentBitNumber.DB_ANTENNA_SIGNAL,
        new Instantiater() {
          @Override
          public RadiotapData newInstance(byte[] rawData, int offset, int length)
              throws IllegalRawDataException {
            return RadiotapDataDbAntennaSignal.newInstance(rawData, offset, length);
          }

          @Override
          public Class<RadiotapDataDbAntennaSignal> getTargetClass() {
            return RadiotapDataDbAntennaSignal.class;
          }
        });
    instantiaters.put(
        RadiotapPresentBitNumber.DB_ANTENNA_NOISE,
        new Instantiater() {
          @Override
          public RadiotapData newInstance(byte[] rawData, int offset, int length)
              throws IllegalRawDataException {
            return RadiotapDataDbAntennaNoise.newInstance(rawData, offset, length);
          }

          @Override
          public Class<RadiotapDataDbAntennaNoise> getTargetClass() {
            return RadiotapDataDbAntennaNoise.class;
          }
        });
    instantiaters.put(
        RadiotapPresentBitNumber.RX_FLAGS,
        new Instantiater() {
          @Override
          public RadiotapData newInstance(byte[] rawData, int offset, int length)
              throws IllegalRawDataException {
            return RadiotapDataRxFlags.newInstance(rawData, offset, length);
          }

          @Override
          public Class<RadiotapDataRxFlags> getTargetClass() {
            return RadiotapDataRxFlags.class;
          }
        });
    instantiaters.put(
        RadiotapPresentBitNumber.MCS,
        new Instantiater() {
          @Override
          public RadiotapData newInstance(byte[] rawData, int offset, int length)
              throws IllegalRawDataException {
            return RadiotapDataMcs.newInstance(rawData, offset, length);
          }

          @Override
          public Class<RadiotapDataMcs> getTargetClass() {
            return RadiotapDataMcs.class;
          }
        });
    instantiaters.put(
        RadiotapPresentBitNumber.A_MPDU_STATUS,
        new Instantiater() {
          @Override
          public RadiotapData newInstance(byte[] rawData, int offset, int length)
              throws IllegalRawDataException {
            return RadiotapDataAMpduStatus.newInstance(rawData, offset, length);
          }

          @Override
          public Class<RadiotapDataAMpduStatus> getTargetClass() {
            return RadiotapDataAMpduStatus.class;
          }
        });
    instantiaters.put(
        RadiotapPresentBitNumber.VHT,
        new Instantiater() {
          @Override
          public RadiotapData newInstance(byte[] rawData, int offset, int length)
              throws IllegalRawDataException {
            return RadiotapDataVht.newInstance(rawData, offset, length);
          }

          @Override
          public Class<RadiotapDataVht> getTargetClass() {
            return RadiotapDataVht.class;
          }
        });
  }

  /** @return the singleton instance of StaticRadiotapDataFieldFactory. */
  public static StaticRadiotapDataFieldFactory getInstance() {
    return INSTANCE;
  }

  @Override
  public RadiotapData newInstance(
      byte[] rawData, int offset, int length, RadiotapPresentBitNumber number) {
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
      return IllegalRadiotapData.newInstance(rawData, offset, length);
    }

    return newInstance(rawData, offset, length);
  }

  @Override
  public RadiotapData newInstance(byte[] rawData, int offset, int length) {
    return UnknownRadiotapData.newInstance(rawData, offset, length);
  }

  @Override
  public Class<? extends RadiotapData> getTargetClass(RadiotapPresentBitNumber number) {
    if (number == null) {
      throw new NullPointerException("number must not be null.");
    }
    Instantiater instantiater = instantiaters.get(number);
    return instantiater != null ? instantiater.getTargetClass() : getTargetClass();
  }

  @Override
  public Class<? extends RadiotapData> getTargetClass() {
    return UnknownRadiotapData.class;
  }

  private static interface Instantiater {

    public RadiotapData newInstance(byte[] rawData, int offset, int length)
        throws IllegalRawDataException;

    public Class<? extends RadiotapData> getTargetClass();
  }
}
