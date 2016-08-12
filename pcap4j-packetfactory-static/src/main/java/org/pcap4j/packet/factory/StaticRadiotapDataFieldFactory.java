/*_##########################################################################
  _##
  _##  Copyright (C) 2016  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory;

import java.util.HashMap;
import java.util.Map;

import org.pcap4j.packet.IllegalRadiotapDataField;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.RadiotapAMpduStatus;
import org.pcap4j.packet.RadiotapAntenna;
import org.pcap4j.packet.RadiotapAntennaNoise;
import org.pcap4j.packet.RadiotapAntennaSignal;
import org.pcap4j.packet.RadiotapChannel;
import org.pcap4j.packet.RadiotapDbAntennaNoise;
import org.pcap4j.packet.RadiotapDbAntennaSignal;
import org.pcap4j.packet.RadiotapDbTxAttenuation;
import org.pcap4j.packet.RadiotapDbmTxPower;
import org.pcap4j.packet.RadiotapFhss;
import org.pcap4j.packet.RadiotapFlags;
import org.pcap4j.packet.RadiotapLockQuality;
import org.pcap4j.packet.RadiotapMcs;
import org.pcap4j.packet.RadiotapPacket.RadiotapDataField;
import org.pcap4j.packet.RadiotapRate;
import org.pcap4j.packet.RadiotapRxFlags;
import org.pcap4j.packet.RadiotapTsft;
import org.pcap4j.packet.RadiotapTxAttenuation;
import org.pcap4j.packet.RadiotapVht;
import org.pcap4j.packet.UnknownRadiotapDataField;
import org.pcap4j.packet.namednumber.RadiotapPresentBitNumber;

/**
 * @author Kaito Yamada
 * @since pcap4j 1.6.5
 */
public final class StaticRadiotapDataFieldFactory
implements PacketFactory<RadiotapDataField, RadiotapPresentBitNumber> {

  private static final StaticRadiotapDataFieldFactory INSTANCE
    = new StaticRadiotapDataFieldFactory();
  private final Map<RadiotapPresentBitNumber, Instantiater> instantiaters
    = new HashMap<RadiotapPresentBitNumber, Instantiater>();

  private StaticRadiotapDataFieldFactory() {
    instantiaters.put(
      RadiotapPresentBitNumber.TSFT, new Instantiater() {
        @Override
        public RadiotapDataField newInstance(
          byte[] rawData, int offset, int length
        ) throws IllegalRawDataException {
          return RadiotapTsft.newInstance(rawData, offset, length);
        }
        @Override
        public Class<RadiotapTsft> getTargetClass() {
          return RadiotapTsft.class;
        }
      }
    );
    instantiaters.put(
      RadiotapPresentBitNumber.FLAGS, new Instantiater() {
        @Override
        public RadiotapDataField newInstance(
          byte[] rawData, int offset, int length
        ) throws IllegalRawDataException {
          return RadiotapFlags.newInstance(rawData, offset, length);
        }
        @Override
        public Class<RadiotapFlags> getTargetClass() {
          return RadiotapFlags.class;
        }
      }
    );
    instantiaters.put(
      RadiotapPresentBitNumber.RATE, new Instantiater() {
        @Override
        public RadiotapDataField newInstance(
          byte[] rawData, int offset, int length
        ) throws IllegalRawDataException {
          return RadiotapRate.newInstance(rawData, offset, length);
        }
        @Override
        public Class<RadiotapRate> getTargetClass() {
          return RadiotapRate.class;
        }
      }
    );
    instantiaters.put(
      RadiotapPresentBitNumber.CHANNEL, new Instantiater() {
        @Override
        public RadiotapDataField newInstance(
          byte[] rawData, int offset, int length
        ) throws IllegalRawDataException {
          return RadiotapChannel.newInstance(rawData, offset, length);
        }
        @Override
        public Class<RadiotapChannel> getTargetClass() {
          return RadiotapChannel.class;
        }
      }
    );
    instantiaters.put(
      RadiotapPresentBitNumber.FHSS, new Instantiater() {
        @Override
        public RadiotapDataField newInstance(
          byte[] rawData, int offset, int length
        ) throws IllegalRawDataException {
          return RadiotapFhss.newInstance(rawData, offset, length);
        }
        @Override
        public Class<RadiotapFhss> getTargetClass() {
          return RadiotapFhss.class;
        }
      }
    );
    instantiaters.put(
      RadiotapPresentBitNumber.ANTENNA_SIGNAL, new Instantiater() {
        @Override
        public RadiotapDataField newInstance(
          byte[] rawData, int offset, int length
        ) throws IllegalRawDataException {
          return RadiotapAntennaSignal.newInstance(rawData, offset, length);
        }
        @Override
        public Class<RadiotapAntennaSignal> getTargetClass() {
          return RadiotapAntennaSignal.class;
        }
      }
    );
    instantiaters.put(
      RadiotapPresentBitNumber.ANTENNA_NOISE, new Instantiater() {
        @Override
        public RadiotapDataField newInstance(
          byte[] rawData, int offset, int length
        ) throws IllegalRawDataException {
          return RadiotapAntennaNoise.newInstance(rawData, offset, length);
        }
        @Override
        public Class<RadiotapAntennaNoise> getTargetClass() {
          return RadiotapAntennaNoise.class;
        }
      }
    );
    instantiaters.put(
      RadiotapPresentBitNumber.LOCK_QUALITY, new Instantiater() {
        @Override
        public RadiotapDataField newInstance(
          byte[] rawData, int offset, int length
        ) throws IllegalRawDataException {
          return RadiotapLockQuality.newInstance(rawData, offset, length);
        }
        @Override
        public Class<RadiotapLockQuality> getTargetClass() {
          return RadiotapLockQuality.class;
        }
      }
    );
    instantiaters.put(
      RadiotapPresentBitNumber.TX_ATTENUATION, new Instantiater() {
        @Override
        public RadiotapDataField newInstance(
          byte[] rawData, int offset, int length
        ) throws IllegalRawDataException {
          return RadiotapTxAttenuation.newInstance(rawData, offset, length);
        }
        @Override
        public Class<RadiotapTxAttenuation> getTargetClass() {
          return RadiotapTxAttenuation.class;
        }
      }
    );
    instantiaters.put(
      RadiotapPresentBitNumber.DB_TX_ATTENUATION, new Instantiater() {
        @Override
        public RadiotapDataField newInstance(
          byte[] rawData, int offset, int length
        ) throws IllegalRawDataException {
          return RadiotapDbTxAttenuation.newInstance(rawData, offset, length);
        }
        @Override
        public Class<RadiotapDbTxAttenuation> getTargetClass() {
          return RadiotapDbTxAttenuation.class;
        }
      }
    );
    instantiaters.put(
      RadiotapPresentBitNumber.DBM_TX_POWER, new Instantiater() {
        @Override
        public RadiotapDataField newInstance(
          byte[] rawData, int offset, int length
        ) throws IllegalRawDataException {
          return RadiotapDbmTxPower.newInstance(rawData, offset, length);
        }
        @Override
        public Class<RadiotapDbmTxPower> getTargetClass() {
          return RadiotapDbmTxPower.class;
        }
      }
    );
    instantiaters.put(
      RadiotapPresentBitNumber.ANTENNA, new Instantiater() {
        @Override
        public RadiotapDataField newInstance(
          byte[] rawData, int offset, int length
        ) throws IllegalRawDataException {
          return RadiotapAntenna.newInstance(rawData, offset, length);
        }
        @Override
        public Class<RadiotapAntenna> getTargetClass() {
          return RadiotapAntenna.class;
        }
      }
    );
    instantiaters.put(
      RadiotapPresentBitNumber.DB_ANTENNA_SIGNAL, new Instantiater() {
        @Override
        public RadiotapDataField newInstance(
          byte[] rawData, int offset, int length
        ) throws IllegalRawDataException {
          return RadiotapDbAntennaSignal.newInstance(rawData, offset, length);
        }
        @Override
        public Class<RadiotapDbAntennaSignal> getTargetClass() {
          return RadiotapDbAntennaSignal.class;
        }
      }
    );
    instantiaters.put(
      RadiotapPresentBitNumber.DB_ANTENNA_NOISE, new Instantiater() {
        @Override
        public RadiotapDataField newInstance(
          byte[] rawData, int offset, int length
        ) throws IllegalRawDataException {
          return RadiotapDbAntennaNoise.newInstance(rawData, offset, length);
        }
        @Override
        public Class<RadiotapDbAntennaNoise> getTargetClass() {
          return RadiotapDbAntennaNoise.class;
        }
      }
    );
    instantiaters.put(
      RadiotapPresentBitNumber.RX_FLAGS, new Instantiater() {
        @Override
        public RadiotapDataField newInstance(
          byte[] rawData, int offset, int length
        ) throws IllegalRawDataException {
          return RadiotapRxFlags.newInstance(rawData, offset, length);
        }
        @Override
        public Class<RadiotapRxFlags> getTargetClass() {
          return RadiotapRxFlags.class;
        }
      }
    );
    instantiaters.put(
      RadiotapPresentBitNumber.MCS, new Instantiater() {
        @Override
        public RadiotapDataField newInstance(
          byte[] rawData, int offset, int length
        ) throws IllegalRawDataException {
          return RadiotapMcs.newInstance(rawData, offset, length);
        }
        @Override
        public Class<RadiotapMcs> getTargetClass() {
          return RadiotapMcs.class;
        }
      }
    );
    instantiaters.put(
      RadiotapPresentBitNumber.A_MPDU_STATUS, new Instantiater() {
        @Override
        public RadiotapDataField newInstance(
          byte[] rawData, int offset, int length
        ) throws IllegalRawDataException {
          return RadiotapAMpduStatus.newInstance(rawData, offset, length);
        }
        @Override
        public Class<RadiotapAMpduStatus> getTargetClass() {
          return RadiotapAMpduStatus.class;
        }
      }
    );
    instantiaters.put(
      RadiotapPresentBitNumber.VHT, new Instantiater() {
        @Override
        public RadiotapDataField newInstance(
          byte[] rawData, int offset, int length
        ) throws IllegalRawDataException {
          return RadiotapVht.newInstance(rawData, offset, length);
        }
        @Override
        public Class<RadiotapVht> getTargetClass() {
          return RadiotapVht.class;
        }
      }
    );
  };

  /**
   *
   * @return the singleton instance of StaticRadiotapDataFieldFactory.
   */
  public static StaticRadiotapDataFieldFactory getInstance() {
    return INSTANCE;
  }

  @Override
  public RadiotapDataField newInstance(
    byte[] rawData, int offset, int length, RadiotapPresentBitNumber number
  ) {
    if (rawData == null || number == null) {
      StringBuilder sb = new StringBuilder(40);
      sb.append("rawData: ")
        .append(rawData)
        .append(" number: ")
        .append(number);
      throw new NullPointerException(sb.toString());
    }

    try {
      Instantiater instantiater = instantiaters.get(number);
      if (instantiater != null) {
        return instantiater.newInstance(rawData, offset, length);
      }
    } catch (IllegalRawDataException e) {
      return IllegalRadiotapDataField.newInstance(rawData, offset, length);
    }

    return newInstance(rawData, offset, length);
  }

  @Override
  public RadiotapDataField newInstance(byte[] rawData, int offset, int length) {
    return UnknownRadiotapDataField.newInstance(rawData, offset, length);
  }

  @Override
  public Class<? extends RadiotapDataField> getTargetClass(RadiotapPresentBitNumber number) {
    if (number == null) {
      throw new NullPointerException("number must not be null.");
    }
    Instantiater instantiater = instantiaters.get(number);
    return instantiater != null ? instantiater.getTargetClass() : getTargetClass();
  }

  @Override
  public Class<? extends RadiotapDataField> getTargetClass() {
    return UnknownRadiotapDataField.class;
  }

  private static interface Instantiater {

    public RadiotapDataField newInstance(
      byte [] rawData, int offset, int length
    ) throws IllegalRawDataException;

    public Class<? extends RadiotapDataField> getTargetClass();

  }

}
