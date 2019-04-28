/*_##########################################################################
  _##
  _##  Copyright (C) 2016-2019 Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory.statik;

import java.util.HashMap;
import java.util.Map;
import org.pcap4j.packet.DnsRDataA;
import org.pcap4j.packet.DnsRDataAaaa;
import org.pcap4j.packet.DnsRDataCName;
import org.pcap4j.packet.DnsRDataCaa;
import org.pcap4j.packet.DnsRDataHInfo;
import org.pcap4j.packet.DnsRDataMInfo;
import org.pcap4j.packet.DnsRDataMb;
import org.pcap4j.packet.DnsRDataMd;
import org.pcap4j.packet.DnsRDataMf;
import org.pcap4j.packet.DnsRDataMg;
import org.pcap4j.packet.DnsRDataMr;
import org.pcap4j.packet.DnsRDataMx;
import org.pcap4j.packet.DnsRDataNs;
import org.pcap4j.packet.DnsRDataNull;
import org.pcap4j.packet.DnsRDataPtr;
import org.pcap4j.packet.DnsRDataSoa;
import org.pcap4j.packet.DnsRDataTxt;
import org.pcap4j.packet.DnsRDataWks;
import org.pcap4j.packet.DnsResourceRecord.DnsRData;
import org.pcap4j.packet.IllegalDnsRData;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.UnknownDnsRData;
import org.pcap4j.packet.factory.PacketFactory;
import org.pcap4j.packet.namednumber.DnsResourceRecordType;

/**
 * @author Kaito Yamada
 * @since pcap4j 1.7.1
 */
public final class StaticDnsRDataFactory implements PacketFactory<DnsRData, DnsResourceRecordType> {

  private static final StaticDnsRDataFactory INSTANCE = new StaticDnsRDataFactory();
  private final Map<DnsResourceRecordType, Instantiater> instantiaters =
      new HashMap<DnsResourceRecordType, Instantiater>();

  private StaticDnsRDataFactory() {
    instantiaters.put(
        DnsResourceRecordType.A,
        new Instantiater() {
          @Override
          public DnsRData newInstance(byte[] rawData, int offset, int length)
              throws IllegalRawDataException {
            return DnsRDataA.newInstance(rawData, offset, length);
          }

          @Override
          public Class<DnsRDataA> getTargetClass() {
            return DnsRDataA.class;
          }
        });
    instantiaters.put(
        DnsResourceRecordType.NS,
        new Instantiater() {
          @Override
          public DnsRData newInstance(byte[] rawData, int offset, int length)
              throws IllegalRawDataException {
            return DnsRDataNs.newInstance(rawData, offset, length);
          }

          @Override
          public Class<DnsRDataNs> getTargetClass() {
            return DnsRDataNs.class;
          }
        });
    instantiaters.put(
        DnsResourceRecordType.MD,
        new Instantiater() {
          @Override
          public DnsRData newInstance(byte[] rawData, int offset, int length)
              throws IllegalRawDataException {
            return DnsRDataMd.newInstance(rawData, offset, length);
          }

          @Override
          public Class<DnsRDataMd> getTargetClass() {
            return DnsRDataMd.class;
          }
        });
    instantiaters.put(
        DnsResourceRecordType.MF,
        new Instantiater() {
          @Override
          public DnsRData newInstance(byte[] rawData, int offset, int length)
              throws IllegalRawDataException {
            return DnsRDataMf.newInstance(rawData, offset, length);
          }

          @Override
          public Class<DnsRDataMf> getTargetClass() {
            return DnsRDataMf.class;
          }
        });
    instantiaters.put(
        DnsResourceRecordType.CNAME,
        new Instantiater() {
          @Override
          public DnsRData newInstance(byte[] rawData, int offset, int length)
              throws IllegalRawDataException {
            return DnsRDataCName.newInstance(rawData, offset, length);
          }

          @Override
          public Class<DnsRDataCName> getTargetClass() {
            return DnsRDataCName.class;
          }
        });
    instantiaters.put(
        DnsResourceRecordType.SOA,
        new Instantiater() {
          @Override
          public DnsRData newInstance(byte[] rawData, int offset, int length)
              throws IllegalRawDataException {
            return DnsRDataSoa.newInstance(rawData, offset, length);
          }

          @Override
          public Class<DnsRDataSoa> getTargetClass() {
            return DnsRDataSoa.class;
          }
        });
    instantiaters.put(
        DnsResourceRecordType.MB,
        new Instantiater() {
          @Override
          public DnsRData newInstance(byte[] rawData, int offset, int length)
              throws IllegalRawDataException {
            return DnsRDataMb.newInstance(rawData, offset, length);
          }

          @Override
          public Class<DnsRDataMb> getTargetClass() {
            return DnsRDataMb.class;
          }
        });
    instantiaters.put(
        DnsResourceRecordType.MG,
        new Instantiater() {
          @Override
          public DnsRData newInstance(byte[] rawData, int offset, int length)
              throws IllegalRawDataException {
            return DnsRDataMg.newInstance(rawData, offset, length);
          }

          @Override
          public Class<DnsRDataMg> getTargetClass() {
            return DnsRDataMg.class;
          }
        });
    instantiaters.put(
        DnsResourceRecordType.MR,
        new Instantiater() {
          @Override
          public DnsRData newInstance(byte[] rawData, int offset, int length)
              throws IllegalRawDataException {
            return DnsRDataMr.newInstance(rawData, offset, length);
          }

          @Override
          public Class<DnsRDataMr> getTargetClass() {
            return DnsRDataMr.class;
          }
        });
    instantiaters.put(
        DnsResourceRecordType.NULL,
        new Instantiater() {
          @Override
          public DnsRData newInstance(byte[] rawData, int offset, int length)
              throws IllegalRawDataException {
            return DnsRDataNull.newInstance(rawData, offset, length);
          }

          @Override
          public Class<DnsRDataNull> getTargetClass() {
            return DnsRDataNull.class;
          }
        });
    instantiaters.put(
        DnsResourceRecordType.WKS,
        new Instantiater() {
          @Override
          public DnsRData newInstance(byte[] rawData, int offset, int length)
              throws IllegalRawDataException {
            return DnsRDataWks.newInstance(rawData, offset, length);
          }

          @Override
          public Class<DnsRDataWks> getTargetClass() {
            return DnsRDataWks.class;
          }
        });
    instantiaters.put(
        DnsResourceRecordType.PTR,
        new Instantiater() {
          @Override
          public DnsRData newInstance(byte[] rawData, int offset, int length)
              throws IllegalRawDataException {
            return DnsRDataPtr.newInstance(rawData, offset, length);
          }

          @Override
          public Class<DnsRDataPtr> getTargetClass() {
            return DnsRDataPtr.class;
          }
        });
    instantiaters.put(
        DnsResourceRecordType.HINFO,
        new Instantiater() {
          @Override
          public DnsRData newInstance(byte[] rawData, int offset, int length)
              throws IllegalRawDataException {
            return DnsRDataHInfo.newInstance(rawData, offset, length);
          }

          @Override
          public Class<DnsRDataHInfo> getTargetClass() {
            return DnsRDataHInfo.class;
          }
        });
    instantiaters.put(
        DnsResourceRecordType.MINFO,
        new Instantiater() {
          @Override
          public DnsRData newInstance(byte[] rawData, int offset, int length)
              throws IllegalRawDataException {
            return DnsRDataMInfo.newInstance(rawData, offset, length);
          }

          @Override
          public Class<DnsRDataMInfo> getTargetClass() {
            return DnsRDataMInfo.class;
          }
        });
    instantiaters.put(
        DnsResourceRecordType.MX,
        new Instantiater() {
          @Override
          public DnsRData newInstance(byte[] rawData, int offset, int length)
              throws IllegalRawDataException {
            return DnsRDataMx.newInstance(rawData, offset, length);
          }

          @Override
          public Class<DnsRDataMx> getTargetClass() {
            return DnsRDataMx.class;
          }
        });
    instantiaters.put(
        DnsResourceRecordType.TXT,
        new Instantiater() {
          @Override
          public DnsRData newInstance(byte[] rawData, int offset, int length)
              throws IllegalRawDataException {
            return DnsRDataTxt.newInstance(rawData, offset, length);
          }

          @Override
          public Class<DnsRDataTxt> getTargetClass() {
            return DnsRDataTxt.class;
          }
        });
    instantiaters.put(
        DnsResourceRecordType.AAAA,
        new Instantiater() {
          @Override
          public DnsRData newInstance(byte[] rawData, int offset, int length)
              throws IllegalRawDataException {
            return DnsRDataAaaa.newInstance(rawData, offset, length);
          }

          @Override
          public Class<DnsRDataAaaa> getTargetClass() {
            return DnsRDataAaaa.class;
          }
        });
    instantiaters.put(
        DnsResourceRecordType.CAA,
        new Instantiater() {
          @Override
          public DnsRData newInstance(byte[] rawData, int offset, int length)
              throws IllegalRawDataException {
            return DnsRDataCaa.newInstance(rawData, offset, length);
          }

          @Override
          public Class<DnsRDataCaa> getTargetClass() {
            return DnsRDataCaa.class;
          }
        });
  }

  /** @return the singleton instance of StaticDnsRDataFactory. */
  public static StaticDnsRDataFactory getInstance() {
    return INSTANCE;
  }

  @Override
  public DnsRData newInstance(
      byte[] rawData, int offset, int length, DnsResourceRecordType number) {
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
      return IllegalDnsRData.newInstance(rawData, offset, length);
    }

    return newInstance(rawData, offset, length);
  }

  @Override
  public DnsRData newInstance(byte[] rawData, int offset, int length) {
    return UnknownDnsRData.newInstance(rawData, offset, length);
  }

  @Override
  public Class<? extends DnsRData> getTargetClass(DnsResourceRecordType number) {
    if (number == null) {
      throw new NullPointerException("number must not be null.");
    }
    Instantiater instantiater = instantiaters.get(number);
    return instantiater != null ? instantiater.getTargetClass() : getTargetClass();
  }

  @Override
  public Class<? extends DnsRData> getTargetClass() {
    return UnknownDnsRData.class;
  }

  private static interface Instantiater {

    public DnsRData newInstance(byte[] rawData, int offset, int length)
        throws IllegalRawDataException;

    public Class<? extends DnsRData> getTargetClass();
  }
}
