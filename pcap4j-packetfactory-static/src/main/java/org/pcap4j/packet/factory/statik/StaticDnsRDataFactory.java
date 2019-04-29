/*_##########################################################################
  _##
  _##  Copyright (C) 2016-2019 Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory.statik;

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

  private StaticDnsRDataFactory() {}

  /** @return the singleton instance of StaticDnsRDataFactory. */
  public static StaticDnsRDataFactory getInstance() {
    return INSTANCE;
  }

  /**
   * This method is a variant of {@link #newInstance(byte[], int, int, DnsResourceRecordType...)}
   * and exists only for performance reason.
   *
   * @param rawData see {@link PacketFactory#newInstance}.
   * @param offset see {@link PacketFactory#newInstance}.
   * @param length see {@link PacketFactory#newInstance}.
   * @return see {@link PacketFactory#newInstance}.
   */
  public DnsRData newInstance(byte[] rawData, int offset, int length) {
    return UnknownDnsRData.newInstance(rawData, offset, length);
  }

  /**
   * This method is a variant of {@link #newInstance(byte[], int, int, DnsResourceRecordType...)}
   * and exists only for performance reason.
   *
   * @param rawData see {@link PacketFactory#newInstance}.
   * @param offset see {@link PacketFactory#newInstance}.
   * @param length see {@link PacketFactory#newInstance}.
   * @param number see {@link PacketFactory#newInstance}.
   * @return see {@link PacketFactory#newInstance}.
   */
  public DnsRData newInstance(
      byte[] rawData, int offset, int length, DnsResourceRecordType number) {
    try {
      switch (Short.toUnsignedInt(number.value())) {
        case 1:
          return DnsRDataA.newInstance(rawData, offset, length);
        case 2:
          return DnsRDataNs.newInstance(rawData, offset, length);
        case 3:
          return DnsRDataMd.newInstance(rawData, offset, length);
        case 4:
          return DnsRDataMf.newInstance(rawData, offset, length);
        case 5:
          return DnsRDataCName.newInstance(rawData, offset, length);
        case 6:
          return DnsRDataSoa.newInstance(rawData, offset, length);
        case 7:
          return DnsRDataMb.newInstance(rawData, offset, length);
        case 8:
          return DnsRDataMg.newInstance(rawData, offset, length);
        case 9:
          return DnsRDataMr.newInstance(rawData, offset, length);
        case 10:
          return DnsRDataNull.newInstance(rawData, offset, length);
        case 11:
          return DnsRDataWks.newInstance(rawData, offset, length);
        case 12:
          return DnsRDataPtr.newInstance(rawData, offset, length);
        case 13:
          return DnsRDataHInfo.newInstance(rawData, offset, length);
        case 14:
          return DnsRDataMInfo.newInstance(rawData, offset, length);
        case 15:
          return DnsRDataMx.newInstance(rawData, offset, length);
        case 16:
          return DnsRDataTxt.newInstance(rawData, offset, length);
        case 28:
          return DnsRDataAaaa.newInstance(rawData, offset, length);
        case 257:
          return DnsRDataCaa.newInstance(rawData, offset, length);
      }
      return UnknownDnsRData.newInstance(rawData, offset, length);
    } catch (IllegalRawDataException e) {
      return IllegalDnsRData.newInstance(rawData, offset, length, e);
    }
  }

  /**
   * This method is a variant of {@link #newInstance(byte[], int, int, DnsResourceRecordType...)}
   * and exists only for performance reason.
   *
   * @param rawData see {@link PacketFactory#newInstance}.
   * @param offset see {@link PacketFactory#newInstance}.
   * @param length see {@link PacketFactory#newInstance}.
   * @param number1 see {@link PacketFactory#newInstance}.
   * @param number2 see {@link PacketFactory#newInstance}.
   * @return see {@link PacketFactory#newInstance}.
   */
  public DnsRData newInstance(
      byte[] rawData,
      int offset,
      int length,
      DnsResourceRecordType number1,
      DnsResourceRecordType number2) {
    try {
      switch (Short.toUnsignedInt(number1.value())) {
        case 1:
          return DnsRDataA.newInstance(rawData, offset, length);
        case 2:
          return DnsRDataNs.newInstance(rawData, offset, length);
        case 3:
          return DnsRDataMd.newInstance(rawData, offset, length);
        case 4:
          return DnsRDataMf.newInstance(rawData, offset, length);
        case 5:
          return DnsRDataCName.newInstance(rawData, offset, length);
        case 6:
          return DnsRDataSoa.newInstance(rawData, offset, length);
        case 7:
          return DnsRDataMb.newInstance(rawData, offset, length);
        case 8:
          return DnsRDataMg.newInstance(rawData, offset, length);
        case 9:
          return DnsRDataMr.newInstance(rawData, offset, length);
        case 10:
          return DnsRDataNull.newInstance(rawData, offset, length);
        case 11:
          return DnsRDataWks.newInstance(rawData, offset, length);
        case 12:
          return DnsRDataPtr.newInstance(rawData, offset, length);
        case 13:
          return DnsRDataHInfo.newInstance(rawData, offset, length);
        case 14:
          return DnsRDataMInfo.newInstance(rawData, offset, length);
        case 15:
          return DnsRDataMx.newInstance(rawData, offset, length);
        case 16:
          return DnsRDataTxt.newInstance(rawData, offset, length);
        case 28:
          return DnsRDataAaaa.newInstance(rawData, offset, length);
        case 257:
          return DnsRDataCaa.newInstance(rawData, offset, length);
      }

      switch (Short.toUnsignedInt(number2.value())) {
        case 1:
          return DnsRDataA.newInstance(rawData, offset, length);
        case 2:
          return DnsRDataNs.newInstance(rawData, offset, length);
        case 3:
          return DnsRDataMd.newInstance(rawData, offset, length);
        case 4:
          return DnsRDataMf.newInstance(rawData, offset, length);
        case 5:
          return DnsRDataCName.newInstance(rawData, offset, length);
        case 6:
          return DnsRDataSoa.newInstance(rawData, offset, length);
        case 7:
          return DnsRDataMb.newInstance(rawData, offset, length);
        case 8:
          return DnsRDataMg.newInstance(rawData, offset, length);
        case 9:
          return DnsRDataMr.newInstance(rawData, offset, length);
        case 10:
          return DnsRDataNull.newInstance(rawData, offset, length);
        case 11:
          return DnsRDataWks.newInstance(rawData, offset, length);
        case 12:
          return DnsRDataPtr.newInstance(rawData, offset, length);
        case 13:
          return DnsRDataHInfo.newInstance(rawData, offset, length);
        case 14:
          return DnsRDataMInfo.newInstance(rawData, offset, length);
        case 15:
          return DnsRDataMx.newInstance(rawData, offset, length);
        case 16:
          return DnsRDataTxt.newInstance(rawData, offset, length);
        case 28:
          return DnsRDataAaaa.newInstance(rawData, offset, length);
        case 257:
          return DnsRDataCaa.newInstance(rawData, offset, length);
      }
      return UnknownDnsRData.newInstance(rawData, offset, length);
    } catch (IllegalRawDataException e) {
      return IllegalDnsRData.newInstance(rawData, offset, length, e);
    }
  }

  @Override
  public DnsRData newInstance(
      byte[] rawData, int offset, int length, DnsResourceRecordType... numbers) {
    try {
      for (DnsResourceRecordType num : numbers) {
        switch (Short.toUnsignedInt(num.value())) {
          case 1:
            return DnsRDataA.newInstance(rawData, offset, length);
          case 2:
            return DnsRDataNs.newInstance(rawData, offset, length);
          case 3:
            return DnsRDataMd.newInstance(rawData, offset, length);
          case 4:
            return DnsRDataMf.newInstance(rawData, offset, length);
          case 5:
            return DnsRDataCName.newInstance(rawData, offset, length);
          case 6:
            return DnsRDataSoa.newInstance(rawData, offset, length);
          case 7:
            return DnsRDataMb.newInstance(rawData, offset, length);
          case 8:
            return DnsRDataMg.newInstance(rawData, offset, length);
          case 9:
            return DnsRDataMr.newInstance(rawData, offset, length);
          case 10:
            return DnsRDataNull.newInstance(rawData, offset, length);
          case 11:
            return DnsRDataWks.newInstance(rawData, offset, length);
          case 12:
            return DnsRDataPtr.newInstance(rawData, offset, length);
          case 13:
            return DnsRDataHInfo.newInstance(rawData, offset, length);
          case 14:
            return DnsRDataMInfo.newInstance(rawData, offset, length);
          case 15:
            return DnsRDataMx.newInstance(rawData, offset, length);
          case 16:
            return DnsRDataTxt.newInstance(rawData, offset, length);
          case 28:
            return DnsRDataAaaa.newInstance(rawData, offset, length);
          case 257:
            return DnsRDataCaa.newInstance(rawData, offset, length);
        }
      }
      return UnknownDnsRData.newInstance(rawData, offset, length);
    } catch (IllegalRawDataException e) {
      return IllegalDnsRData.newInstance(rawData, offset, length, e);
    }
  }
}
