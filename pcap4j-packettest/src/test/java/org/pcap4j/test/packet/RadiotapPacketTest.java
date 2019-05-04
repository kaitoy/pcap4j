/*_##########################################################################
  _##
  _##  Copyright (C) 2016 Pcap4J.org
  _##
  _##########################################################################
*/
package org.pcap4j.test.packet;

import static org.junit.Assert.assertEquals;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.Packet;
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
import org.pcap4j.packet.RadiotapDataMcs.Bandwidth;
import org.pcap4j.packet.RadiotapDataMcs.HtFormat;
import org.pcap4j.packet.RadiotapDataPad;
import org.pcap4j.packet.RadiotapDataRate;
import org.pcap4j.packet.RadiotapDataRxFlags;
import org.pcap4j.packet.RadiotapDataTsft.Builder;
import org.pcap4j.packet.RadiotapDataTxAttenuation;
import org.pcap4j.packet.RadiotapDataVht;
import org.pcap4j.packet.RadiotapFecType;
import org.pcap4j.packet.RadiotapPacket;
import org.pcap4j.packet.RadiotapPacket.RadiotapData;
import org.pcap4j.packet.RadiotapPacket.RadiotapHeader;
import org.pcap4j.packet.RadiotapPresentBitmask;
import org.pcap4j.packet.UnknownPacket;
import org.pcap4j.packet.namednumber.DataLinkType;
import org.pcap4j.packet.namednumber.RadiotapPresentBitNumber;
import org.pcap4j.packet.namednumber.RadiotapVhtBandwidth;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@SuppressWarnings("javadoc")
public class RadiotapPacketTest extends AbstractPacketTest {

  private static final Logger logger = LoggerFactory.getLogger(RadiotapPacketTest.class);

  private final RadiotapPacket packet;
  private final byte version;
  private final byte pad;
  private final List<RadiotapPresentBitmask> presentBitmasks;
  private final List<RadiotapData> dataFields;

  public RadiotapPacketTest() {
    this.version = 0;
    this.pad = 22;
    this.presentBitmasks = new ArrayList<RadiotapPresentBitmask>();
    this.dataFields = new ArrayList<RadiotapData>();

    List<RadiotapPresentBitNumber> bitNumbers = new ArrayList<RadiotapPresentBitNumber>();
    bitNumbers.add(RadiotapPresentBitNumber.TSFT);
    bitNumbers.add(RadiotapPresentBitNumber.FLAGS);
    bitNumbers.add(RadiotapPresentBitNumber.RATE);
    bitNumbers.add(RadiotapPresentBitNumber.CHANNEL);
    bitNumbers.add(RadiotapPresentBitNumber.FHSS);
    bitNumbers.add(RadiotapPresentBitNumber.ANTENNA_SIGNAL);
    bitNumbers.add(RadiotapPresentBitNumber.ANTENNA_NOISE);
    bitNumbers.add(RadiotapPresentBitNumber.LOCK_QUALITY);
    bitNumbers.add(RadiotapPresentBitNumber.TX_ATTENUATION);
    bitNumbers.add(RadiotapPresentBitNumber.DB_TX_ATTENUATION);
    bitNumbers.add(RadiotapPresentBitNumber.DBM_TX_POWER);
    bitNumbers.add(RadiotapPresentBitNumber.ANTENNA);
    bitNumbers.add(RadiotapPresentBitNumber.DB_ANTENNA_SIGNAL);
    bitNumbers.add(RadiotapPresentBitNumber.DB_ANTENNA_NOISE);
    bitNumbers.add(RadiotapPresentBitNumber.RX_FLAGS);
    bitNumbers.add(RadiotapPresentBitNumber.MCS);
    bitNumbers.add(RadiotapPresentBitNumber.A_MPDU_STATUS);
    bitNumbers.add(RadiotapPresentBitNumber.VHT);
    RadiotapPresentBitmask.Builder rpb =
        new RadiotapPresentBitmask.Builder().namespace("").bitNumbers(bitNumbers);
    presentBitmasks.add(rpb.build());

    Builder tsft = new Builder().macTimestamp(new BigInteger("12345678912345678910"));
    dataFields.add(tsft.build());

    RadiotapDataFlags.Builder flags =
        new RadiotapDataFlags.Builder()
            .cfp(true)
            .shortPreamble(true)
            .wepEncrypted(false)
            .fragmented(false)
            .includingFcs(true)
            .padding(true)
            .badFcs(false)
            .shortGuardInterval(false);
    dataFields.add(flags.build());

    RadiotapDataRate.Builder rate = new RadiotapDataRate.Builder().rate((byte) 111);
    dataFields.add(rate.build());

    RadiotapDataChannel.Builder channel =
        new RadiotapDataChannel.Builder()
            .frequency((short) 12345)
            .lsbOfFlags(true)
            .secondLsbOfFlags(true)
            .thirdLsbOfFlags(true)
            .fourthLsbOfFlags(false)
            .turbo(false)
            .cck(false)
            .ofdm(true)
            .twoGhzSpectrum(true)
            .fiveGhzSpectrum(true)
            .onlyPassiveScan(false)
            .dynamicCckOfdm(false)
            .gfsk(false)
            .gsm(true)
            .staticTurbo(true)
            .halfRate(true)
            .quarterRate(false);
    dataFields.add(channel.build());

    RadiotapDataFhss.Builder fhss =
        new RadiotapDataFhss.Builder().hopSet((byte) 0xaa).hopPattern((byte) 0xbb);
    dataFields.add(fhss.build());

    RadiotapDataAntennaSignal.Builder antennaSignal =
        new RadiotapDataAntennaSignal.Builder().antennaSignal((byte) 0xcc);
    dataFields.add(antennaSignal.build());

    RadiotapDataAntennaNoise.Builder antennaNoise =
        new RadiotapDataAntennaNoise.Builder().antennaNoise((byte) 0xdd);
    dataFields.add(antennaNoise.build());

    RadiotapDataLockQuality.Builder lockQuality =
        new RadiotapDataLockQuality.Builder().lockQuality((short) 0xabcd);
    dataFields.add(lockQuality.build());

    RadiotapDataTxAttenuation.Builder txAttenuation =
        new RadiotapDataTxAttenuation.Builder().txAttenuation((short) 0xdcba);
    dataFields.add(txAttenuation.build());

    RadiotapDataDbTxAttenuation.Builder dbTxAttenuation =
        new RadiotapDataDbTxAttenuation.Builder().txAttenuation((short) 0xaaff);
    dataFields.add(dbTxAttenuation.build());

    RadiotapDataDbmTxPower.Builder dbmTxPower =
        new RadiotapDataDbmTxPower.Builder().txPower((byte) 0xaf);
    dataFields.add(dbmTxPower.build());

    RadiotapDataAntenna.Builder antenna = new RadiotapDataAntenna.Builder().antenna((byte) 0xfa);
    dataFields.add(antenna.build());

    RadiotapDataDbAntennaSignal.Builder dbAntennaSignal =
        new RadiotapDataDbAntennaSignal.Builder().antennaSignal((byte) 111);
    dataFields.add(dbAntennaSignal.build());

    RadiotapDataDbAntennaNoise.Builder dbAntennaNoise =
        new RadiotapDataDbAntennaNoise.Builder().antennaNoise((byte) 100);
    dataFields.add(dbAntennaNoise.build());

    RadiotapDataRxFlags.Builder rxFlags =
        new RadiotapDataRxFlags.Builder()
            .lsb(true)
            .badPlcpCrc(false)
            .thirdLsb(true)
            .fourthLsb(true)
            .fifthLsb(false)
            .sixthLsb(false)
            .seventhLsb(true)
            .eighthLsb(true)
            .ninthLsb(true)
            .tenthLsb(false)
            .eleventhLsb(false)
            .twelvethLsb(false)
            .thirteenthLsb(true)
            .fourteenthLsb(true)
            .fifteenthLsb(true)
            .sixteenthLsb(true);
    dataFields.add(rxFlags.build());

    RadiotapDataMcs.Builder mcs =
        new RadiotapDataMcs.Builder()
            .bandwidthKnown(true)
            .mcsIndexKnown(true)
            .guardIntervalKnown(true)
            .htFormatKnown(true)
            .fecTypeKnown(true)
            .stbcKnown(true)
            .nessKnown(true)
            .nessMsb(true)
            .bandwidth(Bandwidth.BW_20L)
            .shortGuardInterval(true)
            .htFormat(HtFormat.MIXED)
            .fecType(RadiotapFecType.LDPC)
            .numStbcStreams((byte) 1)
            .nessLsb(false)
            .mcsRateIndex((byte) 123);
    dataFields.add(mcs.build());

    RadiotapDataPad.Builder dataPad = new RadiotapDataPad.Builder().pad(new byte[] {1, 2, 3});
    dataFields.add(dataPad.build());

    RadiotapDataAMpduStatus.Builder aMpduStatus =
        new RadiotapDataAMpduStatus.Builder()
            .referenceNumber(987654321)
            .driverReportsZeroLengthSubframes(false)
            .zeroLengthSubframe(false)
            .lastSubframeKnown(true)
            .lastSubframe(true)
            .delimiterCrcError(false)
            .delimiterCrcValueKnown(true)
            .tenthMsbOfFlags(false)
            .ninthMsbOfFlags(false)
            .eighthMsbOfFlags(true)
            .seventhMsbOfFlags(true)
            .sixthMsbOfFlags(false)
            .fifthMsbOfFlags(true)
            .fourthMsbOfFlags(false)
            .thirdMsbOfFlags(false)
            .secondMsbOfFlags(true)
            .msbOfFlags(true)
            .delimiterCrcValue((byte) 55)
            .reserved((byte) 99);
    dataFields.add(aMpduStatus.build());

    RadiotapDataVht.Builder vht =
        new RadiotapDataVht.Builder()
            .stbcKnown(true)
            .txopPsNotAllowedKnown(true)
            .guardIntervalKnown(true)
            .shortGiNsymDisambiguationKnown(true)
            .ldpcExtraOfdmSymbolKnown(true)
            .beamformedKnown(true)
            .bandwidthKnown(true)
            .groupIdKnown(true)
            .partialAidKnown(true)
            .seventhMsbOfKnown(false)
            .sixthMsbOfKnown(true)
            .fifthMsbOfKnown(true)
            .fourthMsbOfKnown(false)
            .thirdMsbOfKnown(true)
            .secondMsbOfKnown(true)
            .msbOfKnown(false)
            .stbc(false)
            .txopPsNotAllowed(false)
            .shortGuardInterval(true)
            .shortGiNsymDisambiguation(true)
            .ldpcExtraOfdmSymbol(false)
            .beamformed(true)
            .secondMsbOfFlags(false)
            .msbOfFlags(true)
            .bandwidth(RadiotapVhtBandwidth.BW_20ULL)
            .mcses(new byte[] {(byte) 1, (byte) 2, (byte) 3, (byte) 4})
            .nsses(new byte[] {(byte) 4, (byte) 3, (byte) 2, (byte) 1})
            .fecTypes(
                new RadiotapFecType[] {
                  RadiotapFecType.BCC,
                  RadiotapFecType.LDPC,
                  RadiotapFecType.LDPC,
                  RadiotapFecType.BCC
                })
            .unusedInCoding((byte) 10)
            .groupId((byte) 111)
            .partialAid((short) 12321);
    dataFields.add(vht.build());

    UnknownPacket.Builder uk =
        new UnknownPacket.Builder().rawData(new byte[] {0, 1, 2, 3, 4, 5, 6, 7});

    RadiotapPacket.Builder radio =
        new RadiotapPacket.Builder()
            .version(version)
            .pad(pad)
            .presentBitmasks(presentBitmasks)
            .dataFields(dataFields)
            .payloadBuilder(uk)
            .correctLengthAtBuild(true);
    this.packet = radio.build();
  }

  @Override
  protected Packet getPacket() {
    return packet;
  }

  @Override
  protected Packet getWholePacket() {
    return packet;
  }

  @Override
  protected DataLinkType getDataLinkType() {
    return DataLinkType.IEEE802_11_RADIO;
  }

  @BeforeClass
  public static void setUpBeforeClass() throws Exception {
    logger.info("########## " + RadiotapPacketTest.class.getSimpleName() + " START ##########");
  }

  @AfterClass
  public static void tearDownAfterClass() throws Exception {}

  @Test
  public void testNewPacket() {
    try {
      RadiotapPacket p =
          RadiotapPacket.newPacket(packet.getRawData(), 0, packet.getRawData().length);
      assertEquals(packet, p);
    } catch (IllegalRawDataException e) {
      throw new AssertionError(e);
    }
  }

  @Test
  public void testGetHeader() {
    RadiotapHeader h = packet.getHeader();
    assertEquals(version, h.getVersion());
    assertEquals(pad, h.getPad());
    assertEquals(presentBitmasks, h.getPresentBitmasks());
    assertEquals(dataFields, h.getDataFields());
  }
}
