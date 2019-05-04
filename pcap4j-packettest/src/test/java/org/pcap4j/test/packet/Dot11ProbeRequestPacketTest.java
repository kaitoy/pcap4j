/*_##########################################################################
  _##
  _##  Copyright (C) 2016 Pcap4J.org
  _##
  _##########################################################################
*/
package org.pcap4j.test.packet;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.List;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.pcap4j.packet.Dot112040BssCoexistenceElement;
import org.pcap4j.packet.Dot11AbstractSupportedRatesElement.BssMembershipSelector;
import org.pcap4j.packet.Dot11AbstractSupportedRatesElement.Datum;
import org.pcap4j.packet.Dot11AbstractSupportedRatesElement.Rate;
import org.pcap4j.packet.Dot11ChannelEntry;
import org.pcap4j.packet.Dot11ChannelUsageElement;
import org.pcap4j.packet.Dot11DsssParameterSetElement;
import org.pcap4j.packet.Dot11ExtendedCapabilitiesElement;
import org.pcap4j.packet.Dot11ExtendedSupportedRatesElement;
import org.pcap4j.packet.Dot11FrameControl;
import org.pcap4j.packet.Dot11FrameControl.ProtocolVersion;
import org.pcap4j.packet.Dot11HTCapabilitiesElement;
import org.pcap4j.packet.Dot11HTCapabilitiesElement.AMpduLength;
import org.pcap4j.packet.Dot11HTCapabilitiesElement.AMsduLength;
import org.pcap4j.packet.Dot11HTCapabilitiesElement.BeamformingFeedbackCapability;
import org.pcap4j.packet.Dot11HTCapabilitiesElement.Calibration;
import org.pcap4j.packet.Dot11HTCapabilitiesElement.ChannelEstimationCapability;
import org.pcap4j.packet.Dot11HTCapabilitiesElement.CsiNumRows;
import org.pcap4j.packet.Dot11HTCapabilitiesElement.Grouping;
import org.pcap4j.packet.Dot11HTCapabilitiesElement.McsFeedbackCapability;
import org.pcap4j.packet.Dot11HTCapabilitiesElement.MpduStartSpacing;
import org.pcap4j.packet.Dot11HTCapabilitiesElement.NumBeamformerAntennas;
import org.pcap4j.packet.Dot11HTCapabilitiesElement.NumSpatialStreams;
import org.pcap4j.packet.Dot11HTCapabilitiesElement.PcoTransitionTime;
import org.pcap4j.packet.Dot11HTCapabilitiesElement.SmPowerSaveMode;
import org.pcap4j.packet.Dot11HTCapabilitiesElement.StbcSupport;
import org.pcap4j.packet.Dot11HtControl;
import org.pcap4j.packet.Dot11HtControl.CalibrationPosition;
import org.pcap4j.packet.Dot11HtControl.CsiOrSteering;
import org.pcap4j.packet.Dot11InterworkingElement;
import org.pcap4j.packet.Dot11LinkAdaptationControl.Builder;
import org.pcap4j.packet.Dot11LinkAdaptationControl.Mai;
import org.pcap4j.packet.Dot11MeshIdElement;
import org.pcap4j.packet.Dot11ProbeRequestPacket;
import org.pcap4j.packet.Dot11ProbeRequestPacket.Dot11ProbeRequestHeader;
import org.pcap4j.packet.Dot11RequestElement;
import org.pcap4j.packet.Dot11SequenceControl;
import org.pcap4j.packet.Dot11SsidElement;
import org.pcap4j.packet.Dot11SsidListElement;
import org.pcap4j.packet.Dot11SupportedOperatingClassesElement;
import org.pcap4j.packet.Dot11SupportedRatesElement;
import org.pcap4j.packet.Dot11VendorSpecificElement;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.namednumber.DataLinkType;
import org.pcap4j.packet.namednumber.Dot11AccessNetworkType;
import org.pcap4j.packet.namednumber.Dot11BssMembershipSelector;
import org.pcap4j.packet.namednumber.Dot11ChannelUsageMode;
import org.pcap4j.packet.namednumber.Dot11FrameType;
import org.pcap4j.packet.namednumber.Dot11InformationElementId;
import org.pcap4j.packet.namednumber.Dot11ServiceIntervalGranularity;
import org.pcap4j.packet.namednumber.Dot11VenueInfo;
import org.pcap4j.util.MacAddress;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@SuppressWarnings("javadoc")
public class Dot11ProbeRequestPacketTest extends AbstractPacketTest {

  private static final Logger logger = LoggerFactory.getLogger(Dot11ProbeRequestPacketTest.class);

  private final Dot11FrameControl frameControl;
  private final short duration;
  private final MacAddress address1;
  private final MacAddress address2;
  private final MacAddress address3;
  private final Dot11SequenceControl sequenceControl;
  private final Dot11HtControl htControl;
  private final Dot11SsidElement ssid;
  private final Dot11SupportedRatesElement supportedRates;
  private final Dot11RequestElement request;
  private final Dot11ExtendedSupportedRatesElement extendedSupportedRates;
  private final Dot11DsssParameterSetElement dsssParameterSet;
  private final Dot11SupportedOperatingClassesElement supportedOperatingClasses;
  private final Dot11HTCapabilitiesElement htCapabilities;
  private final Dot112040BssCoexistenceElement twentyFortyBssCoexistence;
  private final Dot11ExtendedCapabilitiesElement extendedCapabilities;
  private final Dot11SsidListElement ssidList;
  private final Dot11ChannelUsageElement channelUsage;
  private final Dot11InterworkingElement interworking;
  private final Dot11MeshIdElement meshId;
  private final List<Dot11VendorSpecificElement> vendorSpecificElements;
  private final Dot11ProbeRequestPacket packet;

  public Dot11ProbeRequestPacketTest() throws Exception {
    this.frameControl =
        new Dot11FrameControl.Builder()
            .protocolVersion(ProtocolVersion.V0)
            .type(Dot11FrameType.PROBE_REQUEST)
            .toDs(true)
            .fromDs(false)
            .moreFragments(false)
            .retry(true)
            .powerManagement(false)
            .moreData(false)
            .protectedFrame(false)
            .order(true)
            .build();
    this.duration = 1234;
    this.address1 = MacAddress.getByName("aa:bb:cc:dd:ee:ff");
    this.address2 = MacAddress.getByName("ff:aa:ff:aa:ff:aa");
    this.address3 = MacAddress.getByName("11:22:33:44:55:66");
    this.sequenceControl =
        new Dot11SequenceControl.Builder()
            .fragmentNumber((byte) 0x0a)
            .sequenceNumber((short) 0x0abc)
            .build();
    this.htControl =
        new Dot11HtControl.Builder()
            .linkAdaptationControl(
                new Builder()
                    .vhtMfb(false)
                    .trq(true)
                    //
                    // .maiOrAseli(Dot11LinkAdaptationControl.ASELI)
                    .maiOrAseli(new Mai(true, (byte) 2))
                    .mfsi((byte) 3)
                    //               .mfbOrAselc(new
                    // Aselc(AselCommand.SOUNDING_LABEL, (byte) 0x05))
                    .mfbOrAselc((byte) 123)
                    .build())
            .calibrationPosition(CalibrationPosition.SOUNDING_COMPLETE)
            .calibrationSequence((byte) 3)
            .bit20(true)
            .bit21(false)
            .csiOrSteering(CsiOrSteering.NONCOMPRESSED_BEAMFORMING)
            .ndpAnnouncement(false)
            .bit25(true)
            .bit26(false)
            .bit27(false)
            .bit28(true)
            .bit29(true)
            .acConstraint(true)
            .rdgOrMorePpdu(false)
            .build();

    this.ssid = new Dot11SsidElement.Builder().correctLengthAtBuild(true).ssid("hogehoge").build();

    List<Datum> ratesAndBssMembershipSelectors = new ArrayList<Datum>();
    ratesAndBssMembershipSelectors.add(new Rate(true, (byte) 0x10));
    ratesAndBssMembershipSelectors.add(
        new BssMembershipSelector(true, Dot11BssMembershipSelector.HT_PHY));
    ratesAndBssMembershipSelectors.add(new Rate(true, (byte) 0x20));
    ratesAndBssMembershipSelectors.add(
        new BssMembershipSelector(false, Dot11BssMembershipSelector.HT_PHY));
    ratesAndBssMembershipSelectors.add(new Rate(false, (byte) 0x30));
    this.supportedRates =
        new Dot11SupportedRatesElement.Builder()
            .correctLengthAtBuild(true)
            .ratesAndBssMembershipSelectors(ratesAndBssMembershipSelectors)
            .build();

    List<Dot11InformationElementId> requestedElementIds =
        new ArrayList<Dot11InformationElementId>();
    requestedElementIds.add(Dot11InformationElementId.ADVERTISEMENT_PROTOCOL);
    requestedElementIds.add(Dot11InformationElementId.BSS_AC_ACCESS_DELAY);
    requestedElementIds.add(Dot11InformationElementId.EMERGENCY_ALERT_IDENTIFIER);
    this.request =
        new Dot11RequestElement.Builder()
            .correctLengthAtBuild(true)
            .requestedElementIds(requestedElementIds)
            .build();

    ratesAndBssMembershipSelectors.clear();
    ratesAndBssMembershipSelectors.add(
        new BssMembershipSelector(false, Dot11BssMembershipSelector.HT_PHY));
    ratesAndBssMembershipSelectors.add(new Rate(true, (byte) 111));
    this.extendedSupportedRates =
        new Dot11ExtendedSupportedRatesElement.Builder()
            .correctLengthAtBuild(true)
            .ratesAndBssMembershipSelectors(ratesAndBssMembershipSelectors)
            .build();

    this.dsssParameterSet =
        new Dot11DsssParameterSetElement.Builder()
            .correctLengthAtBuild(true)
            .currentChannel((byte) 0x99)
            .build();

    this.supportedOperatingClasses =
        new Dot11SupportedOperatingClassesElement.Builder()
            .correctLengthAtBuild(true)
            .currentOperatingClass((byte) 0xee)
            .operatingClasses(new byte[] {5, 4, 3, 2, 1})
            .build();

    this.htCapabilities =
        new Dot11HTCapabilitiesElement.Builder()
            .correctLengthAtBuild(true)
            .ldpcCodingSupported(false)
            .both20and40MhzSupported(true)
            .smPowerSaveMode(SmPowerSaveMode.DYNAMIC)
            .htGreenfieldSupported(false)
            .shortGiFor20MhzSupported(true)
            .shortGiFor40MhzSupported(false)
            .txStbcSupported(true)
            .rxStbcSupport(StbcSupport.ONE_SPATIAL_STREAM)
            .htDelayedBlockAckSupported(false)
            .maxAMsduLength(AMsduLength.MAX_7935)
            .dsssCckModeIn40MhzSupported(true)
            .bit13OfHtCapabilitiesInfo(false)
            .fortyMhzIntolerant(true)
            .lSigTxopProtectionSupported(false)
            .maxAMpduLength(AMpduLength.MAX_32767)
            .minMpduStartSpacing(MpduStartSpacing.FOUR_US)
            .bit5OfAMpduParameters(true)
            .bit6OfAMpduParameters(false)
            .bit7OfAMpduParameters(true)
            .supportedRxMcsIndexes(
                new boolean[] {
                  true, false, false, false, false, true, false, false, false, false,
                  true, false, false, false, false, true, false, false, false, false,
                  true, false, false, false, false, true, false, false, false, false,
                  true, false, false, false, false, true, false, false, false, false,
                  true, false, false, false, false, true, false, false, false, false,
                  true, false, false, false, false, true, false, false, false, false,
                  true, false, false, false, false, true, false, false, false, false,
                  true, false, false, false, false, true, false
                })
            .bit77OfSupportedMcsSet(false)
            .bit78OfSupportedMcsSet(false)
            .bit79OfSupportedMcsSet(true)
            .rxHighestSupportedDataRate((short) 1000)
            .bit90OfSupportedMcsSet(false)
            .bit91OfSupportedMcsSet(false)
            .bit92OfSupportedMcsSet(true)
            .bit93OfSupportedMcsSet(false)
            .bit94OfSupportedMcsSet(false)
            .bit95OfSupportedMcsSet(true)
            .txMcsSetDefined(false)
            .txRxMcsSetNotEqual(false)
            .txMaxNumSpatialStreamsSupported(NumSpatialStreams.THREE)
            .txUnequalModulationSupported(true)
            .bit101OfSupportedMcsSet(false)
            .bit102OfSupportedMcsSet(false)
            .bit103OfSupportedMcsSet(true)
            .bit104OfSupportedMcsSet(false)
            .bit105OfSupportedMcsSet(false)
            .bit106OfSupportedMcsSet(true)
            .bit107OfSupportedMcsSet(false)
            .bit108OfSupportedMcsSet(false)
            .bit109OfSupportedMcsSet(true)
            .bit110OfSupportedMcsSet(false)
            .bit111OfSupportedMcsSet(false)
            .bit112OfSupportedMcsSet(true)
            .bit113OfSupportedMcsSet(false)
            .bit114OfSupportedMcsSet(false)
            .bit115OfSupportedMcsSet(true)
            .bit116OfSupportedMcsSet(false)
            .bit117OfSupportedMcsSet(false)
            .bit118OfSupportedMcsSet(true)
            .bit119OfSupportedMcsSet(false)
            .bit120OfSupportedMcsSet(false)
            .bit121OfSupportedMcsSet(true)
            .bit122OfSupportedMcsSet(false)
            .bit123OfSupportedMcsSet(false)
            .bit124OfSupportedMcsSet(true)
            .bit125OfSupportedMcsSet(false)
            .bit126OfSupportedMcsSet(false)
            .bit127OfSupportedMcsSet(true)
            .pcoSupported(false)
            .pcoTransitionTime(PcoTransitionTime.PTT_1_5_MS)
            .bit3OfHtExtendedCapabilities(false)
            .bit4OfHtExtendedCapabilities(true)
            .bit5OfHtExtendedCapabilities(false)
            .bit6OfHtExtendedCapabilities(false)
            .bit7OfHtExtendedCapabilities(true)
            .mcsFeedbackCapability(McsFeedbackCapability.ONLY_UNSOLICITED)
            .htControlFieldSupported(false)
            .rdResponderSupported(false)
            .bit12OfHtExtendedCapabilities(true)
            .bit13OfHtExtendedCapabilities(false)
            .bit14OfHtExtendedCapabilities(false)
            .bit15OfHtExtendedCapabilities(true)
            .implicitTxBeamformingReceivingSupported(false)
            .rxStaggeredSoundingSupported(false)
            .txStaggeredSoundingSupported(true)
            .rxNdpSupported(false)
            .txNdpSupported(false)
            .implicitTxBeamformingSupported(true)
            .calibration(Calibration.RESPOND)
            .explicitCsiTxBeamformingSupported(false)
            .explicitNoncompressedSteeringSupported(false)
            .explicitCompressedSteeringSupported(true)
            .explicitTxBeamformingCsiFeedbackCapability(BeamformingFeedbackCapability.DELAYED)
            .explicitNoncompressedBeamformingFeedbackCapability(
                BeamformingFeedbackCapability.DELAYED_AND_IMMEDIATE)
            .explicitCompressedBeamformingFeedbackCapability(
                BeamformingFeedbackCapability.IMMEDIATE)
            .minGrouping(Grouping.GROUPS_OF_1_2)
            .csiNumBeamformerAntennasSupported(NumBeamformerAntennas.TWO)
            .noncompressedSteeringNumBeamformerAntennasSupported(NumBeamformerAntennas.FOUR)
            .compressedSteeringNumBeamformerAntennasSupported(NumBeamformerAntennas.SINGLE)
            .csiMaxNumRowsBeamformerSupported(CsiNumRows.THREE)
            .channelEstimationCapability(ChannelEstimationCapability.TWO_SPACE_TIME_STREAMS)
            .bit29OfTransmitBeamformingCapabilities(false)
            .bit30OfTransmitBeamformingCapabilities(false)
            .bit31OfTransmitBeamformingCapabilities(true)
            .antennaSelectionSupported(false)
            .explicitCsiFeedbackBasedTxAselSupported(false)
            .antennaIndicesFeedbackBasedTxAselSupported(true)
            .explicitCsiFeedbackSupported(false)
            .antennaIndicesFeedbackSupported(false)
            .rxAselSupported(true)
            .txSoundingPpdusSupported(false)
            .bit7OfAselCapability(false)
            .build();

    this.twentyFortyBssCoexistence =
        new Dot112040BssCoexistenceElement.Builder()
            .correctLengthAtBuild(true)
            .informationRequested(false)
            .fortyMhzIntolerant(false)
            .twentyMhzBssWidthRequested(true)
            .obssScanningExemptionRequested(false)
            .obssScanningExemptionGranted(false)
            .bit5(true)
            .bit6(true)
            .bit7(true)
            .build();

    this.extendedCapabilities =
        new Dot11ExtendedCapabilitiesElement.Builder()
            .correctLengthAtBuild(true)
            .twentyFortyBssCoexistenceManagementSupported(false)
            .bit1(false)
            .extendedChannelSwitchingSupported(true)
            .bit3(false)
            .psmpOperationSupported(false)
            .bit5(true)
            .scheduledPsmpSupported(false)
            .eventActivated(false)
            .diagnosticsActivated(true)
            .multicastDiagnosticsActivated(false)
            .locationTrackingActivated(false)
            .fmsActivated(true)
            .proxyArpServiceActivated(false)
            .collocatedInterferenceReportingActivated(false)
            .rmCivicMeasurementActivated(true)
            .rmLciMeasurementActivated(false)
            .tfsActivated(false)
            .wnmSleepModeActivated(true)
            .timBroadcastActivated(false)
            .bssTransitionActivated(false)
            .qosTrafficCapabilityActivated(true)
            .acStationCountActivated(false)
            .multiBssIdActivated(false)
            .timingMeasurementActivated(true)
            .channelUsageActivated(false)
            .ssidListActivated(false)
            .dmsActivated(true)
            .utcTsfOffsetActivated(false)
            .tdlsPeerUapsdBufferStaSupported(false)
            .tdlsPeerPsmSupported(true)
            .tdlsChannelSwitchingActivated(false)
            .interworkingServiceActivated(false)
            .qosMapActivated(true)
            .ebrActivated(false)
            .sspnInterfaceActivated(false)
            .bit35(true)
            .msgcfActivated(false)
            .tdlsSupported(false)
            .tdlsProhibited(true)
            .tdlsChannelSwitchingProhibited(false)
            .rejectingUnadmittedTraffic(false)
            .serviceIntervalGranularity(Dot11ServiceIntervalGranularity.SIG_35_MS)
            .rmIdentifierMeasurementActivated(false)
            .uapsdCoexistenceActivated(false)
            .wnmNotificationActivated(true)
            .bit47(false)
            .utf8Ssid(false)
            .bit49(true)
            .bit50(false)
            .bit51(false)
            .bit52(true)
            .bit53(false)
            .bit54(false)
            .bit55(true)
            .trailingData(new byte[] {0x12, 0x34})
            .build();

    List<Dot11SsidElement> ssids = new ArrayList<Dot11SsidElement>();
    ssids.add(new Dot11SsidElement.Builder().correctLengthAtBuild(true).ssid("abcde").build());
    ssids.add(
        new Dot11SsidElement.Builder()
            .correctLengthAtBuild(true)
            .ssid("fooooooooooooooooo")
            .build());
    this.ssidList =
        new Dot11SsidListElement.Builder().correctLengthAtBuild(true).ssidList(ssids).build();

    List<Dot11ChannelEntry> channelEntries = new ArrayList<Dot11ChannelEntry>();
    channelEntries.add(new Dot11ChannelEntry((byte) 0x01, (byte) 0x10));
    channelEntries.add(new Dot11ChannelEntry((byte) 0x02, (byte) 0x20));
    channelEntries.add(new Dot11ChannelEntry((byte) 0x03, (byte) 0x30));
    this.channelUsage =
        new Dot11ChannelUsageElement.Builder()
            .correctLengthAtBuild(true)
            .usageMode(Dot11ChannelUsageMode.NONINFRASTRUCTURE_DOT_11)
            .channelEntries(channelEntries)
            .build();

    this.interworking =
        new Dot11InterworkingElement.Builder()
            .correctLengthAtBuild(true)
            .accessnetworkType(Dot11AccessNetworkType.PRIVATE_NETWORK)
            .internet(false)
            .asra(true)
            .esr(false)
            .uesa(true)
            .venueInfo(Dot11VenueInfo.POLICE_STATION)
            .hessid(new byte[] {0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f})
            .build();

    this.meshId =
        new Dot11MeshIdElement.Builder()
            .correctLengthAtBuild(true)
            .meshId(new byte[] {0x50, 0x40, 0x30, 0x20, 0x10, 0x00})
            .build();

    this.vendorSpecificElements = new ArrayList<Dot11VendorSpecificElement>();
    vendorSpecificElements.add(
        new Dot11VendorSpecificElement.Builder()
            .information(new byte[] {1, 1, 1, 1, 1})
            .correctLengthAtBuild(true)
            .build());
    vendorSpecificElements.add(
        new Dot11VendorSpecificElement.Builder()
            .information(new byte[] {2, 2, 2, 2, 2, 2})
            .correctLengthAtBuild(true)
            .build());

    Dot11ProbeRequestPacket.Builder b =
        new Dot11ProbeRequestPacket.Builder()
            .frameControl(frameControl)
            .duration(duration)
            .address1(address1)
            .address2(address2)
            .address3(address3)
            .sequenceControl(sequenceControl)
            .htControl(htControl)
            .ssid(ssid)
            .supportedRates(supportedRates)
            .request(request)
            .extendedSupportedRates(extendedSupportedRates)
            .dsssParameterSet(dsssParameterSet)
            .supportedOperatingClasses(supportedOperatingClasses)
            .htCapabilities(htCapabilities)
            .twentyFortyBssCoexistence(twentyFortyBssCoexistence)
            .extendedCapabilities(extendedCapabilities)
            .ssidList(ssidList)
            .channelUsage(channelUsage)
            .interworking(interworking)
            .meshId(meshId)
            .vendorSpecificElements(vendorSpecificElements);
    this.packet = b.build();
  }

  @Override
  protected Packet getPacket() {
    return packet;
  }

  @Override
  protected Packet getWholePacket() {
    return packet;
  }

  @BeforeClass
  public static void setUpBeforeClass() throws Exception {
    logger.info(
        "########## " + Dot11ProbeRequestPacketTest.class.getSimpleName() + " START ##########");
  }

  @AfterClass
  public static void tearDownAfterClass() throws Exception {}

  @Test
  public void testNewPacket() {
    try {
      Dot11ProbeRequestPacket p =
          Dot11ProbeRequestPacket.newPacket(packet.getRawData(), 0, packet.getRawData().length);
      assertEquals(packet, p);
    } catch (IllegalRawDataException e) {
      throw new AssertionError(e);
    }
  }

  @Test
  public void testGetHeader() {
    Dot11ProbeRequestHeader h = packet.getHeader();
    assertEquals(frameControl, h.getFrameControl());
    assertEquals(duration, h.getDuration());
    assertEquals(address1, h.getAddress1());
    assertEquals(address2, h.getAddress2());
    assertEquals(address3, h.getAddress3());
    assertEquals(sequenceControl, h.getSequenceControl());
    assertEquals(htControl, h.getHtControl());
    assertEquals(ssid, h.getSsid());
    assertEquals(supportedRates, h.getSupportedRates());
    assertEquals(request, h.getRequest());
    assertEquals(extendedSupportedRates, h.getExtendedSupportedRates());
    assertEquals(dsssParameterSet, h.getDsssParameterSet());
    assertEquals(supportedOperatingClasses, h.getSupportedOperatingClasses());
    assertEquals(htCapabilities, h.getHtCapabilities());
    assertEquals(twentyFortyBssCoexistence, h.get2040BssCoexistence());
    assertEquals(extendedCapabilities, h.getExtendedCapabilities());
    assertEquals(ssidList, h.getSsidList());
    assertEquals(channelUsage, h.getChannelUsage());
    assertEquals(interworking, h.getInterworking());
    assertEquals(meshId, h.getMeshId());
    assertEquals(vendorSpecificElements, h.getVendorSpecificElements());
  }

  @Override
  protected DataLinkType getDataLinkType() {
    return DataLinkType.IEEE802_11;
  }

  @Test
  public void testHasValidFcs() {
    assertFalse(packet.hasValidFcs());

    Dot11ProbeRequestPacket.Builder b = packet.getBuilder().fcs(111).correctChecksumAtBuild(false);
    Dot11ProbeRequestPacket p = b.correctChecksumAtBuild(false).build();
    assertFalse(p.hasValidFcs());

    b.correctChecksumAtBuild(true);
    p = b.build();
    assertTrue(p.hasValidFcs());
  }
}
