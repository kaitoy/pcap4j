/*_##########################################################################
  _##
  _##  Copyright (C) 2016  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import java.util.Arrays;
import org.pcap4j.packet.namednumber.Dot11InformationElementId;
import org.pcap4j.packet.namednumber.Dot11ServiceIntervalGranularity;
import org.pcap4j.util.ByteArrays;

/**
 * IEEE802.11 Extended Capabilities element
 *
 * <pre style="white-space: pre;">
 *         1                 1                  n
 * +-----------------+-----------------+-----------------
 * |   Element ID    |     Length      |  Capabilities
 * +-----------------+-----------------+-----------------
 * Element ID: 127
 * </pre>
 *
 * The Extended Capabilities element carries information about the capabilities of an IEEE 802.11
 * STA that augment the Capability Information field (CIF).
 *
 * @see <a href="http://standards.ieee.org/getieee802/download/802.11-2012.pdf">IEEE802.11</a>
 * @author Kaito Yamada
 * @since pcap4j 1.7.0
 */
public final class Dot11ExtendedCapabilitiesElement extends Dot11InformationElement {

  /** */
  private static final long serialVersionUID = 5039470467536222487L;

  private final Boolean twentyFortyBssCoexistenceManagementSupported;
  private final Boolean bit1;
  private final Boolean extendedChannelSwitchingSupported;
  private final Boolean bit3;
  private final Boolean psmpOperationSupported;
  private final Boolean bit5;
  private final Boolean scheduledPsmpSupported;
  private final Boolean eventActivated;
  private final Boolean diagnosticsActivated;
  private final Boolean multicastDiagnosticsActivated;
  private final Boolean locationTrackingActivated;
  private final Boolean fmsActivated;
  private final Boolean proxyArpServiceActivated;
  private final Boolean collocatedInterferenceReportingActivated;
  private final Boolean rmCivicMeasurementActivated;
  private final Boolean rmLciMeasurementActivated;
  private final Boolean tfsActivated;
  private final Boolean wnmSleepModeActivated;
  private final Boolean timBroadcastActivated;
  private final Boolean bssTransitionActivated;
  private final Boolean qosTrafficCapabilityActivated;
  private final Boolean acStationCountActivated;
  private final Boolean multiBssIdActivated;
  private final Boolean timingMeasurementActivated;
  private final Boolean channelUsageActivated;
  private final Boolean ssidListActivated;
  private final Boolean dmsActivated;
  private final Boolean utcTsfOffsetActivated;
  private final Boolean tdlsPeerUapsdBufferStaSupported;
  private final Boolean tdlsPeerPsmSupported;
  private final Boolean tdlsChannelSwitchingActivated;
  private final Boolean interworkingServiceActivated;
  private final Boolean qosMapActivated;
  private final Boolean ebrActivated;
  private final Boolean sspnInterfaceActivated;
  private final Boolean bit35;
  private final Boolean msgcfActivated;
  private final Boolean tdlsSupported;
  private final Boolean tdlsProhibited;
  private final Boolean tdlsChannelSwitchingProhibited;
  private final Boolean rejectingUnadmittedTraffic;
  private final Dot11ServiceIntervalGranularity serviceIntervalGranularity;
  private final Boolean rmIdentifierMeasurementActivated;
  private final Boolean uapsdCoexistenceActivated;
  private final Boolean wnmNotificationActivated;
  private final Boolean bit47;
  private final Boolean utf8Ssid;
  private final Boolean bit49;
  private final Boolean bit50;
  private final Boolean bit51;
  private final Boolean bit52;
  private final Boolean bit53;
  private final Boolean bit54;
  private final Boolean bit55;
  private final byte[] trailingData;
  private final int actualLength;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new Dot11ExtendedCapabilitiesElement object.
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  public static Dot11ExtendedCapabilitiesElement newInstance(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    ByteArrays.validateBounds(rawData, offset, length);
    return new Dot11ExtendedCapabilitiesElement(rawData, offset, length);
  }

  /**
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @throws IllegalRawDataException if parsing the raw data fails.
   */
  private Dot11ExtendedCapabilitiesElement(byte[] rawData, int offset, int length)
      throws IllegalRawDataException {
    super(rawData, offset, length, Dot11InformationElementId.EXTENDED_CAPABILITIES);

    this.actualLength = getLengthAsInt();

    if (actualLength > 0) {
      this.twentyFortyBssCoexistenceManagementSupported = (rawData[offset + 2] & 0x01) != 0;
      this.bit1 = (rawData[offset + 2] & 0x02) != 0;
      this.extendedChannelSwitchingSupported = (rawData[offset + 2] & 0x04) != 0;
      this.bit3 = (rawData[offset + 2] & 0x08) != 0;
      this.psmpOperationSupported = (rawData[offset + 2] & 0x10) != 0;
      this.bit5 = (rawData[offset + 2] & 0x20) != 0;
      this.scheduledPsmpSupported = (rawData[offset + 2] & 0x40) != 0;
      this.eventActivated = (rawData[offset + 2] & 0x80) != 0;
    } else {
      this.twentyFortyBssCoexistenceManagementSupported = null;
      this.bit1 = null;
      this.extendedChannelSwitchingSupported = null;
      this.bit3 = null;
      this.psmpOperationSupported = null;
      this.bit5 = null;
      this.scheduledPsmpSupported = null;
      this.eventActivated = null;
    }

    if (actualLength > 1) {
      this.diagnosticsActivated = (rawData[offset + 3] & 0x01) != 0;
      this.multicastDiagnosticsActivated = (rawData[offset + 3] & 0x02) != 0;
      this.locationTrackingActivated = (rawData[offset + 3] & 0x04) != 0;
      this.fmsActivated = (rawData[offset + 3] & 0x08) != 0;
      this.proxyArpServiceActivated = (rawData[offset + 3] & 0x10) != 0;
      this.collocatedInterferenceReportingActivated = (rawData[offset + 3] & 0x20) != 0;
      this.rmCivicMeasurementActivated = (rawData[offset + 3] & 0x40) != 0;
      this.rmLciMeasurementActivated = (rawData[offset + 3] & 0x80) != 0;
    } else {
      this.diagnosticsActivated = null;
      this.multicastDiagnosticsActivated = null;
      this.locationTrackingActivated = null;
      this.fmsActivated = null;
      this.proxyArpServiceActivated = null;
      this.collocatedInterferenceReportingActivated = null;
      this.rmCivicMeasurementActivated = null;
      this.rmLciMeasurementActivated = null;
    }

    if (actualLength > 2) {
      this.tfsActivated = (rawData[offset + 4] & 0x01) != 0;
      this.wnmSleepModeActivated = (rawData[offset + 4] & 0x02) != 0;
      this.timBroadcastActivated = (rawData[offset + 4] & 0x04) != 0;
      this.bssTransitionActivated = (rawData[offset + 4] & 0x08) != 0;
      this.qosTrafficCapabilityActivated = (rawData[offset + 4] & 0x10) != 0;
      this.acStationCountActivated = (rawData[offset + 4] & 0x20) != 0;
      this.multiBssIdActivated = (rawData[offset + 4] & 0x40) != 0;
      this.timingMeasurementActivated = (rawData[offset + 4] & 0x80) != 0;
    } else {
      this.tfsActivated = null;
      this.wnmSleepModeActivated = null;
      this.timBroadcastActivated = null;
      this.bssTransitionActivated = null;
      this.qosTrafficCapabilityActivated = null;
      this.acStationCountActivated = null;
      this.multiBssIdActivated = null;
      this.timingMeasurementActivated = null;
    }

    if (actualLength > 3) {
      this.channelUsageActivated = (rawData[offset + 5] & 0x01) != 0;
      this.ssidListActivated = (rawData[offset + 5] & 0x02) != 0;
      this.dmsActivated = (rawData[offset + 5] & 0x04) != 0;
      this.utcTsfOffsetActivated = (rawData[offset + 5] & 0x08) != 0;
      this.tdlsPeerUapsdBufferStaSupported = (rawData[offset + 5] & 0x10) != 0;
      this.tdlsPeerPsmSupported = (rawData[offset + 5] & 0x20) != 0;
      this.tdlsChannelSwitchingActivated = (rawData[offset + 5] & 0x40) != 0;
      this.interworkingServiceActivated = (rawData[offset + 5] & 0x80) != 0;
    } else {
      this.channelUsageActivated = null;
      this.ssidListActivated = null;
      this.dmsActivated = null;
      this.utcTsfOffsetActivated = null;
      this.tdlsPeerUapsdBufferStaSupported = null;
      this.tdlsPeerPsmSupported = null;
      this.tdlsChannelSwitchingActivated = null;
      this.interworkingServiceActivated = null;
    }

    if (actualLength > 4) {
      this.qosMapActivated = (rawData[offset + 6] & 0x01) != 0;
      this.ebrActivated = (rawData[offset + 6] & 0x02) != 0;
      this.sspnInterfaceActivated = (rawData[offset + 6] & 0x04) != 0;
      this.bit35 = (rawData[offset + 6] & 0x08) != 0;
      this.msgcfActivated = (rawData[offset + 6] & 0x10) != 0;
      this.tdlsSupported = (rawData[offset + 6] & 0x20) != 0;
      this.tdlsProhibited = (rawData[offset + 6] & 0x40) != 0;
      this.tdlsChannelSwitchingProhibited = (rawData[offset + 6] & 0x80) != 0;
    } else {
      this.qosMapActivated = null;
      this.ebrActivated = null;
      this.sspnInterfaceActivated = null;
      this.bit35 = null;
      this.msgcfActivated = null;
      this.tdlsSupported = null;
      this.tdlsProhibited = null;
      this.tdlsChannelSwitchingProhibited = null;
    }

    if (actualLength > 5) {
      this.rejectingUnadmittedTraffic = (rawData[offset + 7] & 0x01) != 0;
      this.serviceIntervalGranularity =
          Dot11ServiceIntervalGranularity.getInstance((byte) ((rawData[offset + 7] & 0x0E) >> 1));
      this.rmIdentifierMeasurementActivated = (rawData[offset + 7] & 0x10) != 0;
      this.uapsdCoexistenceActivated = (rawData[offset + 7] & 0x20) != 0;
      this.wnmNotificationActivated = (rawData[offset + 7] & 0x40) != 0;
      this.bit47 = (rawData[offset + 7] & 0x80) != 0;
    } else {
      this.rejectingUnadmittedTraffic = null;
      this.serviceIntervalGranularity = null;
      this.rmIdentifierMeasurementActivated = null;
      this.uapsdCoexistenceActivated = null;
      this.wnmNotificationActivated = null;
      this.bit47 = null;
    }

    if (actualLength > 6) {
      this.utf8Ssid = (rawData[offset + 8] & 0x01) != 0;
      this.bit49 = (rawData[offset + 8] & 0x02) != 0;
      this.bit50 = (rawData[offset + 8] & 0x04) != 0;
      this.bit51 = (rawData[offset + 8] & 0x08) != 0;
      this.bit52 = (rawData[offset + 8] & 0x10) != 0;
      this.bit53 = (rawData[offset + 8] & 0x20) != 0;
      this.bit54 = (rawData[offset + 8] & 0x40) != 0;
      this.bit55 = (rawData[offset + 8] & 0x80) != 0;
    } else {
      this.utf8Ssid = null;
      this.bit49 = null;
      this.bit50 = null;
      this.bit51 = null;
      this.bit52 = null;
      this.bit53 = null;
      this.bit54 = null;
      this.bit55 = null;
    }

    if (actualLength > 7) {
      this.trailingData = ByteArrays.getSubArray(rawData, offset + 9, actualLength - 7);
    } else {
      this.trailingData = null;
    }
  }

  /** @param builder builder */
  private Dot11ExtendedCapabilitiesElement(Builder builder) {
    super(builder);

    if (builder.trailingData.length > 248) {
      throw new IllegalArgumentException(
          "Too long trailingData: " + ByteArrays.toHexString(builder.trailingData, " "));
    }

    if (builder.getCorrectLengthAtBuild()) {
      this.actualLength = getLengthAsInt();
    } else {
      this.actualLength = calcActualLength(builder);
    }

    this.twentyFortyBssCoexistenceManagementSupported =
        builder.twentyFortyBssCoexistenceManagementSupported;
    this.bit1 = builder.bit1;
    this.extendedChannelSwitchingSupported = builder.extendedChannelSwitchingSupported;
    this.bit3 = builder.bit3;
    this.psmpOperationSupported = builder.psmpOperationSupported;
    this.bit5 = builder.bit5;
    this.scheduledPsmpSupported = builder.scheduledPsmpSupported;
    this.eventActivated = builder.eventActivated;
    this.diagnosticsActivated = builder.diagnosticsActivated;
    this.multicastDiagnosticsActivated = builder.multicastDiagnosticsActivated;
    this.locationTrackingActivated = builder.locationTrackingActivated;
    this.fmsActivated = builder.fmsActivated;
    this.proxyArpServiceActivated = builder.proxyArpServiceActivated;
    this.collocatedInterferenceReportingActivated =
        builder.collocatedInterferenceReportingActivated;
    this.rmCivicMeasurementActivated = builder.rmCivicMeasurementActivated;
    this.rmLciMeasurementActivated = builder.rmLciMeasurementActivated;
    this.tfsActivated = builder.tfsActivated;
    this.wnmSleepModeActivated = builder.wnmSleepModeActivated;
    this.timBroadcastActivated = builder.timBroadcastActivated;
    this.bssTransitionActivated = builder.bssTransitionActivated;
    this.qosTrafficCapabilityActivated = builder.qosTrafficCapabilityActivated;
    this.acStationCountActivated = builder.acStationCountActivated;
    this.multiBssIdActivated = builder.multiBssIdActivated;
    this.timingMeasurementActivated = builder.timingMeasurementActivated;
    this.channelUsageActivated = builder.channelUsageActivated;
    this.ssidListActivated = builder.ssidListActivated;
    this.dmsActivated = builder.dmsActivated;
    this.utcTsfOffsetActivated = builder.utcTsfOffsetActivated;
    this.tdlsPeerUapsdBufferStaSupported = builder.tdlsPeerUapsdBufferStaSupported;
    this.tdlsPeerPsmSupported = builder.tdlsPeerPsmSupported;
    this.tdlsChannelSwitchingActivated = builder.tdlsChannelSwitchingActivated;
    this.interworkingServiceActivated = builder.interworkingServiceActivated;
    this.qosMapActivated = builder.qosMapActivated;
    this.ebrActivated = builder.ebrActivated;
    this.sspnInterfaceActivated = builder.sspnInterfaceActivated;
    this.bit35 = builder.bit35;
    this.msgcfActivated = builder.msgcfActivated;
    this.tdlsSupported = builder.tdlsSupported;
    this.tdlsProhibited = builder.tdlsProhibited;
    this.tdlsChannelSwitchingProhibited = builder.tdlsChannelSwitchingProhibited;
    this.rejectingUnadmittedTraffic = builder.rejectingUnadmittedTraffic;
    this.serviceIntervalGranularity = builder.serviceIntervalGranularity;
    this.rmIdentifierMeasurementActivated = builder.rmIdentifierMeasurementActivated;
    this.uapsdCoexistenceActivated = builder.uapsdCoexistenceActivated;
    this.wnmNotificationActivated = builder.wnmNotificationActivated;
    this.bit47 = builder.bit47;
    this.utf8Ssid = builder.utf8Ssid;
    this.bit49 = builder.bit49;
    this.bit50 = builder.bit50;
    this.bit51 = builder.bit51;
    this.bit52 = builder.bit52;
    this.bit53 = builder.bit53;
    this.bit54 = builder.bit54;
    this.bit55 = builder.bit55;
    if (builder.trailingData != null) {
      this.trailingData = ByteArrays.clone(builder.trailingData);
    } else {
      this.trailingData = null;
    }
  }

  private static int calcActualLength(Builder builder) {
    if (builder.trailingData != null) {
      return 7 + builder.trailingData.length;
    } else if (builder.utf8Ssid != null
        || builder.bit49 != null
        || builder.bit50 != null
        || builder.bit51 != null
        || builder.bit52 != null
        || builder.bit53 != null
        || builder.bit54 != null
        || builder.bit55 != null) {
      return 7;
    } else if (builder.rejectingUnadmittedTraffic != null
        || builder.serviceIntervalGranularity != null
        || builder.rmIdentifierMeasurementActivated != null
        || builder.uapsdCoexistenceActivated != null
        || builder.wnmNotificationActivated != null
        || builder.bit47 != null) {
      return 6;
    } else if (builder.qosMapActivated != null
        || builder.ebrActivated != null
        || builder.sspnInterfaceActivated != null
        || builder.bit35 != null
        || builder.msgcfActivated != null
        || builder.tdlsSupported != null
        || builder.tdlsProhibited != null
        || builder.tdlsChannelSwitchingProhibited != null) {
      return 5;
    } else if (builder.channelUsageActivated != null
        || builder.ssidListActivated != null
        || builder.dmsActivated != null
        || builder.utcTsfOffsetActivated != null
        || builder.tdlsPeerUapsdBufferStaSupported != null
        || builder.tdlsPeerPsmSupported != null
        || builder.tdlsChannelSwitchingActivated != null
        || builder.interworkingServiceActivated != null) {
      return 4;
    } else if (builder.tfsActivated != null
        || builder.wnmSleepModeActivated != null
        || builder.timBroadcastActivated != null
        || builder.bssTransitionActivated != null
        || builder.qosTrafficCapabilityActivated != null
        || builder.acStationCountActivated != null
        || builder.multiBssIdActivated != null
        || builder.timingMeasurementActivated != null) {
      return 3;
    } else if (builder.diagnosticsActivated != null
        || builder.multicastDiagnosticsActivated != null
        || builder.locationTrackingActivated != null
        || builder.fmsActivated != null
        || builder.proxyArpServiceActivated != null
        || builder.collocatedInterferenceReportingActivated != null
        || builder.rmCivicMeasurementActivated != null
        || builder.rmLciMeasurementActivated != null) {
      return 2;
    } else if (builder.twentyFortyBssCoexistenceManagementSupported != null
        || builder.bit1 != null
        || builder.extendedChannelSwitchingSupported != null
        || builder.bit3 != null
        || builder.psmpOperationSupported != null
        || builder.bit5 != null
        || builder.scheduledPsmpSupported != null
        || builder.eventActivated != null) {
      return 1;
    } else {
      return 0;
    }
  }

  /** @return twentyFortyBssCoexistenceManagementSupported. May be null. */
  public Boolean is2040BssCoexistenceManagementSupported() {
    return twentyFortyBssCoexistenceManagementSupported;
  }

  /** @return bit1. May be null. */
  public Boolean getBit1() {
    return bit1;
  }

  /** @return extendedChannelSwitchingSupported. May be null. */
  public Boolean isExtendedChannelSwitchingSupported() {
    return extendedChannelSwitchingSupported;
  }

  /** @return bit3. May be null. */
  public Boolean getBit3() {
    return bit3;
  }

  /** @return psmpOperationSupported. May be null. */
  public Boolean isPsmpOperationSupported() {
    return psmpOperationSupported;
  }

  /** @return bit5. May be null. */
  public Boolean getBit5() {
    return bit5;
  }

  /** @return scheduledPsmpSupported. May be null. */
  public Boolean isScheduledPsmpSupported() {
    return scheduledPsmpSupported;
  }

  /** @return eventActivated. May be null. */
  public Boolean isEventActivated() {
    return eventActivated;
  }

  /** @return diagnosticsActivated. May be null. */
  public Boolean isDiagnosticsActivated() {
    return diagnosticsActivated;
  }

  /** @return multicastDiagnosticsActivated. May be null. */
  public Boolean isMulticastDiagnosticsActivated() {
    return multicastDiagnosticsActivated;
  }

  /** @return locationTrackingActivated. May be null. */
  public Boolean isLocationTrackingActivated() {
    return locationTrackingActivated;
  }

  /** @return fmsActivated. May be null. */
  public Boolean isFmsActivated() {
    return fmsActivated;
  }

  /** @return proxyArpServiceActivated. May be null. */
  public Boolean isProxyArpServiceActivated() {
    return proxyArpServiceActivated;
  }

  /** @return collocatedInterferenceReportingActivated. May be null. */
  public Boolean isCollocatedInterferenceReportingActivated() {
    return collocatedInterferenceReportingActivated;
  }

  /** @return rmCivicMeasurementActivated. May be null. */
  public Boolean isRmCivicMeasurementActivated() {
    return rmCivicMeasurementActivated;
  }

  /** @return rmLciMeasurementActivated. May be null. */
  public Boolean isRmLciMeasurementActivated() {
    return rmLciMeasurementActivated;
  }

  /** @return tfsActivated. May be null. */
  public Boolean isTfsActivated() {
    return tfsActivated;
  }

  /** @return wnmSleepModeActivated. May be null. */
  public Boolean isWnmSleepModeActivated() {
    return wnmSleepModeActivated;
  }

  /** @return timBroadcastActivated. May be null. */
  public Boolean isTimBroadcastActivated() {
    return timBroadcastActivated;
  }

  /** @return bssTransitionActivated. May be null. */
  public Boolean isBssTransitionActivated() {
    return bssTransitionActivated;
  }

  /** @return qosTrafficCapabilityActivated. May be null. */
  public Boolean isQosTrafficCapabilityActivated() {
    return qosTrafficCapabilityActivated;
  }

  /** @return acStationCountActivated. May be null. */
  public Boolean isAcStationCountActivated() {
    return acStationCountActivated;
  }

  /** @return multiBssIdActivated. May be null. */
  public Boolean isMultiBssIdActivated() {
    return multiBssIdActivated;
  }

  /** @return timingMeasurementActivated. May be null. */
  public Boolean isTimingMeasurementActivated() {
    return timingMeasurementActivated;
  }

  /** @return channelUsageActivated. May be null. */
  public Boolean isChannelUsageActivated() {
    return channelUsageActivated;
  }

  /** @return ssidListActivated. May be null. */
  public Boolean isSsidListActivated() {
    return ssidListActivated;
  }

  /** @return dmsActivated. May be null. */
  public Boolean isDmsActivated() {
    return dmsActivated;
  }

  /** @return utcTsfOffsetActivated. May be null. */
  public Boolean isUtcTsfOffsetActivated() {
    return utcTsfOffsetActivated;
  }

  /** @return tdlsPeerUapsdBufferStaSupported. May be null. */
  public Boolean isTdlsPeerUapsdBufferStaSupported() {
    return tdlsPeerUapsdBufferStaSupported;
  }

  /** @return tdlsPeerPsmSupported. May be null. */
  public Boolean isTdlsPeerPsmSupported() {
    return tdlsPeerPsmSupported;
  }

  /** @return tdlsChannelSwitchingActivated. May be null. */
  public Boolean isTdlsChannelSwitchingActivated() {
    return tdlsChannelSwitchingActivated;
  }

  /** @return interworkingServiceActivated. May be null. */
  public Boolean isInterworkingServiceActivated() {
    return interworkingServiceActivated;
  }

  /** @return qosMapActivated. May be null. */
  public Boolean isQosMapActivated() {
    return qosMapActivated;
  }

  /** @return ebrActivated. May be null. */
  public Boolean isEbrActivated() {
    return ebrActivated;
  }

  /** @return sspnInterfaceActivated. May be null. */
  public Boolean isSspnInterfaceActivated() {
    return sspnInterfaceActivated;
  }

  /** @return bit35. May be null. */
  public Boolean getBit35() {
    return bit35;
  }

  /** @return msgcfActivated. May be null. */
  public Boolean isMsgcfActivated() {
    return msgcfActivated;
  }

  /** @return tdlsSupported. May be null. */
  public Boolean isTdlsSupported() {
    return tdlsSupported;
  }

  /** @return tdlsProhibited. May be null. */
  public Boolean isTdlsProhibited() {
    return tdlsProhibited;
  }

  /** @return tdlsChannelSwitchingProhibited. May be null. */
  public Boolean isTdlsChannelSwitchingProhibited() {
    return tdlsChannelSwitchingProhibited;
  }

  /** @return rejectingUnadmittedTraffic. May be null. */
  public Boolean isRejectingUnadmittedTraffic() {
    return rejectingUnadmittedTraffic;
  }

  /** @return serviceIntervalGranularity. May be null. */
  public Dot11ServiceIntervalGranularity getServiceIntervalGranularity() {
    return serviceIntervalGranularity;
  }

  /** @return rmIdentifierMeasurementActivated. May be null. */
  public Boolean isRmIdentifierMeasurementActivated() {
    return rmIdentifierMeasurementActivated;
  }

  /** @return uapsdCoexistenceActivated. May be null. */
  public Boolean isUapsdCoexistenceActivated() {
    return uapsdCoexistenceActivated;
  }

  /** @return wnmNotificationActivated. May be null. */
  public Boolean isWnmNotificationActivated() {
    return wnmNotificationActivated;
  }

  /** @return bit47. May be null. */
  public Boolean getBit47() {
    return bit47;
  }

  /** @return utf8Ssid. May be null. */
  public Boolean isutf8Ssid() {
    return utf8Ssid;
  }

  /** @return bit49. May be null. */
  public Boolean getBit49() {
    return bit49;
  }

  /** @return bit50. May be null. */
  public Boolean getBit50() {
    return bit50;
  }

  /** @return bit51. May be null. */
  public Boolean getBit51() {
    return bit51;
  }

  /** @return bit52. May be null. */
  public Boolean getBit52() {
    return bit52;
  }

  /** @return bit53. May be null. */
  public Boolean getBit53() {
    return bit53;
  }

  /** @return bit54. May be null. */
  public Boolean getBit54() {
    return bit54;
  }

  /** @return bit55. May be null. */
  public Boolean getBit55() {
    return bit55;
  }

  /** @return trailingData. May be null. */
  public byte[] getTrailingData() {
    return trailingData != null ? ByteArrays.clone(trailingData) : null;
  }

  @Override
  public int length() {
    return actualLength + 2;
  }

  @Override
  public byte[] getRawData() {
    byte[] rawData = new byte[length()];
    rawData[0] = getElementId().value();
    rawData[1] = getLength();
    if (actualLength > 0) {
      if (Boolean.TRUE.equals(twentyFortyBssCoexistenceManagementSupported)) {
        rawData[2] |= 0x01;
      }
      if (Boolean.TRUE.equals(bit1)) {
        rawData[2] |= 0x02;
      }
      if (Boolean.TRUE.equals(extendedChannelSwitchingSupported)) {
        rawData[2] |= 0x04;
      }
      if (Boolean.TRUE.equals(bit3)) {
        rawData[2] |= 0x08;
      }
      if (Boolean.TRUE.equals(psmpOperationSupported)) {
        rawData[2] |= 0x10;
      }
      if (Boolean.TRUE.equals(bit5)) {
        rawData[2] |= 0x20;
      }
      if (Boolean.TRUE.equals(scheduledPsmpSupported)) {
        rawData[2] |= 0x40;
      }
      if (Boolean.TRUE.equals(eventActivated)) {
        rawData[2] |= 0x80;
      }
    }
    if (actualLength > 1) {
      if (Boolean.TRUE.equals(diagnosticsActivated)) {
        rawData[3] |= 0x01;
      }
      if (Boolean.TRUE.equals(multicastDiagnosticsActivated)) {
        rawData[3] |= 0x02;
      }
      if (Boolean.TRUE.equals(locationTrackingActivated)) {
        rawData[3] |= 0x04;
      }
      if (Boolean.TRUE.equals(fmsActivated)) {
        rawData[3] |= 0x08;
      }
      if (Boolean.TRUE.equals(proxyArpServiceActivated)) {
        rawData[3] |= 0x10;
      }
      if (Boolean.TRUE.equals(collocatedInterferenceReportingActivated)) {
        rawData[3] |= 0x20;
      }
      if (Boolean.TRUE.equals(rmCivicMeasurementActivated)) {
        rawData[3] |= 0x40;
      }
      if (Boolean.TRUE.equals(rmLciMeasurementActivated)) {
        rawData[3] |= 0x80;
      }
    }
    if (actualLength > 2) {
      if (Boolean.TRUE.equals(tfsActivated)) {
        rawData[4] |= 0x01;
      }
      if (Boolean.TRUE.equals(wnmSleepModeActivated)) {
        rawData[4] |= 0x02;
      }
      if (Boolean.TRUE.equals(timBroadcastActivated)) {
        rawData[4] |= 0x04;
      }
      if (Boolean.TRUE.equals(bssTransitionActivated)) {
        rawData[4] |= 0x08;
      }
      if (Boolean.TRUE.equals(qosTrafficCapabilityActivated)) {
        rawData[4] |= 0x10;
      }
      if (Boolean.TRUE.equals(acStationCountActivated)) {
        rawData[4] |= 0x20;
      }
      if (Boolean.TRUE.equals(multiBssIdActivated)) {
        rawData[4] |= 0x40;
      }
      if (Boolean.TRUE.equals(timingMeasurementActivated)) {
        rawData[4] |= 0x80;
      }
    }
    if (actualLength > 3) {
      if (Boolean.TRUE.equals(channelUsageActivated)) {
        rawData[5] |= 0x01;
      }
      if (Boolean.TRUE.equals(ssidListActivated)) {
        rawData[5] |= 0x02;
      }
      if (Boolean.TRUE.equals(dmsActivated)) {
        rawData[5] |= 0x04;
      }
      if (Boolean.TRUE.equals(utcTsfOffsetActivated)) {
        rawData[5] |= 0x08;
      }
      if (Boolean.TRUE.equals(tdlsPeerUapsdBufferStaSupported)) {
        rawData[5] |= 0x10;
      }
      if (Boolean.TRUE.equals(tdlsPeerPsmSupported)) {
        rawData[5] |= 0x20;
      }
      if (Boolean.TRUE.equals(tdlsChannelSwitchingActivated)) {
        rawData[5] |= 0x40;
      }
      if (Boolean.TRUE.equals(interworkingServiceActivated)) {
        rawData[5] |= 0x80;
      }
    }
    if (actualLength > 4) {
      if (Boolean.TRUE.equals(qosMapActivated)) {
        rawData[6] |= 0x01;
      }
      if (Boolean.TRUE.equals(ebrActivated)) {
        rawData[6] |= 0x02;
      }
      if (Boolean.TRUE.equals(sspnInterfaceActivated)) {
        rawData[6] |= 0x04;
      }
      if (Boolean.TRUE.equals(bit35)) {
        rawData[6] |= 0x08;
      }
      if (Boolean.TRUE.equals(msgcfActivated)) {
        rawData[6] |= 0x10;
      }
      if (Boolean.TRUE.equals(tdlsSupported)) {
        rawData[6] |= 0x20;
      }
      if (Boolean.TRUE.equals(tdlsProhibited)) {
        rawData[6] |= 0x40;
      }
      if (Boolean.TRUE.equals(tdlsChannelSwitchingProhibited)) {
        rawData[6] |= 0x80;
      }
    }
    if (actualLength > 5) {
      rawData[7] = (byte) (serviceIntervalGranularity.value() << 1);
      if (Boolean.TRUE.equals(rejectingUnadmittedTraffic)) {
        rawData[7] |= 0x01;
      }
      if (Boolean.TRUE.equals(rmIdentifierMeasurementActivated)) {
        rawData[7] |= 0x10;
      }
      if (Boolean.TRUE.equals(uapsdCoexistenceActivated)) {
        rawData[7] |= 0x20;
      }
      if (Boolean.TRUE.equals(wnmNotificationActivated)) {
        rawData[7] |= 0x40;
      }
      if (Boolean.TRUE.equals(bit47)) {
        rawData[7] |= 0x80;
      }
    }
    if (actualLength > 6) {
      if (Boolean.TRUE.equals(utf8Ssid)) {
        rawData[8] |= 0x01;
      }
      if (Boolean.TRUE.equals(bit49)) {
        rawData[8] |= 0x02;
      }
      if (Boolean.TRUE.equals(bit50)) {
        rawData[8] |= 0x04;
      }
      if (Boolean.TRUE.equals(bit51)) {
        rawData[8] |= 0x08;
      }
      if (Boolean.TRUE.equals(bit52)) {
        rawData[8] |= 0x10;
      }
      if (Boolean.TRUE.equals(bit53)) {
        rawData[8] |= 0x20;
      }
      if (Boolean.TRUE.equals(bit54)) {
        rawData[8] |= 0x40;
      }
      if (Boolean.TRUE.equals(bit55)) {
        rawData[8] |= 0x80;
      }
    }
    if (actualLength > 7) {
      System.arraycopy(trailingData, 0, rawData, 9, trailingData.length);
    }
    return rawData;
  }

  /** @return a new Builder object populated with this object's fields. */
  public Builder getBuilder() {
    return new Builder(this);
  }

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = super.hashCode();
    result = prime * result + ((utf8Ssid == null) ? 0 : utf8Ssid.hashCode());
    result =
        prime * result
            + ((acStationCountActivated == null) ? 0 : acStationCountActivated.hashCode());
    result = prime * result + ((bit1 == null) ? 0 : bit1.hashCode());
    result = prime * result + ((bit3 == null) ? 0 : bit3.hashCode());
    result = prime * result + ((bit35 == null) ? 0 : bit35.hashCode());
    result = prime * result + ((bit47 == null) ? 0 : bit47.hashCode());
    result = prime * result + ((bit49 == null) ? 0 : bit49.hashCode());
    result = prime * result + ((bit5 == null) ? 0 : bit5.hashCode());
    result = prime * result + ((bit50 == null) ? 0 : bit50.hashCode());
    result = prime * result + ((bit51 == null) ? 0 : bit51.hashCode());
    result = prime * result + ((bit52 == null) ? 0 : bit52.hashCode());
    result = prime * result + ((bit53 == null) ? 0 : bit53.hashCode());
    result = prime * result + ((bit54 == null) ? 0 : bit54.hashCode());
    result = prime * result + ((bit55 == null) ? 0 : bit55.hashCode());
    result =
        prime * result + ((bssTransitionActivated == null) ? 0 : bssTransitionActivated.hashCode());
    result =
        prime * result + ((channelUsageActivated == null) ? 0 : channelUsageActivated.hashCode());
    result =
        prime * result
            + ((collocatedInterferenceReportingActivated == null)
                ? 0
                : collocatedInterferenceReportingActivated.hashCode());
    result =
        prime * result + ((diagnosticsActivated == null) ? 0 : diagnosticsActivated.hashCode());
    result = prime * result + ((dmsActivated == null) ? 0 : dmsActivated.hashCode());
    result = prime * result + ((ebrActivated == null) ? 0 : ebrActivated.hashCode());
    result = prime * result + ((eventActivated == null) ? 0 : eventActivated.hashCode());
    result =
        prime * result
            + ((extendedChannelSwitchingSupported == null)
                ? 0
                : extendedChannelSwitchingSupported.hashCode());
    result = prime * result + ((fmsActivated == null) ? 0 : fmsActivated.hashCode());
    result =
        prime * result
            + ((interworkingServiceActivated == null)
                ? 0
                : interworkingServiceActivated.hashCode());
    result =
        prime * result
            + ((locationTrackingActivated == null) ? 0 : locationTrackingActivated.hashCode());
    result = prime * result + ((msgcfActivated == null) ? 0 : msgcfActivated.hashCode());
    result = prime * result + ((multiBssIdActivated == null) ? 0 : multiBssIdActivated.hashCode());
    result =
        prime * result
            + ((multicastDiagnosticsActivated == null)
                ? 0
                : multicastDiagnosticsActivated.hashCode());
    result =
        prime * result
            + ((proxyArpServiceActivated == null) ? 0 : proxyArpServiceActivated.hashCode());
    result =
        prime * result + ((psmpOperationSupported == null) ? 0 : psmpOperationSupported.hashCode());
    result = prime * result + ((qosMapActivated == null) ? 0 : qosMapActivated.hashCode());
    result =
        prime * result
            + ((qosTrafficCapabilityActivated == null)
                ? 0
                : qosTrafficCapabilityActivated.hashCode());
    result =
        prime * result
            + ((rejectingUnadmittedTraffic == null) ? 0 : rejectingUnadmittedTraffic.hashCode());
    result =
        prime * result
            + ((rmCivicMeasurementActivated == null) ? 0 : rmCivicMeasurementActivated.hashCode());
    result =
        prime * result
            + ((rmIdentifierMeasurementActivated == null)
                ? 0
                : rmIdentifierMeasurementActivated.hashCode());
    result =
        prime * result
            + ((rmLciMeasurementActivated == null) ? 0 : rmLciMeasurementActivated.hashCode());
    result =
        prime * result + ((scheduledPsmpSupported == null) ? 0 : scheduledPsmpSupported.hashCode());
    result =
        prime * result
            + ((serviceIntervalGranularity == null) ? 0 : serviceIntervalGranularity.hashCode());
    result = prime * result + ((ssidListActivated == null) ? 0 : ssidListActivated.hashCode());
    result =
        prime * result + ((sspnInterfaceActivated == null) ? 0 : sspnInterfaceActivated.hashCode());
    result =
        prime * result
            + ((tdlsChannelSwitchingActivated == null)
                ? 0
                : tdlsChannelSwitchingActivated.hashCode());
    result =
        prime * result
            + ((tdlsChannelSwitchingProhibited == null)
                ? 0
                : tdlsChannelSwitchingProhibited.hashCode());
    result =
        prime * result + ((tdlsPeerPsmSupported == null) ? 0 : tdlsPeerPsmSupported.hashCode());
    result =
        prime * result
            + ((tdlsPeerUapsdBufferStaSupported == null)
                ? 0
                : tdlsPeerUapsdBufferStaSupported.hashCode());
    result = prime * result + ((tdlsProhibited == null) ? 0 : tdlsProhibited.hashCode());
    result = prime * result + ((tdlsSupported == null) ? 0 : tdlsSupported.hashCode());
    result = prime * result + ((tfsActivated == null) ? 0 : tfsActivated.hashCode());
    result =
        prime * result + ((timBroadcastActivated == null) ? 0 : timBroadcastActivated.hashCode());
    result =
        prime * result
            + ((timingMeasurementActivated == null) ? 0 : timingMeasurementActivated.hashCode());
    result = prime * result + Arrays.hashCode(trailingData);
    result =
        prime * result
            + ((twentyFortyBssCoexistenceManagementSupported == null)
                ? 0
                : twentyFortyBssCoexistenceManagementSupported.hashCode());
    result =
        prime * result
            + ((uapsdCoexistenceActivated == null) ? 0 : uapsdCoexistenceActivated.hashCode());
    result =
        prime * result + ((utcTsfOffsetActivated == null) ? 0 : utcTsfOffsetActivated.hashCode());
    result =
        prime * result
            + ((wnmNotificationActivated == null) ? 0 : wnmNotificationActivated.hashCode());
    result =
        prime * result + ((wnmSleepModeActivated == null) ? 0 : wnmSleepModeActivated.hashCode());
    return result;
  }

  @Override
  public boolean equals(Object obj) {
    if (!super.equals(obj)) return false;
    Dot11ExtendedCapabilitiesElement other = (Dot11ExtendedCapabilitiesElement) obj;
    if (utf8Ssid == null) {
      if (other.utf8Ssid != null) return false;
    } else if (!utf8Ssid.equals(other.utf8Ssid)) return false;
    if (acStationCountActivated == null) {
      if (other.acStationCountActivated != null) return false;
    } else if (!acStationCountActivated.equals(other.acStationCountActivated)) return false;
    if (bit1 == null) {
      if (other.bit1 != null) return false;
    } else if (!bit1.equals(other.bit1)) return false;
    if (bit3 == null) {
      if (other.bit3 != null) return false;
    } else if (!bit3.equals(other.bit3)) return false;
    if (bit35 == null) {
      if (other.bit35 != null) return false;
    } else if (!bit35.equals(other.bit35)) return false;
    if (bit47 == null) {
      if (other.bit47 != null) return false;
    } else if (!bit47.equals(other.bit47)) return false;
    if (bit49 == null) {
      if (other.bit49 != null) return false;
    } else if (!bit49.equals(other.bit49)) return false;
    if (bit5 == null) {
      if (other.bit5 != null) return false;
    } else if (!bit5.equals(other.bit5)) return false;
    if (bit50 == null) {
      if (other.bit50 != null) return false;
    } else if (!bit50.equals(other.bit50)) return false;
    if (bit51 == null) {
      if (other.bit51 != null) return false;
    } else if (!bit51.equals(other.bit51)) return false;
    if (bit52 == null) {
      if (other.bit52 != null) return false;
    } else if (!bit52.equals(other.bit52)) return false;
    if (bit53 == null) {
      if (other.bit53 != null) return false;
    } else if (!bit53.equals(other.bit53)) return false;
    if (bit54 == null) {
      if (other.bit54 != null) return false;
    } else if (!bit54.equals(other.bit54)) return false;
    if (bit55 == null) {
      if (other.bit55 != null) return false;
    } else if (!bit55.equals(other.bit55)) return false;
    if (bssTransitionActivated == null) {
      if (other.bssTransitionActivated != null) return false;
    } else if (!bssTransitionActivated.equals(other.bssTransitionActivated)) return false;
    if (channelUsageActivated == null) {
      if (other.channelUsageActivated != null) return false;
    } else if (!channelUsageActivated.equals(other.channelUsageActivated)) return false;
    if (collocatedInterferenceReportingActivated == null) {
      if (other.collocatedInterferenceReportingActivated != null) return false;
    } else if (!collocatedInterferenceReportingActivated.equals(
        other.collocatedInterferenceReportingActivated)) return false;
    if (diagnosticsActivated == null) {
      if (other.diagnosticsActivated != null) return false;
    } else if (!diagnosticsActivated.equals(other.diagnosticsActivated)) return false;
    if (dmsActivated == null) {
      if (other.dmsActivated != null) return false;
    } else if (!dmsActivated.equals(other.dmsActivated)) return false;
    if (ebrActivated == null) {
      if (other.ebrActivated != null) return false;
    } else if (!ebrActivated.equals(other.ebrActivated)) return false;
    if (eventActivated == null) {
      if (other.eventActivated != null) return false;
    } else if (!eventActivated.equals(other.eventActivated)) return false;
    if (extendedChannelSwitchingSupported == null) {
      if (other.extendedChannelSwitchingSupported != null) return false;
    } else if (!extendedChannelSwitchingSupported.equals(other.extendedChannelSwitchingSupported))
      return false;
    if (fmsActivated == null) {
      if (other.fmsActivated != null) return false;
    } else if (!fmsActivated.equals(other.fmsActivated)) return false;
    if (interworkingServiceActivated == null) {
      if (other.interworkingServiceActivated != null) return false;
    } else if (!interworkingServiceActivated.equals(other.interworkingServiceActivated))
      return false;
    if (locationTrackingActivated == null) {
      if (other.locationTrackingActivated != null) return false;
    } else if (!locationTrackingActivated.equals(other.locationTrackingActivated)) return false;
    if (msgcfActivated == null) {
      if (other.msgcfActivated != null) return false;
    } else if (!msgcfActivated.equals(other.msgcfActivated)) return false;
    if (multiBssIdActivated == null) {
      if (other.multiBssIdActivated != null) return false;
    } else if (!multiBssIdActivated.equals(other.multiBssIdActivated)) return false;
    if (multicastDiagnosticsActivated == null) {
      if (other.multicastDiagnosticsActivated != null) return false;
    } else if (!multicastDiagnosticsActivated.equals(other.multicastDiagnosticsActivated))
      return false;
    if (proxyArpServiceActivated == null) {
      if (other.proxyArpServiceActivated != null) return false;
    } else if (!proxyArpServiceActivated.equals(other.proxyArpServiceActivated)) return false;
    if (psmpOperationSupported == null) {
      if (other.psmpOperationSupported != null) return false;
    } else if (!psmpOperationSupported.equals(other.psmpOperationSupported)) return false;
    if (qosMapActivated == null) {
      if (other.qosMapActivated != null) return false;
    } else if (!qosMapActivated.equals(other.qosMapActivated)) return false;
    if (qosTrafficCapabilityActivated == null) {
      if (other.qosTrafficCapabilityActivated != null) return false;
    } else if (!qosTrafficCapabilityActivated.equals(other.qosTrafficCapabilityActivated))
      return false;
    if (rejectingUnadmittedTraffic == null) {
      if (other.rejectingUnadmittedTraffic != null) return false;
    } else if (!rejectingUnadmittedTraffic.equals(other.rejectingUnadmittedTraffic)) return false;
    if (rmCivicMeasurementActivated == null) {
      if (other.rmCivicMeasurementActivated != null) return false;
    } else if (!rmCivicMeasurementActivated.equals(other.rmCivicMeasurementActivated)) return false;
    if (rmIdentifierMeasurementActivated == null) {
      if (other.rmIdentifierMeasurementActivated != null) return false;
    } else if (!rmIdentifierMeasurementActivated.equals(other.rmIdentifierMeasurementActivated))
      return false;
    if (rmLciMeasurementActivated == null) {
      if (other.rmLciMeasurementActivated != null) return false;
    } else if (!rmLciMeasurementActivated.equals(other.rmLciMeasurementActivated)) return false;
    if (scheduledPsmpSupported == null) {
      if (other.scheduledPsmpSupported != null) return false;
    } else if (!scheduledPsmpSupported.equals(other.scheduledPsmpSupported)) return false;
    if (serviceIntervalGranularity == null) {
      if (other.serviceIntervalGranularity != null) return false;
    } else if (!serviceIntervalGranularity.equals(other.serviceIntervalGranularity)) return false;
    if (ssidListActivated == null) {
      if (other.ssidListActivated != null) return false;
    } else if (!ssidListActivated.equals(other.ssidListActivated)) return false;
    if (sspnInterfaceActivated == null) {
      if (other.sspnInterfaceActivated != null) return false;
    } else if (!sspnInterfaceActivated.equals(other.sspnInterfaceActivated)) return false;
    if (tdlsChannelSwitchingActivated == null) {
      if (other.tdlsChannelSwitchingActivated != null) return false;
    } else if (!tdlsChannelSwitchingActivated.equals(other.tdlsChannelSwitchingActivated))
      return false;
    if (tdlsChannelSwitchingProhibited == null) {
      if (other.tdlsChannelSwitchingProhibited != null) return false;
    } else if (!tdlsChannelSwitchingProhibited.equals(other.tdlsChannelSwitchingProhibited))
      return false;
    if (tdlsPeerPsmSupported == null) {
      if (other.tdlsPeerPsmSupported != null) return false;
    } else if (!tdlsPeerPsmSupported.equals(other.tdlsPeerPsmSupported)) return false;
    if (tdlsPeerUapsdBufferStaSupported == null) {
      if (other.tdlsPeerUapsdBufferStaSupported != null) return false;
    } else if (!tdlsPeerUapsdBufferStaSupported.equals(other.tdlsPeerUapsdBufferStaSupported))
      return false;
    if (tdlsProhibited == null) {
      if (other.tdlsProhibited != null) return false;
    } else if (!tdlsProhibited.equals(other.tdlsProhibited)) return false;
    if (tdlsSupported == null) {
      if (other.tdlsSupported != null) return false;
    } else if (!tdlsSupported.equals(other.tdlsSupported)) return false;
    if (tfsActivated == null) {
      if (other.tfsActivated != null) return false;
    } else if (!tfsActivated.equals(other.tfsActivated)) return false;
    if (timBroadcastActivated == null) {
      if (other.timBroadcastActivated != null) return false;
    } else if (!timBroadcastActivated.equals(other.timBroadcastActivated)) return false;
    if (timingMeasurementActivated == null) {
      if (other.timingMeasurementActivated != null) return false;
    } else if (!timingMeasurementActivated.equals(other.timingMeasurementActivated)) return false;
    if (!Arrays.equals(trailingData, other.trailingData)) return false;
    if (twentyFortyBssCoexistenceManagementSupported == null) {
      if (other.twentyFortyBssCoexistenceManagementSupported != null) return false;
    } else if (!twentyFortyBssCoexistenceManagementSupported.equals(
        other.twentyFortyBssCoexistenceManagementSupported)) return false;
    if (uapsdCoexistenceActivated == null) {
      if (other.uapsdCoexistenceActivated != null) return false;
    } else if (!uapsdCoexistenceActivated.equals(other.uapsdCoexistenceActivated)) return false;
    if (utcTsfOffsetActivated == null) {
      if (other.utcTsfOffsetActivated != null) return false;
    } else if (!utcTsfOffsetActivated.equals(other.utcTsfOffsetActivated)) return false;
    if (wnmNotificationActivated == null) {
      if (other.wnmNotificationActivated != null) return false;
    } else if (!wnmNotificationActivated.equals(other.wnmNotificationActivated)) return false;
    if (wnmSleepModeActivated == null) {
      if (other.wnmSleepModeActivated != null) return false;
    } else if (!wnmSleepModeActivated.equals(other.wnmSleepModeActivated)) return false;
    return true;
  }

  @Override
  public String toString() {
    return toString("");
  }

  /**
   * @param indent indent
   * @return the string representation of this object.
   */
  public String toString(String indent) {
    StringBuilder sb = new StringBuilder();
    String ls = System.getProperty("line.separator");

    sb.append(indent).append("Extended Capabilities:").append(ls);
    sb.append(indent).append("  Element ID: ").append(getElementId()).append(ls);
    sb.append(indent).append("  Length: ").append(getLengthAsInt()).append(" bytes").append(ls);
    if (actualLength > 0) {
      sb.append(indent)
          .append("  20/40 BSS Coexistence Management Supported: ")
          .append(twentyFortyBssCoexistenceManagementSupported)
          .append(ls);
      sb.append(indent).append("  Bit1: ").append(bit1).append(ls);
      sb.append(indent)
          .append("  Extended Channel Switching Supported: ")
          .append(extendedChannelSwitchingSupported)
          .append(ls);
      sb.append(indent).append("  Bit3: ").append(bit3).append(ls);
      sb.append(indent)
          .append("  PSMP Operation Supported: ")
          .append(psmpOperationSupported)
          .append(ls);
      sb.append(indent).append("  Bit5: ").append(bit5).append(ls);
      sb.append(indent)
          .append("  Scheduled PSMP Supported: ")
          .append(scheduledPsmpSupported)
          .append(ls);
      sb.append(indent).append("  Event Activated: ").append(eventActivated).append(ls);
    }
    if (actualLength > 1) {
      sb.append(indent).append("  Diagnostics Activated: ").append(diagnosticsActivated).append(ls);
      sb.append(indent)
          .append("  Multicast Diagnostics Activated: ")
          .append(multicastDiagnosticsActivated)
          .append(ls);
      sb.append(indent)
          .append("  Location Tracking Activated: ")
          .append(locationTrackingActivated)
          .append(ls);
      sb.append(indent).append("  FMS Activated: ").append(fmsActivated).append(ls);
      sb.append(indent)
          .append("  Proxy ARP Service Activated: ")
          .append(proxyArpServiceActivated)
          .append(ls);
      sb.append(indent)
          .append("  Collocated Interference Reporting Activated: ")
          .append(collocatedInterferenceReportingActivated)
          .append(ls);
      sb.append(indent)
          .append("  RM Civic Measurement Activated: ")
          .append(rmCivicMeasurementActivated)
          .append(ls);
      sb.append(indent)
          .append("  RM LCI Measurement Activated: ")
          .append(rmLciMeasurementActivated)
          .append(ls);
    }
    if (actualLength > 2) {
      sb.append(indent).append("  TFS Activated: ").append(tfsActivated).append(ls);
      sb.append(indent)
          .append("  WNM Sleep Mode Activated: ")
          .append(wnmSleepModeActivated)
          .append(ls);
      sb.append(indent)
          .append("  TIM Broadcast Activated: ")
          .append(timBroadcastActivated)
          .append(ls);
      sb.append(indent)
          .append("  BSS Transition Activated: ")
          .append(bssTransitionActivated)
          .append(ls);
      sb.append(indent)
          .append("  QoS Traffic Capability Activated: ")
          .append(qosTrafficCapabilityActivated)
          .append(ls);
      sb.append(indent)
          .append("  AC Station Count Activated: ")
          .append(acStationCountActivated)
          .append(ls);
      sb.append(indent).append("  Multi BSS ID Activated: ").append(multiBssIdActivated).append(ls);
      sb.append(indent)
          .append("  Timing Measurement Activated: ")
          .append(timingMeasurementActivated)
          .append(ls);
    }
    if (actualLength > 3) {
      sb.append(indent)
          .append("  Channel Usage Activated: ")
          .append(channelUsageActivated)
          .append(ls);
      sb.append(indent).append("  SSID List Activated: ").append(ssidListActivated).append(ls);
      sb.append(indent).append("  DMS Activated: ").append(dmsActivated).append(ls);
      sb.append(indent)
          .append("  UTC TSF Offset Activated: ")
          .append(utcTsfOffsetActivated)
          .append(ls);
      sb.append(indent)
          .append("  TDLS Peer U-APSD Buffer STA Supported: ")
          .append(tdlsPeerUapsdBufferStaSupported)
          .append(ls);
      sb.append(indent)
          .append("  TDLS Peer PSM Supported: ")
          .append(tdlsPeerPsmSupported)
          .append(ls);
      sb.append(indent)
          .append("  TDLS Channel Switching Activated: ")
          .append(tdlsChannelSwitchingActivated)
          .append(ls);
      sb.append(indent)
          .append("  Interworking Service Activated: ")
          .append(interworkingServiceActivated)
          .append(ls);
    }
    if (actualLength > 4) {
      sb.append(indent).append("  QoS Map Activated: ").append(qosMapActivated).append(ls);
      sb.append(indent).append("  EBR Activated: ").append(ebrActivated).append(ls);
      sb.append(indent)
          .append("  SSPN Interface Activated: ")
          .append(sspnInterfaceActivated)
          .append(ls);
      sb.append(indent).append("  Bit35: ").append(bit35).append(ls);
      sb.append(indent).append("  MSGCF Activated: ").append(msgcfActivated).append(ls);
      sb.append(indent).append("  TDLS Supported: ").append(tdlsSupported).append(ls);
      sb.append(indent).append("  TDLS Prohibited: ").append(tdlsProhibited).append(ls);
      sb.append(indent)
          .append("  TDLS Channel Switching Prohibited: ")
          .append(tdlsChannelSwitchingProhibited)
          .append(ls);
    }
    if (actualLength > 5) {
      sb.append(indent)
          .append("  Rejecting Unadmitted Traffic: ")
          .append(rejectingUnadmittedTraffic)
          .append(ls);
      sb.append(indent)
          .append("  Service Interval Granularity: ")
          .append(serviceIntervalGranularity)
          .append(ls);
      sb.append(indent)
          .append("  RM Identifier Measurement Activated: ")
          .append(rmIdentifierMeasurementActivated)
          .append(ls);
      sb.append(indent)
          .append("  U-APSD Coexistence Activated: ")
          .append(uapsdCoexistenceActivated)
          .append(ls);
      sb.append(indent)
          .append("  WNM-Notification Activated: ")
          .append(wnmNotificationActivated)
          .append(ls);
      sb.append(indent).append("  Bit47: ").append(bit47).append(ls);
    }
    if (actualLength > 6) {
      sb.append(indent).append("  UTF-8 SSID: ").append(utf8Ssid).append(ls);
      sb.append(indent).append("  Bit49: ").append(bit49).append(ls);
      sb.append(indent).append("  Bit50: ").append(bit50).append(ls);
      sb.append(indent).append("  Bit51: ").append(bit51).append(ls);
      sb.append(indent).append("  Bit52: ").append(bit52).append(ls);
      sb.append(indent).append("  Bit53: ").append(bit53).append(ls);
      sb.append(indent).append("  Bit54: ").append(bit54).append(ls);
      sb.append(indent).append("  Bit55: ").append(bit55).append(ls);
    }
    if (actualLength > 7) {
      sb.append(indent)
          .append("  Trailing Data: 0x")
          .append(ByteArrays.toHexString(trailingData, ""))
          .append(ls);
    }

    return sb.toString();
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 1.7.0
   */
  public static final class Builder extends Dot11InformationElement.Builder {

    private Boolean twentyFortyBssCoexistenceManagementSupported;
    private Boolean bit1;
    private Boolean extendedChannelSwitchingSupported;
    private Boolean bit3;
    private Boolean psmpOperationSupported;
    private Boolean bit5;
    private Boolean scheduledPsmpSupported;
    private Boolean eventActivated;
    private Boolean diagnosticsActivated;
    private Boolean multicastDiagnosticsActivated;
    private Boolean locationTrackingActivated;
    private Boolean fmsActivated;
    private Boolean proxyArpServiceActivated;
    private Boolean collocatedInterferenceReportingActivated;
    private Boolean rmCivicMeasurementActivated;
    private Boolean rmLciMeasurementActivated;
    private Boolean tfsActivated;
    private Boolean wnmSleepModeActivated;
    private Boolean timBroadcastActivated;
    private Boolean bssTransitionActivated;
    private Boolean qosTrafficCapabilityActivated;
    private Boolean acStationCountActivated;
    private Boolean multiBssIdActivated;
    private Boolean timingMeasurementActivated;
    private Boolean channelUsageActivated;
    private Boolean ssidListActivated;
    private Boolean dmsActivated;
    private Boolean utcTsfOffsetActivated;
    private Boolean tdlsPeerUapsdBufferStaSupported;
    private Boolean tdlsPeerPsmSupported;
    private Boolean tdlsChannelSwitchingActivated;
    private Boolean interworkingServiceActivated;
    private Boolean qosMapActivated;
    private Boolean ebrActivated;
    private Boolean sspnInterfaceActivated;
    private Boolean bit35;
    private Boolean msgcfActivated;
    private Boolean tdlsSupported;
    private Boolean tdlsProhibited;
    private Boolean tdlsChannelSwitchingProhibited;
    private Boolean rejectingUnadmittedTraffic;
    private Dot11ServiceIntervalGranularity serviceIntervalGranularity;
    private Boolean rmIdentifierMeasurementActivated;
    private Boolean uapsdCoexistenceActivated;
    private Boolean wnmNotificationActivated;
    private Boolean bit47;
    private Boolean utf8Ssid;
    private Boolean bit49;
    private Boolean bit50;
    private Boolean bit51;
    private Boolean bit52;
    private Boolean bit53;
    private Boolean bit54;
    private Boolean bit55;
    private byte[] trailingData;

    /** */
    public Builder() {
      elementId(
          Dot11InformationElementId.getInstance(
              Dot11InformationElementId.EXTENDED_CAPABILITIES.value()));
    }

    /** @param elem a Dot11ExtendedCapabilitiesElement object. */
    private Builder(Dot11ExtendedCapabilitiesElement elem) {
      super(elem);
      this.twentyFortyBssCoexistenceManagementSupported =
          elem.twentyFortyBssCoexistenceManagementSupported;
      this.bit1 = elem.bit1;
      this.extendedChannelSwitchingSupported = elem.extendedChannelSwitchingSupported;
      this.bit3 = elem.bit3;
      this.psmpOperationSupported = elem.psmpOperationSupported;
      this.bit5 = elem.bit5;
      this.scheduledPsmpSupported = elem.scheduledPsmpSupported;
      this.eventActivated = elem.eventActivated;
      this.diagnosticsActivated = elem.diagnosticsActivated;
      this.multicastDiagnosticsActivated = elem.multicastDiagnosticsActivated;
      this.locationTrackingActivated = elem.locationTrackingActivated;
      this.fmsActivated = elem.fmsActivated;
      this.proxyArpServiceActivated = elem.proxyArpServiceActivated;
      this.collocatedInterferenceReportingActivated = elem.collocatedInterferenceReportingActivated;
      this.rmCivicMeasurementActivated = elem.rmCivicMeasurementActivated;
      this.rmLciMeasurementActivated = elem.rmLciMeasurementActivated;
      this.tfsActivated = elem.tfsActivated;
      this.wnmSleepModeActivated = elem.wnmSleepModeActivated;
      this.timBroadcastActivated = elem.timBroadcastActivated;
      this.bssTransitionActivated = elem.bssTransitionActivated;
      this.qosTrafficCapabilityActivated = elem.qosTrafficCapabilityActivated;
      this.acStationCountActivated = elem.acStationCountActivated;
      this.multiBssIdActivated = elem.multiBssIdActivated;
      this.timingMeasurementActivated = elem.timingMeasurementActivated;
      this.channelUsageActivated = elem.channelUsageActivated;
      this.ssidListActivated = elem.ssidListActivated;
      this.dmsActivated = elem.dmsActivated;
      this.utcTsfOffsetActivated = elem.utcTsfOffsetActivated;
      this.tdlsPeerUapsdBufferStaSupported = elem.tdlsPeerUapsdBufferStaSupported;
      this.tdlsPeerPsmSupported = elem.tdlsPeerPsmSupported;
      this.tdlsChannelSwitchingActivated = elem.tdlsChannelSwitchingActivated;
      this.interworkingServiceActivated = elem.interworkingServiceActivated;
      this.qosMapActivated = elem.qosMapActivated;
      this.ebrActivated = elem.ebrActivated;
      this.sspnInterfaceActivated = elem.sspnInterfaceActivated;
      this.bit35 = elem.bit35;
      this.msgcfActivated = elem.msgcfActivated;
      this.tdlsSupported = elem.tdlsSupported;
      this.tdlsProhibited = elem.tdlsProhibited;
      this.tdlsChannelSwitchingProhibited = elem.tdlsChannelSwitchingProhibited;
      this.rejectingUnadmittedTraffic = elem.rejectingUnadmittedTraffic;
      this.serviceIntervalGranularity = elem.serviceIntervalGranularity;
      this.rmIdentifierMeasurementActivated = elem.rmIdentifierMeasurementActivated;
      this.uapsdCoexistenceActivated = elem.uapsdCoexistenceActivated;
      this.wnmNotificationActivated = elem.wnmNotificationActivated;
      this.bit47 = elem.bit47;
      this.utf8Ssid = elem.utf8Ssid;
      this.bit49 = elem.bit49;
      this.bit50 = elem.bit50;
      this.bit51 = elem.bit51;
      this.bit52 = elem.bit52;
      this.bit53 = elem.bit53;
      this.bit54 = elem.bit54;
      this.bit55 = elem.bit55;
      this.trailingData = elem.trailingData;
    }

    /**
     * @param twentyFortyBssCoexistenceManagementSupported
     *     twentyFortyBssCoexistenceManagementSupported
     * @return this Builder object for method chaining.
     */
    public Builder twentyFortyBssCoexistenceManagementSupported(
        Boolean twentyFortyBssCoexistenceManagementSupported) {
      this.twentyFortyBssCoexistenceManagementSupported =
          twentyFortyBssCoexistenceManagementSupported;
      return this;
    }

    /**
     * @param bit1 bit1
     * @return this Builder object for method chaining.
     */
    public Builder bit1(Boolean bit1) {
      this.bit1 = bit1;
      return this;
    }

    /**
     * @param extendedChannelSwitchingSupported extendedChannelSwitchingSupported
     * @return this Builder object for method chaining.
     */
    public Builder extendedChannelSwitchingSupported(Boolean extendedChannelSwitchingSupported) {
      this.extendedChannelSwitchingSupported = extendedChannelSwitchingSupported;
      return this;
    }

    /**
     * @param bit3 bit3
     * @return this Builder object for method chaining.
     */
    public Builder bit3(Boolean bit3) {
      this.bit3 = bit3;
      return this;
    }

    /**
     * @param psmpOperationSupported psmpOperationSupported
     * @return this Builder object for method chaining.
     */
    public Builder psmpOperationSupported(Boolean psmpOperationSupported) {
      this.psmpOperationSupported = psmpOperationSupported;
      return this;
    }

    /**
     * @param bit5 bit5
     * @return this Builder object for method chaining.
     */
    public Builder bit5(Boolean bit5) {
      this.bit5 = bit5;
      return this;
    }

    /**
     * @param scheduledPsmpSupported scheduledPsmpSupported
     * @return this Builder object for method chaining.
     */
    public Builder scheduledPsmpSupported(Boolean scheduledPsmpSupported) {
      this.scheduledPsmpSupported = scheduledPsmpSupported;
      return this;
    }

    /**
     * @param eventActivated eventActivated
     * @return this Builder object for method chaining.
     */
    public Builder eventActivated(Boolean eventActivated) {
      this.eventActivated = eventActivated;
      return this;
    }

    /**
     * @param diagnosticsActivated diagnosticsActivated
     * @return this Builder object for method chaining.
     */
    public Builder diagnosticsActivated(Boolean diagnosticsActivated) {
      this.diagnosticsActivated = diagnosticsActivated;
      return this;
    }

    /**
     * @param multicastDiagnosticsActivated multicastDiagnosticsActivated
     * @return this Builder object for method chaining.
     */
    public Builder multicastDiagnosticsActivated(Boolean multicastDiagnosticsActivated) {
      this.multicastDiagnosticsActivated = multicastDiagnosticsActivated;
      return this;
    }

    /**
     * @param locationTrackingActivated locationTrackingActivated
     * @return this Builder object for method chaining.
     */
    public Builder locationTrackingActivated(Boolean locationTrackingActivated) {
      this.locationTrackingActivated = locationTrackingActivated;
      return this;
    }

    /**
     * @param fmsActivated fmsActivated
     * @return this Builder object for method chaining.
     */
    public Builder fmsActivated(Boolean fmsActivated) {
      this.fmsActivated = fmsActivated;
      return this;
    }

    /**
     * @param proxyArpServiceActivated proxyArpServiceActivated
     * @return this Builder object for method chaining.
     */
    public Builder proxyArpServiceActivated(Boolean proxyArpServiceActivated) {
      this.proxyArpServiceActivated = proxyArpServiceActivated;
      return this;
    }

    /**
     * @param collocatedInterferenceReportingActivated collocatedInterferenceReportingActivated
     * @return this Builder object for method chaining.
     */
    public Builder collocatedInterferenceReportingActivated(
        Boolean collocatedInterferenceReportingActivated) {
      this.collocatedInterferenceReportingActivated = collocatedInterferenceReportingActivated;
      return this;
    }

    /**
     * @param rmCivicMeasurementActivated rmCivicMeasurementActivated
     * @return this Builder object for method chaining.
     */
    public Builder rmCivicMeasurementActivated(Boolean rmCivicMeasurementActivated) {
      this.rmCivicMeasurementActivated = rmCivicMeasurementActivated;
      return this;
    }

    /**
     * @param rmLciMeasurementActivated rmLciMeasurementActivated
     * @return this Builder object for method chaining.
     */
    public Builder rmLciMeasurementActivated(Boolean rmLciMeasurementActivated) {
      this.rmLciMeasurementActivated = rmLciMeasurementActivated;
      return this;
    }

    /**
     * @param tfsActivated tfsActivated
     * @return this Builder object for method chaining.
     */
    public Builder tfsActivated(Boolean tfsActivated) {
      this.tfsActivated = tfsActivated;
      return this;
    }

    /**
     * @param wnmSleepModeActivated wnmSleepModeActivated
     * @return this Builder object for method chaining.
     */
    public Builder wnmSleepModeActivated(Boolean wnmSleepModeActivated) {
      this.wnmSleepModeActivated = wnmSleepModeActivated;
      return this;
    }

    /**
     * @param timBroadcastActivated timBroadcastActivated
     * @return this Builder object for method chaining.
     */
    public Builder timBroadcastActivated(Boolean timBroadcastActivated) {
      this.timBroadcastActivated = timBroadcastActivated;
      return this;
    }

    /**
     * @param bssTransitionActivated bssTransitionActivated
     * @return this Builder object for method chaining.
     */
    public Builder bssTransitionActivated(Boolean bssTransitionActivated) {
      this.bssTransitionActivated = bssTransitionActivated;
      return this;
    }

    /**
     * @param qosTrafficCapabilityActivated qosTrafficCapabilityActivated
     * @return this Builder object for method chaining.
     */
    public Builder qosTrafficCapabilityActivated(Boolean qosTrafficCapabilityActivated) {
      this.qosTrafficCapabilityActivated = qosTrafficCapabilityActivated;
      return this;
    }

    /**
     * @param acStationCountActivated acStationCountActivated
     * @return this Builder object for method chaining.
     */
    public Builder acStationCountActivated(Boolean acStationCountActivated) {
      this.acStationCountActivated = acStationCountActivated;
      return this;
    }

    /**
     * @param multiBssIdActivated multiBssIdActivated
     * @return this Builder object for method chaining.
     */
    public Builder multiBssIdActivated(Boolean multiBssIdActivated) {
      this.multiBssIdActivated = multiBssIdActivated;
      return this;
    }

    /**
     * @param timingMeasurementActivated timingMeasurementActivated
     * @return this Builder object for method chaining.
     */
    public Builder timingMeasurementActivated(Boolean timingMeasurementActivated) {
      this.timingMeasurementActivated = timingMeasurementActivated;
      return this;
    }

    /**
     * @param channelUsageActivated channelUsageActivated
     * @return this Builder object for method chaining.
     */
    public Builder channelUsageActivated(Boolean channelUsageActivated) {
      this.channelUsageActivated = channelUsageActivated;
      return this;
    }

    /**
     * @param ssidListActivated ssidListActivated
     * @return this Builder object for method chaining.
     */
    public Builder ssidListActivated(Boolean ssidListActivated) {
      this.ssidListActivated = ssidListActivated;
      return this;
    }

    /**
     * @param dmsActivated dmsActivated
     * @return this Builder object for method chaining.
     */
    public Builder dmsActivated(Boolean dmsActivated) {
      this.dmsActivated = dmsActivated;
      return this;
    }

    /**
     * @param utcTsfOffsetActivated utcTsfOffsetActivated
     * @return this Builder object for method chaining.
     */
    public Builder utcTsfOffsetActivated(Boolean utcTsfOffsetActivated) {
      this.utcTsfOffsetActivated = utcTsfOffsetActivated;
      return this;
    }

    /**
     * @param tdlsPeerUapsdBufferStaSupported tdlsPeerUapsdBufferStaSupported
     * @return this Builder object for method chaining.
     */
    public Builder tdlsPeerUapsdBufferStaSupported(Boolean tdlsPeerUapsdBufferStaSupported) {
      this.tdlsPeerUapsdBufferStaSupported = tdlsPeerUapsdBufferStaSupported;
      return this;
    }

    /**
     * @param tdlsPeerPsmSupported tdlsPeerPsmSupported
     * @return this Builder object for method chaining.
     */
    public Builder tdlsPeerPsmSupported(Boolean tdlsPeerPsmSupported) {
      this.tdlsPeerPsmSupported = tdlsPeerPsmSupported;
      return this;
    }

    /**
     * @param tdlsChannelSwitchingActivated tdlsChannelSwitchingActivated
     * @return this Builder object for method chaining.
     */
    public Builder tdlsChannelSwitchingActivated(Boolean tdlsChannelSwitchingActivated) {
      this.tdlsChannelSwitchingActivated = tdlsChannelSwitchingActivated;
      return this;
    }

    /**
     * @param interworkingServiceActivated interworkingServiceActivated
     * @return this Builder object for method chaining.
     */
    public Builder interworkingServiceActivated(Boolean interworkingServiceActivated) {
      this.interworkingServiceActivated = interworkingServiceActivated;
      return this;
    }

    /**
     * @param qosMapActivated qosMapActivated
     * @return this Builder object for method chaining.
     */
    public Builder qosMapActivated(Boolean qosMapActivated) {
      this.qosMapActivated = qosMapActivated;
      return this;
    }

    /**
     * @param ebrActivated ebrActivated
     * @return this Builder object for method chaining.
     */
    public Builder ebrActivated(Boolean ebrActivated) {
      this.ebrActivated = ebrActivated;
      return this;
    }

    /**
     * @param sspnInterfaceActivated sspnInterfaceActivated
     * @return this Builder object for method chaining.
     */
    public Builder sspnInterfaceActivated(Boolean sspnInterfaceActivated) {
      this.sspnInterfaceActivated = sspnInterfaceActivated;
      return this;
    }

    /**
     * @param bit35 bit35
     * @return this Builder object for method chaining.
     */
    public Builder bit35(Boolean bit35) {
      this.bit35 = bit35;
      return this;
    }

    /**
     * @param msgcfActivated msgcfActivated
     * @return this Builder object for method chaining.
     */
    public Builder msgcfActivated(Boolean msgcfActivated) {
      this.msgcfActivated = msgcfActivated;
      return this;
    }

    /**
     * @param tdlsSupported tdlsSupported
     * @return this Builder object for method chaining.
     */
    public Builder tdlsSupported(Boolean tdlsSupported) {
      this.tdlsSupported = tdlsSupported;
      return this;
    }

    /**
     * @param tdlsProhibited tdlsProhibited
     * @return this Builder object for method chaining.
     */
    public Builder tdlsProhibited(Boolean tdlsProhibited) {
      this.tdlsProhibited = tdlsProhibited;
      return this;
    }

    /**
     * @param tdlsChannelSwitchingProhibited tdlsChannelSwitchingProhibited
     * @return this Builder object for method chaining.
     */
    public Builder tdlsChannelSwitchingProhibited(Boolean tdlsChannelSwitchingProhibited) {
      this.tdlsChannelSwitchingProhibited = tdlsChannelSwitchingProhibited;
      return this;
    }

    /**
     * @param rejectingUnadmittedTraffic rejectingUnadmittedTraffic
     * @return this Builder object for method chaining.
     */
    public Builder rejectingUnadmittedTraffic(Boolean rejectingUnadmittedTraffic) {
      this.rejectingUnadmittedTraffic = rejectingUnadmittedTraffic;
      return this;
    }

    /**
     * @param serviceIntervalGranularity serviceIntervalGranularity
     * @return this Builder object for method chaining.
     */
    public Builder serviceIntervalGranularity(
        Dot11ServiceIntervalGranularity serviceIntervalGranularity) {
      this.serviceIntervalGranularity = serviceIntervalGranularity;
      return this;
    }

    /**
     * @param rmIdentifierMeasurementActivated rmIdentifierMeasurementActivated
     * @return this Builder object for method chaining.
     */
    public Builder rmIdentifierMeasurementActivated(Boolean rmIdentifierMeasurementActivated) {
      this.rmIdentifierMeasurementActivated = rmIdentifierMeasurementActivated;
      return this;
    }

    /**
     * @param uapsdCoexistenceActivated uapsdCoexistenceActivated
     * @return this Builder object for method chaining.
     */
    public Builder uapsdCoexistenceActivated(Boolean uapsdCoexistenceActivated) {
      this.uapsdCoexistenceActivated = uapsdCoexistenceActivated;
      return this;
    }

    /**
     * @param wnmNotificationActivated wnmNotificationActivated
     * @return this Builder object for method chaining.
     */
    public Builder wnmNotificationActivated(Boolean wnmNotificationActivated) {
      this.wnmNotificationActivated = wnmNotificationActivated;
      return this;
    }

    /**
     * @param bit47 bit47
     * @return this Builder object for method chaining.
     */
    public Builder bit47(Boolean bit47) {
      this.bit47 = bit47;
      return this;
    }

    /**
     * @param utf8Ssid utf8Ssid
     * @return this Builder object for method chaining.
     */
    public Builder utf8Ssid(Boolean utf8Ssid) {
      this.utf8Ssid = utf8Ssid;
      return this;
    }

    /**
     * @param bit49 bit49
     * @return this Builder object for method chaining.
     */
    public Builder bit49(Boolean bit49) {
      this.bit49 = bit49;
      return this;
    }

    /**
     * @param bit50 bit50
     * @return this Builder object for method chaining.
     */
    public Builder bit50(Boolean bit50) {
      this.bit50 = bit50;
      return this;
    }

    /**
     * @param bit51 bit51
     * @return this Builder object for method chaining.
     */
    public Builder bit51(Boolean bit51) {
      this.bit51 = bit51;
      return this;
    }

    /**
     * @param bit52 bit52
     * @return this Builder object for method chaining.
     */
    public Builder bit52(Boolean bit52) {
      this.bit52 = bit52;
      return this;
    }

    /**
     * @param bit53 bit53
     * @return this Builder object for method chaining.
     */
    public Builder bit53(Boolean bit53) {
      this.bit53 = bit53;
      return this;
    }

    /**
     * @param bit54 bit54
     * @return this Builder object for method chaining.
     */
    public Builder bit54(Boolean bit54) {
      this.bit54 = bit54;
      return this;
    }

    /**
     * @param bit55 bit55
     * @return this Builder object for method chaining.
     */
    public Builder bit55(Boolean bit55) {
      this.bit55 = bit55;
      return this;
    }

    /**
     * @param trailingData trailingData
     * @return this Builder object for method chaining.
     */
    public Builder trailingData(byte[] trailingData) {
      this.trailingData = trailingData;
      return this;
    }

    @Override
    public Builder length(byte length) {
      super.length(length);
      return this;
    }

    @Override
    public Builder correctLengthAtBuild(boolean correctLengthAtBuild) {
      super.correctLengthAtBuild(correctLengthAtBuild);
      return this;
    }

    @Override
    public Dot11ExtendedCapabilitiesElement build() {
      if (getCorrectLengthAtBuild()) {
        length((byte) calcActualLength(this));
      }
      return new Dot11ExtendedCapabilitiesElement(this);
    }
  }
}
