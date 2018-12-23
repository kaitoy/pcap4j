/*_##########################################################################
  _##
  _##  Copyright (C) 2016  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.namednumber;

import java.util.HashMap;
import java.util.Map;

/**
 * IEEE802.11 Information element ID
 *
 * @see <a href="http://standards.ieee.org/getieee802/download/802.11-2012.pdf">IEEE802.11</a>
 * @author Kaito Yamada
 * @since pcap4j 1.7.0
 */
public final class Dot11InformationElementId extends NamedNumber<Byte, Dot11InformationElementId> {

  /** */
  private static final long serialVersionUID = -7844508106198134349L;

  /** SSID: 0 */
  public static final Dot11InformationElementId SSID =
      new Dot11InformationElementId((byte) 0, "SSID");

  /** Supported rates: 1 */
  public static final Dot11InformationElementId SUPPORTED_RATES =
      new Dot11InformationElementId((byte) 1, "Supported rates");

  /** FH Parameter Set: 2 */
  public static final Dot11InformationElementId FH_PARAMETER_SET =
      new Dot11InformationElementId((byte) 2, "FH Parameter Set");

  /** DSSS Parameter Set: 3 */
  public static final Dot11InformationElementId DSSS_PARAMETER_SET =
      new Dot11InformationElementId((byte) 3, "DSSS Parameter Set");

  /** CF Parameter Set: 4 */
  public static final Dot11InformationElementId CF_PARAMETER_SET =
      new Dot11InformationElementId((byte) 4, "CF Parameter Set");

  /** TIM: 5 */
  public static final Dot11InformationElementId TIM =
      new Dot11InformationElementId((byte) 5, "TIM");

  /** IBSS Parameter Set: 6 */
  public static final Dot11InformationElementId IBSS_PARAMETER_SET =
      new Dot11InformationElementId((byte) 6, "IBSS Parameter Set");

  /** Country: 7 */
  public static final Dot11InformationElementId COUNTRY =
      new Dot11InformationElementId((byte) 7, "Country");

  /** Hopping Pattern Parameters: 8 */
  public static final Dot11InformationElementId HOPPING_PATTERN_PARAMETERS =
      new Dot11InformationElementId((byte) 8, "Hopping Pattern Parameters");

  /** Hopping Pattern Table: 9 */
  public static final Dot11InformationElementId HOPPING_PATTERN_TABLE =
      new Dot11InformationElementId((byte) 9, "Hopping Pattern Table");

  /** Request: 10 */
  public static final Dot11InformationElementId REQUEST =
      new Dot11InformationElementId((byte) 10, "Request");

  /** BSS Load: 11 */
  public static final Dot11InformationElementId BSS_LOAD =
      new Dot11InformationElementId((byte) 11, "BSS Load");

  /** EDCA Parameter Set: 12 */
  public static final Dot11InformationElementId EDCA_PARAMETER_SET =
      new Dot11InformationElementId((byte) 12, "EDCA Parameter Set");

  /** TSPEC: 13 */
  public static final Dot11InformationElementId TSPEC =
      new Dot11InformationElementId((byte) 13, "TSPEC");

  /** TCLAS: 14 */
  public static final Dot11InformationElementId TCLAS =
      new Dot11InformationElementId((byte) 14, "TCLAS");

  /** Schedule: 15 */
  public static final Dot11InformationElementId SCHEDULE =
      new Dot11InformationElementId((byte) 15, "Schedule");

  /** Challenge text: 16 */
  public static final Dot11InformationElementId CHALLENGE_TEXT =
      new Dot11InformationElementId((byte) 16, "Challenge text");

  /** Power Constraint: 32 */
  public static final Dot11InformationElementId POWER_CONSTRAINT =
      new Dot11InformationElementId((byte) 32, "Power Constraint");

  /** Power Capability: 33 */
  public static final Dot11InformationElementId POWER_CAPABILITY =
      new Dot11InformationElementId((byte) 33, "Power Capability");

  /** TPC Request: 34 */
  public static final Dot11InformationElementId TPC_REQUEST =
      new Dot11InformationElementId((byte) 34, "TPC Request");

  /** TPC Report: 35 */
  public static final Dot11InformationElementId TPC_REPORT =
      new Dot11InformationElementId((byte) 35, "TPC Report");

  /** Supported Channels: 36 */
  public static final Dot11InformationElementId SUPPORTED_CHANNELS =
      new Dot11InformationElementId((byte) 36, "Supported Channels");

  /** Channel Switch Announcement: 37 */
  public static final Dot11InformationElementId CHANNEL_SWITCH_ANNOUNCEMENT =
      new Dot11InformationElementId((byte) 37, "Channel Switch Announcement");

  /** Measurement Request: 38 */
  public static final Dot11InformationElementId MEASUREMENT_REQUEST =
      new Dot11InformationElementId((byte) 38, "Measurement Request");

  /** Measurement Report: 39 */
  public static final Dot11InformationElementId MEASUREMENT_REPORT =
      new Dot11InformationElementId((byte) 39, "Measurement Report");

  /** Quiet: 40 */
  public static final Dot11InformationElementId QUIET =
      new Dot11InformationElementId((byte) 40, "Quiet");

  /** IBSS DFS: 41 */
  public static final Dot11InformationElementId IBSS_DFS =
      new Dot11InformationElementId((byte) 41, "IBSS DFS");

  /** ERP: 42 */
  public static final Dot11InformationElementId ERP =
      new Dot11InformationElementId((byte) 42, "ERP");

  /** TS Delay: 43 */
  public static final Dot11InformationElementId TS_DELAY =
      new Dot11InformationElementId((byte) 43, "TS Delay");

  /** TCLAS Processing: 44 */
  public static final Dot11InformationElementId TCLAS_PROCESSING =
      new Dot11InformationElementId((byte) 44, "TCLAS Processing");

  /** HT Capabilities: 45 */
  public static final Dot11InformationElementId HT_CAPABILITIES =
      new Dot11InformationElementId((byte) 45, "HT Capabilities");

  /** QoS Capability: 46 */
  public static final Dot11InformationElementId QOS_CAPABILITY =
      new Dot11InformationElementId((byte) 46, "QoS Capability");

  /** RSN: 48 */
  public static final Dot11InformationElementId RSN =
      new Dot11InformationElementId((byte) 48, "RSN");

  /** Extended Supported Rates: 50 */
  public static final Dot11InformationElementId EXTENDED_SUPPORTED_RATES =
      new Dot11InformationElementId((byte) 50, "Extended Supported Rates");

  /** AP Channel Report: 51 */
  public static final Dot11InformationElementId AP_CHANNEL_REPORT =
      new Dot11InformationElementId((byte) 51, "AP Channel Report");

  /** Neighbor Report: 52 */
  public static final Dot11InformationElementId NEIGHBOR_REPORT =
      new Dot11InformationElementId((byte) 52, "Neighbor Report");

  /** RCPI: 53 */
  public static final Dot11InformationElementId RCPI =
      new Dot11InformationElementId((byte) 53, "RCPI");

  /** Mobility Domain (MDE): 54 */
  public static final Dot11InformationElementId MOBILITY_DOMAIN =
      new Dot11InformationElementId((byte) 54, "Mobility Domain (MDE)");

  /** Fast BSS Transition (FTE): 55 */
  public static final Dot11InformationElementId FAST_BSS_TRANSITION =
      new Dot11InformationElementId((byte) 55, "Fast BSS Transition (FTE)");

  /** Timeout Interval: 56 */
  public static final Dot11InformationElementId TIMEOUT_INTERVAL =
      new Dot11InformationElementId((byte) 56, "Timeout Interval");

  /** RIC Data (RDE): 57 */
  public static final Dot11InformationElementId RIC_DATA =
      new Dot11InformationElementId((byte) 57, "RIC Data (RDE)");

  /** DSE Registered Location: 58 */
  public static final Dot11InformationElementId DSE_REGISTERED_LOCATION =
      new Dot11InformationElementId((byte) 58, "DSE Registered Location");

  /** Supported Operating Classes: 59 */
  public static final Dot11InformationElementId SUPPORTED_OPERATING_CLASSES =
      new Dot11InformationElementId((byte) 59, "Supported Operating Classes");

  /** Extended Channel Switch Announcement: 60 */
  public static final Dot11InformationElementId EXTENDED_CHANNEL_SWITCH_ANNOUNCEMENT =
      new Dot11InformationElementId((byte) 60, "Extended Channel Switch Announcement");

  /** HT Operation: 61 */
  public static final Dot11InformationElementId HT_OPERATION =
      new Dot11InformationElementId((byte) 61, "HT Operation");

  /** Secondary Channel Offset: 62 */
  public static final Dot11InformationElementId SECONDARY_CHANNEL_OFFSET =
      new Dot11InformationElementId((byte) 62, "Secondary Channel Offset");

  /** BSS Average Access Delay: 63 */
  public static final Dot11InformationElementId BSS_AVERAGE_ACCESS_DELAY =
      new Dot11InformationElementId((byte) 63, "BSS Average Access Delay");

  /** Antenna: 64 */
  public static final Dot11InformationElementId ANTENNA =
      new Dot11InformationElementId((byte) 64, "Antenna");

  /** RSNI: 65 */
  public static final Dot11InformationElementId RSNI =
      new Dot11InformationElementId((byte) 65, "RSNI");

  /** Measurement Pilot Transmission: 66 */
  public static final Dot11InformationElementId MEASUREMENT_PILOT_TRANSMISSION =
      new Dot11InformationElementId((byte) 66, "Measurement Pilot Transmission");

  /** BSS Available Admission Capacity: 67 */
  public static final Dot11InformationElementId BSS_AVAILABLE_ADMISSION_CAPACITY =
      new Dot11InformationElementId((byte) 67, "BSS Available Admission Capacity");

  /** BSS AC Access Delay: 68 */
  public static final Dot11InformationElementId BSS_AC_ACCESS_DELAY =
      new Dot11InformationElementId((byte) 68, "BSS AC Access Delay");

  /** Time Advertisement: 69 */
  public static final Dot11InformationElementId TIME_ADVERTISEMENT =
      new Dot11InformationElementId((byte) 69, "Time Advertisement");

  /** RM Enabled Capabilities: 70 */
  public static final Dot11InformationElementId RM_ENABLED_CAPABILITIES =
      new Dot11InformationElementId((byte) 70, "RM Enabled Capabilities");

  /** Multiple BSSID: 71 */
  public static final Dot11InformationElementId MULTIPLE_BSSID =
      new Dot11InformationElementId((byte) 71, "Multiple BSSID");

  /** 20/40 BSS Coexistence: 72 */
  public static final Dot11InformationElementId IE_20_40_BSS_COEXISTENCE =
      new Dot11InformationElementId((byte) 72, "20/40 BSS Coexistence");

  /** 20/40 BSS Intolerant Channel Report: 73 */
  public static final Dot11InformationElementId IE_20_40_BSS_INTOLERANT_CHANNEL_REPORT =
      new Dot11InformationElementId((byte) 73, "20/40 BSS Intolerant Channel Report");

  /** Overlapping BSS Scan Parameters: 74 */
  public static final Dot11InformationElementId OVERLAPPING_BSS_SCAN_PARAMETERS =
      new Dot11InformationElementId((byte) 74, "Overlapping BSS Scan Parameters");

  /** RIC Descriptor: 75 */
  public static final Dot11InformationElementId RIC_DESCRIPTOR =
      new Dot11InformationElementId((byte) 75, "RIC Descriptor");

  /** Management MIC: 76 */
  public static final Dot11InformationElementId MANAGEMENT_MIC =
      new Dot11InformationElementId((byte) 76, "Management MIC");

  /** Event Request: 78 */
  public static final Dot11InformationElementId EVENT_REQUEST =
      new Dot11InformationElementId((byte) 78, "Event Request");

  /** Event Report: 79 */
  public static final Dot11InformationElementId EVENT_REPORT =
      new Dot11InformationElementId((byte) 79, "Event Report");

  /** Diagnostic Request: 80 */
  public static final Dot11InformationElementId DIAGNOSTIC_REQUEST =
      new Dot11InformationElementId((byte) 80, "Diagnostic Request");

  /** Diagnostic Report: 81 */
  public static final Dot11InformationElementId DIAGNOSTIC_REPORT =
      new Dot11InformationElementId((byte) 81, "Diagnostic Report");

  /** Location Parameters: 82 */
  public static final Dot11InformationElementId LOCATION_PARAMETERS =
      new Dot11InformationElementId((byte) 82, "Location Parameters");

  /** Nontransmitted BSSID Capability: 83 */
  public static final Dot11InformationElementId NONTRANSMITTED_BSSID_CAPABILITY =
      new Dot11InformationElementId((byte) 83, "Nontransmitted BSSID Capability");

  /** SSID List: 84 */
  public static final Dot11InformationElementId SSID_LIST =
      new Dot11InformationElementId((byte) 84, "SSID List");

  /** Multiple BSSID-Index: 85 */
  public static final Dot11InformationElementId MULTIPLE_BSSID_INDEX =
      new Dot11InformationElementId((byte) 85, "Multiple BSSID-Index");

  /** FMS Descriptor: 86 */
  public static final Dot11InformationElementId FMS_DESCRIPTOR =
      new Dot11InformationElementId((byte) 86, "FMS Descriptor");

  /** FMS Request: 87 */
  public static final Dot11InformationElementId FMS_REQUEST =
      new Dot11InformationElementId((byte) 87, "FMS Request");

  /** FMS Response: 88 */
  public static final Dot11InformationElementId FMS_RESPONSE =
      new Dot11InformationElementId((byte) 88, "FMS Response");

  /** QoS Traffic Capability: 89 */
  public static final Dot11InformationElementId QOS_TRAFFIC_CAPABILITY =
      new Dot11InformationElementId((byte) 89, "QoS Traffic Capability");

  /** BSS Max Idle Period: 90 */
  public static final Dot11InformationElementId BSS_MAX_IDLE_PERIOD =
      new Dot11InformationElementId((byte) 90, "BSS Max Idle Period");

  /** TFS Request: 91 */
  public static final Dot11InformationElementId TFS_REQUEST =
      new Dot11InformationElementId((byte) 91, "TFS Request");

  /** TFS Response: 92 */
  public static final Dot11InformationElementId TFS_RESPONSE =
      new Dot11InformationElementId((byte) 92, "TFS Response");

  /** WNM-Sleep Mode: 93 */
  public static final Dot11InformationElementId WNM_SLEEP_MODE =
      new Dot11InformationElementId((byte) 93, "WNM-Sleep Mode");

  /** TIM Broadcast Request: 94 */
  public static final Dot11InformationElementId TIM_BROADCAST_REQUEST =
      new Dot11InformationElementId((byte) 94, "TIM Broadcast Request");

  /** TIM Broadcast Response: 95 */
  public static final Dot11InformationElementId TIM_BROADCAST_RESPONSE =
      new Dot11InformationElementId((byte) 95, "TIM Broadcast Response");

  /** Collocated Interference Report: 96 */
  public static final Dot11InformationElementId COLLOCATED_INTERFERENCE_REPORT =
      new Dot11InformationElementId((byte) 96, "Collocated Interference Report");

  /** Channel Usage: 97 */
  public static final Dot11InformationElementId CHANNEL_USAGE =
      new Dot11InformationElementId((byte) 97, "Channel Usage");

  /** Time Zone: 98 */
  public static final Dot11InformationElementId TIME_ZONE =
      new Dot11InformationElementId((byte) 98, "Time Zone");

  /** DMS Request: 99 */
  public static final Dot11InformationElementId DMS_REQUEST =
      new Dot11InformationElementId((byte) 99, "DMS Request");

  /** DMS Response: 100 */
  public static final Dot11InformationElementId DMS_RESPONSE =
      new Dot11InformationElementId((byte) 100, "DMS Response");

  /** Link Identifier: 101 */
  public static final Dot11InformationElementId LINK_IDENTIFIER =
      new Dot11InformationElementId((byte) 101, "Link Identifier");

  /** Wakeup Schedule: 102 */
  public static final Dot11InformationElementId WAKEUP_SCHEDULE =
      new Dot11InformationElementId((byte) 102, "Wakeup Schedule");

  /** Channel Switch Timing: 104 */
  public static final Dot11InformationElementId CHANNEL_SWITCH_TIMING =
      new Dot11InformationElementId((byte) 104, "Channel Switch Timing");

  /** PTI Control: 105 */
  public static final Dot11InformationElementId PTI_CONTROL =
      new Dot11InformationElementId((byte) 105, "PTI Control");

  /** TPU Buffer Status: 106 */
  public static final Dot11InformationElementId TPU_BUFFER_STATUS =
      new Dot11InformationElementId((byte) 106, "TPU Buffer Status");

  /** Interworking: 107 */
  public static final Dot11InformationElementId INTERWORKING =
      new Dot11InformationElementId((byte) 107, "Interworking");

  /** Advertisement Protocol: 108 */
  public static final Dot11InformationElementId ADVERTISEMENT_PROTOCOL =
      new Dot11InformationElementId((byte) 108, "Advertisement Protocol");

  /** Expedited Bandwidth Request: 109 */
  public static final Dot11InformationElementId EXPEDITED_BANDWIDTH_REQUEST =
      new Dot11InformationElementId((byte) 109, "Expedited Bandwidth Request");

  /** QoS Map Set: 110 */
  public static final Dot11InformationElementId QOS_MAP_SET =
      new Dot11InformationElementId((byte) 110, "QoS Map Set");

  /** Roaming Consortium: 111 */
  public static final Dot11InformationElementId ROAMING_CONSORTIUM =
      new Dot11InformationElementId((byte) 111, "Roaming Consortium");

  /** Emergency Alert Identifier: 112 */
  public static final Dot11InformationElementId EMERGENCY_ALERT_IDENTIFIER =
      new Dot11InformationElementId((byte) 112, "Emergency Alert Identifier");

  /** Mesh Configuration: 113 */
  public static final Dot11InformationElementId MESH_CONFIGURATION =
      new Dot11InformationElementId((byte) 113, "Mesh Configuration");

  /** Mesh ID: 114 */
  public static final Dot11InformationElementId MESH_ID =
      new Dot11InformationElementId((byte) 114, "Mesh ID");

  /** Mesh Link Metric Report: 115 */
  public static final Dot11InformationElementId MESH_LINK_METRIC_REPORT =
      new Dot11InformationElementId((byte) 115, "Mesh Link Metric Report");

  /** Congestion Notification: 116 */
  public static final Dot11InformationElementId CONGESTION_NOTIFICATION =
      new Dot11InformationElementId((byte) 116, "Congestion Notification");

  /** Mesh Peering Management: 117 */
  public static final Dot11InformationElementId MESH_PEERING_MANAGEMENT =
      new Dot11InformationElementId((byte) 117, "Mesh Peering Management");

  /** Mesh Channel Switch Parameters: 118 */
  public static final Dot11InformationElementId MESH_CHANNEL_SWITCH_PARAMETERS =
      new Dot11InformationElementId((byte) 118, "Mesh Channel Switch Parameters");

  /** Mesh Awake Window: 119 */
  public static final Dot11InformationElementId MESH_AWAKE_WINDOW =
      new Dot11InformationElementId((byte) 119, "Mesh Awake Window");

  /** Beacon Timing: 120 */
  public static final Dot11InformationElementId BEACON_TIMING =
      new Dot11InformationElementId((byte) 120, "Beacon Timing");

  /** MCCAOP Setup Request: 121 */
  public static final Dot11InformationElementId MCCAOP_SETUP_REQUEST =
      new Dot11InformationElementId((byte) 121, "MCCAOP Setup Request");

  /** MCCAOP Setup Reply: 122 */
  public static final Dot11InformationElementId MCCAOP_SETUP_REPLY =
      new Dot11InformationElementId((byte) 122, "MCCAOP Setup Reply");

  /** MCCAOP Advertisement: 123 */
  public static final Dot11InformationElementId MCCAOP_ADVERTISEMENT =
      new Dot11InformationElementId((byte) 123, "MCCAOP Advertisement");

  /** MCCAOP Teardown: 124 */
  public static final Dot11InformationElementId MCCAOP_TEARDOWN =
      new Dot11InformationElementId((byte) 124, "MCCAOP Teardown");

  /** GANN: 125 */
  public static final Dot11InformationElementId GANN =
      new Dot11InformationElementId((byte) 125, "GANN");

  /** RANN: 126 */
  public static final Dot11InformationElementId RANN =
      new Dot11InformationElementId((byte) 126, "RANN");

  /** Extended Capabilities: 127 */
  public static final Dot11InformationElementId EXTENDED_CAPABILITIES =
      new Dot11InformationElementId((byte) 127, "Extended Capabilities");

  /** PREQ: 130 */
  public static final Dot11InformationElementId PREQ =
      new Dot11InformationElementId((byte) 130, "PREQ");

  /** PREP: 131 */
  public static final Dot11InformationElementId PREP =
      new Dot11InformationElementId((byte) 131, "PREP");

  /** PERR: 132 */
  public static final Dot11InformationElementId PERR =
      new Dot11InformationElementId((byte) 132, "PERR");

  /** PXU: 137 */
  public static final Dot11InformationElementId PXU =
      new Dot11InformationElementId((byte) 137, "PXU");

  /** PXUC: 138 */
  public static final Dot11InformationElementId PXUC =
      new Dot11InformationElementId((byte) 138, "PXUC");

  /** Authenticated Mesh Peering Exchange: 139 */
  public static final Dot11InformationElementId AUTHENTICATED_MESH_PEERING_EXCHANGE =
      new Dot11InformationElementId((byte) 139, "Authenticated Mesh Peering Exchange");

  /** MIC: 140 */
  public static final Dot11InformationElementId MIC =
      new Dot11InformationElementId((byte) 140, "MIC");

  /** Destination URI: 141 */
  public static final Dot11InformationElementId DESTINATION_URI =
      new Dot11InformationElementId((byte) 141, "Destination URI");

  /** U-APSD Coexistence: 142 */
  public static final Dot11InformationElementId U_APSD_COEXISTENCE =
      new Dot11InformationElementId((byte) 142, "U-APSD Coexistence");

  /** MCCAOP Advertisement Overview: 174 */
  public static final Dot11InformationElementId MCCAOP_ADVERTISEMENT_OVERVIEW =
      new Dot11InformationElementId((byte) 174, "MCCAOP Advertisement Overview");

  /** Vendor Specific: 221 */
  public static final Dot11InformationElementId VENDOR_SPECIFIC =
      new Dot11InformationElementId((byte) 221, "Vendor Specific");

  private static final Map<Byte, Dot11InformationElementId> registry =
      new HashMap<Byte, Dot11InformationElementId>();

  static {
    registry.put(SSID.value(), SSID);
    registry.put(SUPPORTED_RATES.value(), SUPPORTED_RATES);
    registry.put(FH_PARAMETER_SET.value(), FH_PARAMETER_SET);
    registry.put(DSSS_PARAMETER_SET.value(), DSSS_PARAMETER_SET);
    registry.put(CF_PARAMETER_SET.value(), CF_PARAMETER_SET);
    registry.put(TIM.value(), TIM);
    registry.put(IBSS_PARAMETER_SET.value(), IBSS_PARAMETER_SET);
    registry.put(COUNTRY.value(), COUNTRY);
    registry.put(HOPPING_PATTERN_PARAMETERS.value(), HOPPING_PATTERN_PARAMETERS);
    registry.put(HOPPING_PATTERN_TABLE.value(), HOPPING_PATTERN_TABLE);
    registry.put(REQUEST.value(), REQUEST);
    registry.put(BSS_LOAD.value(), BSS_LOAD);
    registry.put(EDCA_PARAMETER_SET.value(), EDCA_PARAMETER_SET);
    registry.put(TSPEC.value(), TSPEC);
    registry.put(TCLAS.value(), TCLAS);
    registry.put(SCHEDULE.value(), SCHEDULE);
    registry.put(CHALLENGE_TEXT.value(), CHALLENGE_TEXT);
    registry.put(POWER_CONSTRAINT.value(), POWER_CONSTRAINT);
    registry.put(POWER_CAPABILITY.value(), POWER_CAPABILITY);
    registry.put(TPC_REQUEST.value(), TPC_REQUEST);
    registry.put(TPC_REPORT.value(), TPC_REPORT);
    registry.put(SUPPORTED_CHANNELS.value(), SUPPORTED_CHANNELS);
    registry.put(CHANNEL_SWITCH_ANNOUNCEMENT.value(), CHANNEL_SWITCH_ANNOUNCEMENT);
    registry.put(MEASUREMENT_REQUEST.value(), MEASUREMENT_REQUEST);
    registry.put(MEASUREMENT_REPORT.value(), MEASUREMENT_REPORT);
    registry.put(QUIET.value(), QUIET);
    registry.put(IBSS_DFS.value(), IBSS_DFS);
    registry.put(ERP.value(), ERP);
    registry.put(TS_DELAY.value(), TS_DELAY);
    registry.put(TCLAS_PROCESSING.value(), TCLAS_PROCESSING);
    registry.put(HT_CAPABILITIES.value(), HT_CAPABILITIES);
    registry.put(QOS_CAPABILITY.value(), QOS_CAPABILITY);
    registry.put(RSN.value(), RSN);
    registry.put(EXTENDED_SUPPORTED_RATES.value(), EXTENDED_SUPPORTED_RATES);
    registry.put(AP_CHANNEL_REPORT.value(), AP_CHANNEL_REPORT);
    registry.put(NEIGHBOR_REPORT.value(), NEIGHBOR_REPORT);
    registry.put(RCPI.value(), RCPI);
    registry.put(MOBILITY_DOMAIN.value(), MOBILITY_DOMAIN);
    registry.put(FAST_BSS_TRANSITION.value(), FAST_BSS_TRANSITION);
    registry.put(TIMEOUT_INTERVAL.value(), TIMEOUT_INTERVAL);
    registry.put(RIC_DATA.value(), RIC_DATA);
    registry.put(DSE_REGISTERED_LOCATION.value(), DSE_REGISTERED_LOCATION);
    registry.put(SUPPORTED_OPERATING_CLASSES.value(), SUPPORTED_OPERATING_CLASSES);
    registry.put(
        EXTENDED_CHANNEL_SWITCH_ANNOUNCEMENT.value(), EXTENDED_CHANNEL_SWITCH_ANNOUNCEMENT);
    registry.put(HT_OPERATION.value(), HT_OPERATION);
    registry.put(SECONDARY_CHANNEL_OFFSET.value(), SECONDARY_CHANNEL_OFFSET);
    registry.put(BSS_AVERAGE_ACCESS_DELAY.value(), BSS_AVERAGE_ACCESS_DELAY);
    registry.put(ANTENNA.value(), ANTENNA);
    registry.put(RSNI.value(), RSNI);
    registry.put(MEASUREMENT_PILOT_TRANSMISSION.value(), MEASUREMENT_PILOT_TRANSMISSION);
    registry.put(BSS_AVAILABLE_ADMISSION_CAPACITY.value(), BSS_AVAILABLE_ADMISSION_CAPACITY);
    registry.put(BSS_AC_ACCESS_DELAY.value(), BSS_AC_ACCESS_DELAY);
    registry.put(TIME_ADVERTISEMENT.value(), TIME_ADVERTISEMENT);
    registry.put(RM_ENABLED_CAPABILITIES.value(), RM_ENABLED_CAPABILITIES);
    registry.put(MULTIPLE_BSSID.value(), MULTIPLE_BSSID);
    registry.put(IE_20_40_BSS_COEXISTENCE.value(), IE_20_40_BSS_COEXISTENCE);
    registry.put(
        IE_20_40_BSS_INTOLERANT_CHANNEL_REPORT.value(), IE_20_40_BSS_INTOLERANT_CHANNEL_REPORT);
    registry.put(OVERLAPPING_BSS_SCAN_PARAMETERS.value(), OVERLAPPING_BSS_SCAN_PARAMETERS);
    registry.put(RIC_DESCRIPTOR.value(), RIC_DESCRIPTOR);
    registry.put(MANAGEMENT_MIC.value(), MANAGEMENT_MIC);
    registry.put(EVENT_REQUEST.value(), EVENT_REQUEST);
    registry.put(EVENT_REPORT.value(), EVENT_REPORT);
    registry.put(DIAGNOSTIC_REQUEST.value(), DIAGNOSTIC_REQUEST);
    registry.put(DIAGNOSTIC_REPORT.value(), DIAGNOSTIC_REPORT);
    registry.put(LOCATION_PARAMETERS.value(), LOCATION_PARAMETERS);
    registry.put(NONTRANSMITTED_BSSID_CAPABILITY.value(), NONTRANSMITTED_BSSID_CAPABILITY);
    registry.put(SSID_LIST.value(), SSID_LIST);
    registry.put(MULTIPLE_BSSID_INDEX.value(), MULTIPLE_BSSID_INDEX);
    registry.put(FMS_DESCRIPTOR.value(), FMS_DESCRIPTOR);
    registry.put(FMS_REQUEST.value(), FMS_REQUEST);
    registry.put(FMS_RESPONSE.value(), FMS_RESPONSE);
    registry.put(QOS_TRAFFIC_CAPABILITY.value(), QOS_TRAFFIC_CAPABILITY);
    registry.put(BSS_MAX_IDLE_PERIOD.value(), BSS_MAX_IDLE_PERIOD);
    registry.put(TFS_REQUEST.value(), TFS_REQUEST);
    registry.put(TFS_RESPONSE.value(), TFS_RESPONSE);
    registry.put(WNM_SLEEP_MODE.value(), WNM_SLEEP_MODE);
    registry.put(TIM_BROADCAST_REQUEST.value(), TIM_BROADCAST_REQUEST);
    registry.put(TIM_BROADCAST_RESPONSE.value(), TIM_BROADCAST_RESPONSE);
    registry.put(COLLOCATED_INTERFERENCE_REPORT.value(), COLLOCATED_INTERFERENCE_REPORT);
    registry.put(CHANNEL_USAGE.value(), CHANNEL_USAGE);
    registry.put(TIME_ZONE.value(), TIME_ZONE);
    registry.put(DMS_REQUEST.value(), DMS_REQUEST);
    registry.put(DMS_RESPONSE.value(), DMS_RESPONSE);
    registry.put(LINK_IDENTIFIER.value(), LINK_IDENTIFIER);
    registry.put(WAKEUP_SCHEDULE.value(), WAKEUP_SCHEDULE);
    registry.put(CHANNEL_SWITCH_TIMING.value(), CHANNEL_SWITCH_TIMING);
    registry.put(PTI_CONTROL.value(), PTI_CONTROL);
    registry.put(TPU_BUFFER_STATUS.value(), TPU_BUFFER_STATUS);
    registry.put(INTERWORKING.value(), INTERWORKING);
    registry.put(ADVERTISEMENT_PROTOCOL.value(), ADVERTISEMENT_PROTOCOL);
    registry.put(EXPEDITED_BANDWIDTH_REQUEST.value(), EXPEDITED_BANDWIDTH_REQUEST);
    registry.put(QOS_MAP_SET.value(), QOS_MAP_SET);
    registry.put(ROAMING_CONSORTIUM.value(), ROAMING_CONSORTIUM);
    registry.put(EMERGENCY_ALERT_IDENTIFIER.value(), EMERGENCY_ALERT_IDENTIFIER);
    registry.put(MESH_CONFIGURATION.value(), MESH_CONFIGURATION);
    registry.put(MESH_ID.value(), MESH_ID);
    registry.put(MESH_LINK_METRIC_REPORT.value(), MESH_LINK_METRIC_REPORT);
    registry.put(CONGESTION_NOTIFICATION.value(), CONGESTION_NOTIFICATION);
    registry.put(MESH_PEERING_MANAGEMENT.value(), MESH_PEERING_MANAGEMENT);
    registry.put(MESH_CHANNEL_SWITCH_PARAMETERS.value(), MESH_CHANNEL_SWITCH_PARAMETERS);
    registry.put(MESH_AWAKE_WINDOW.value(), MESH_AWAKE_WINDOW);
    registry.put(BEACON_TIMING.value(), BEACON_TIMING);
    registry.put(MCCAOP_SETUP_REQUEST.value(), MCCAOP_SETUP_REQUEST);
    registry.put(MCCAOP_SETUP_REPLY.value(), MCCAOP_SETUP_REPLY);
    registry.put(MCCAOP_ADVERTISEMENT.value(), MCCAOP_ADVERTISEMENT);
    registry.put(MCCAOP_TEARDOWN.value(), MCCAOP_TEARDOWN);
    registry.put(GANN.value(), GANN);
    registry.put(RANN.value(), RANN);
    registry.put(EXTENDED_CAPABILITIES.value(), EXTENDED_CAPABILITIES);
    registry.put(PREQ.value(), PREQ);
    registry.put(PREP.value(), PREP);
    registry.put(PERR.value(), PERR);
    registry.put(PXU.value(), PXU);
    registry.put(PXUC.value(), PXUC);
    registry.put(AUTHENTICATED_MESH_PEERING_EXCHANGE.value(), AUTHENTICATED_MESH_PEERING_EXCHANGE);
    registry.put(MIC.value(), MIC);
    registry.put(DESTINATION_URI.value(), DESTINATION_URI);
    registry.put(U_APSD_COEXISTENCE.value(), U_APSD_COEXISTENCE);
    registry.put(MCCAOP_ADVERTISEMENT_OVERVIEW.value(), MCCAOP_ADVERTISEMENT_OVERVIEW);
    registry.put(VENDOR_SPECIFIC.value(), VENDOR_SPECIFIC);
  }

  /**
   * @param value value
   * @param name name
   */
  public Dot11InformationElementId(Byte value, String name) {
    super(value, name);
  }

  /**
   * @param value value
   * @return a Dot11InformationElementId object.
   */
  public static Dot11InformationElementId getInstance(Byte value) {
    if (registry.containsKey(value)) {
      return registry.get(value);
    } else {
      return new Dot11InformationElementId(value, "unknown");
    }
  }

  /**
   * @param number number
   * @return a Dot11InformationElementId object.
   */
  public static Dot11InformationElementId register(Dot11InformationElementId number) {
    return registry.put(number.value(), number);
  }

  @Override
  public int compareTo(Dot11InformationElementId o) {
    return value().compareTo(o.value());
  }

  /** */
  @Override
  public String valueAsString() {
    return String.valueOf(value() & 0xFF);
  }
}
