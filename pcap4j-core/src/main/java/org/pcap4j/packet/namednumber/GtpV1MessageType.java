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
 * GTPv1 Message Type
 *
 * @see <a
 *     href="http://www.etsi.org/deliver/etsi_ts/129000_129099/129060/12.06.00_60/ts_129060v120600p.pdf">ETSI
 *     TS 129 060 V12.6.0</a>
 * @author Waveform
 * @since pcap4j 1.6.6
 */
public final class GtpV1MessageType extends NamedNumber<Byte, GtpV1MessageType> {

  /** */
  private static final long serialVersionUID = 7592798859079852877L;

  /** Message type 1 (Echo Request) */
  public static final GtpV1MessageType ECHO_REQUEST =
      new GtpV1MessageType((byte) 1, "Echo Request");

  /** Message type 2 (Echo Response) */
  public static final GtpV1MessageType ECHO_RESPONSE =
      new GtpV1MessageType((byte) 2, "Echo Response");

  /** Message type 3 (Version not Supported) */
  public static final GtpV1MessageType VERSION_NOT_SUPPORTED =
      new GtpV1MessageType((byte) 3, "Version Not Supported");

  /** Message type 4 (Node Alive Request) */
  public static final GtpV1MessageType NODE_ALIVE_REQUEST =
      new GtpV1MessageType((byte) 4, "Node Alive Request");

  /** Message type 5 (Node Alive Response) */
  public static final GtpV1MessageType NODE_ALIVE_RESPONSE =
      new GtpV1MessageType((byte) 5, "Node Alive Response");

  /** Message type 6 (Redirection Request) */
  public static final GtpV1MessageType REDIRECTION_REQUEST =
      new GtpV1MessageType((byte) 6, "Redirection Request");

  /** Message type 7 (Redirection Response) */
  public static final GtpV1MessageType REDIRECTION_RESPONSE =
      new GtpV1MessageType((byte) 7, "Redirection Response");

  /** Message type 16 (Create PDP Context Request) */
  public static final GtpV1MessageType CREATE_PDP_CONTEXT_REQUEST =
      new GtpV1MessageType((byte) 16, "Create PDP Context Request");

  /** Message type 17 (Create PDP Context Response) */
  public static final GtpV1MessageType CREATE_PDP_CONTEXT_RESPONSE =
      new GtpV1MessageType((byte) 17, "Create PDP Context Response");

  /** Message type 18 (Update PDP Context Request) */
  public static final GtpV1MessageType UPDATE_PDP_CONTEXT_REQUEST =
      new GtpV1MessageType((byte) 18, "Update PDP Context Request");

  /** Message type 19 (Update PDP Context Response) */
  public static final GtpV1MessageType UPDATE_PDP_CONTEXT_RESPONSE =
      new GtpV1MessageType((byte) 19, "Update PDP Context Response");

  /** Message type 20 (Delete PDP Context Request) */
  public static final GtpV1MessageType DELETE_PDP_CONTEXT_REQUEST =
      new GtpV1MessageType((byte) 20, "Delete PDP Context Request");

  /** Message type 21 (Delete PDP Context Response) */
  public static final GtpV1MessageType DELETE_PDP_CONTEXT_RESPONSE =
      new GtpV1MessageType((byte) 21, "Delete PDP Context Response");

  /** Message type 22 (Initiate PDP Context Activation Request) */
  public static final GtpV1MessageType INITIATE_PDP_CONTEXT_ACTIVATION_REQUEST =
      new GtpV1MessageType((byte) 22, "Initiate PDP Context Activation Request");

  /** Message type 23 (Initiate PDP Context Activation Response) */
  public static final GtpV1MessageType INITIATE_PDP_CONTEXT_ACTIVATION_RESPONSE =
      new GtpV1MessageType((byte) 22, "Initiate PDP Context Activation Response");

  /** Message type 26 (Error Indication) */
  public static final GtpV1MessageType ERROR_INDICATION =
      new GtpV1MessageType((byte) 26, "Error Indication");

  /** Message type 27 (PDU Notification Request) */
  public static final GtpV1MessageType PDU_NOTIFICATION_REQUEST =
      new GtpV1MessageType((byte) 27, "PDU Notification Request");

  /** Message type 28 (PDU Notification Response) */
  public static final GtpV1MessageType PDU_NOTIFICATION_RESPONSE =
      new GtpV1MessageType((byte) 28, "PDU Notification Response");

  /** Message type 29 (PDU Notification Reject Request) */
  public static final GtpV1MessageType PDU_NOTIFICATION_REJECT_REQUEST =
      new GtpV1MessageType((byte) 29, "PDU Notification Reject Request");

  /** Message type 30 (PDU Notification Reject Response) */
  public static final GtpV1MessageType PDU_NOTIFICATION_REJECT_RESPONSE =
      new GtpV1MessageType((byte) 30, "PDU Notification Reject Response");

  /** Message type 31 (Supported Extension Headers Notification) */
  public static final GtpV1MessageType SUPPORTED_EXTENSION_HEADERS_NOTIFICATION =
      new GtpV1MessageType((byte) 31, "Supported Extension Headers Notification");

  /** Message type 32 (Send Routing Information for GPRS Request) */
  public static final GtpV1MessageType SEND_ROUTING_INFORMATION_FOR_GPRS_REQUEST =
      new GtpV1MessageType((byte) 32, "Send Routing Information for GPRS Request");

  /** Message type 33 (Send Routing Information for GPRS Response) */
  public static final GtpV1MessageType SEND_ROUTING_INFORMATION_FOR_GPRS_RESPONSE =
      new GtpV1MessageType((byte) 33, "Send Routing Information for GPRS Response");

  /** Message type 34 (Failure Report Request) */
  public static final GtpV1MessageType FAILURE_REPORT_REQUEST =
      new GtpV1MessageType((byte) 34, "Failure Report Request");

  /** Message type 35 (Failure Report Response) */
  public static final GtpV1MessageType FAILURE_REPORT_RESPONSE =
      new GtpV1MessageType((byte) 35, "Failure Report Response");

  /** Message type 36 (Note MS GPRS Present Request ) */
  public static final GtpV1MessageType NOTE_MS_GPRS_PRESENT_REQUEST =
      new GtpV1MessageType((byte) 36, "Note MS GPRS Present Request");

  /** Message type 37 (Note MS GPRS Present Response) */
  public static final GtpV1MessageType NOTE_MS_GPRS_PRESENT_RESPONSE =
      new GtpV1MessageType((byte) 37, "Note MS GPRS Present Response");

  /** Message type 48 (Identification Request) */
  public static final GtpV1MessageType IDENTIFICATION_REQUEST =
      new GtpV1MessageType((byte) 48, "Identification Request");

  /** Message type 49 (Identification Response) */
  public static final GtpV1MessageType IDENTIFICATION_RESPONSE =
      new GtpV1MessageType((byte) 49, "Identification Response");

  /** Message type 50 (SGSN Context Request) */
  public static final GtpV1MessageType SGSN_CONTEXT_REQUEST =
      new GtpV1MessageType((byte) 50, "SGSN Context Request");

  /** Message type 51 (SGSN Context Response) */
  public static final GtpV1MessageType SGSN_CONTEXT_RESPONSE =
      new GtpV1MessageType((byte) 51, "SGSN Context Response");

  /** Message type 52 (SGSN Context Acknowledge) */
  public static final GtpV1MessageType SGSN_CONTEXT_ACKNOWLEDGE =
      new GtpV1MessageType((byte) 52, "SGSN Context Acknowledge");

  /** Message type 53 (Forward Relocation Request) */
  public static final GtpV1MessageType FORWARD_RELOCATION_REQUEST =
      new GtpV1MessageType((byte) 53, "Forward Relocation Request");

  /** Message type 54 (Forward Relocation Response) */
  public static final GtpV1MessageType FORWARD_RELOCATION_RESPONSE =
      new GtpV1MessageType((byte) 54, "Forward Relocation Response");

  /** Message type 55 (Forward Relocation Complete) */
  public static final GtpV1MessageType FORWARD_RELOCATION_COMPLETE =
      new GtpV1MessageType((byte) 55, "Forward Relocation Complete");

  /** Message type 56 (Relocation Cancel Request) */
  public static final GtpV1MessageType RELOCATION_CANCEL_REQUEST =
      new GtpV1MessageType((byte) 56, "Relocation Cancel Request");

  /** Message type 57 (Relocation Cancel Response) */
  public static final GtpV1MessageType RELOCATION_CANCEL_RESPONSE =
      new GtpV1MessageType((byte) 57, "Relocation Cancel Response");

  /** Message type 58 (Forward SNRS Context) */
  public static final GtpV1MessageType FORWARD_SNRS_CONTEXT =
      new GtpV1MessageType((byte) 58, "Forward SNRS Context");

  /** Message type 59 (Forward Relocation Complete Acknowledge) */
  public static final GtpV1MessageType FORWARD_RELOCATION_COMPLETE_ACKNOWLEDGE =
      new GtpV1MessageType((byte) 59, "Forward Relocation Complete Acknowledge");

  /** Message type 60 (Forward SNRS Context Acknowledge) */
  public static final GtpV1MessageType FORWARD_SNRS_CONTEXT_ACKNOWLEDGE =
      new GtpV1MessageType((byte) 60, "Forward SNRS Context Acknowledge");

  /** Message type 70 (RAN Information Relay) */
  public static final GtpV1MessageType RAN_INFORMATION_RELAY =
      new GtpV1MessageType((byte) 70, "RAN Information Relay");

  /** Message type 96 (MBMS Notification Request) */
  public static final GtpV1MessageType MBMS_NOTIFICATION_REQUEST =
      new GtpV1MessageType((byte) 96, "MBMS Notification Request");

  /** Message type 97 (MBMS Notification Response) */
  public static final GtpV1MessageType MBMS_NOTIFICATION_RESPONSE =
      new GtpV1MessageType((byte) 97, "MBMS Notification Response");

  /** Message type 98 (MBMS Notification Reject Request) */
  public static final GtpV1MessageType MBMS_NOTIFICATION_REJECT_REQUEST =
      new GtpV1MessageType((byte) 98, "MBMS Notification Request");

  /** Message type 99 (MBMS Notification Reject Response) */
  public static final GtpV1MessageType MBMS_NOTIFICATION_REJECT_RESPONSE =
      new GtpV1MessageType((byte) 99, "MBMS Notification Response");

  /** Message type 100 (Create MBMS Context Request) */
  public static final GtpV1MessageType CREATE_MBMS_CONTEXT_REQUEST =
      new GtpV1MessageType((byte) 100, "Create MBMS Context Request");

  /** Message type 101 (Create MBMS Context Response) */
  public static final GtpV1MessageType CREATE_MBMS_CONTEXT_RESPONSE =
      new GtpV1MessageType((byte) 101, "Create MBMS Context Response");

  /** Message type 102 (Update MBMS Context Request) */
  public static final GtpV1MessageType UPDATE_MBMS_CONTEXT_REQUEST =
      new GtpV1MessageType((byte) 102, "Update MBMS Context Request");

  /** Message type 103 (Update MBMS Context Response) */
  public static final GtpV1MessageType UPDATE_MBMS_CONTEXT_RESPONSE =
      new GtpV1MessageType((byte) 103, "Update MBMS Context Response");

  /** Message type 104 (Delete MBMS Context Request) */
  public static final GtpV1MessageType DELETE_MBMS_CONTEXT_REQUEST =
      new GtpV1MessageType((byte) 104, "Delete MBMS Context Request");

  /** Message type 105 (Delete MBMS Context Response) */
  public static final GtpV1MessageType DELETE_MBMS_CONTEXT_RESPONSE =
      new GtpV1MessageType((byte) 105, "Delete MBMS Context Response");

  /** Message type 112 (MBMS Registration Request) */
  public static final GtpV1MessageType MBMS_REGISTRATION_REQUEST =
      new GtpV1MessageType((byte) 112, "MBMS Registration Request");

  /** Message type 113 (MBMS Registration Response) */
  public static final GtpV1MessageType MBMS_REGISTRATION_RESPONSE =
      new GtpV1MessageType((byte) 113, "MBMS Registration Response");

  /** Message type 114 (MBMS De-Registration Request) */
  public static final GtpV1MessageType MBMS_DE_REGISTRATION_REQUEST =
      new GtpV1MessageType((byte) 114, "MBMS De Registration Request");

  /** Message type 115 (MBMS De-Registration Response) */
  public static final GtpV1MessageType MBMS_DE_REGISTRATION_RESPONSE =
      new GtpV1MessageType((byte) 115, "MBMS De Registration Response");

  /** Message type 116 (MBMS Session Start Request) */
  public static final GtpV1MessageType MBMS_SESSION_START_REQUEST =
      new GtpV1MessageType((byte) 116, "MBMS Session Start Request");

  /** Message type 117 (MBMS Session Start Response) */
  public static final GtpV1MessageType MBMS_SESSION_START_RESPONSE =
      new GtpV1MessageType((byte) 117, "MBMS Session Start Response");

  /** Message type 118 (MBMS Session Stop Request) */
  public static final GtpV1MessageType MBMS_SESSION_STOP_REQUEST =
      new GtpV1MessageType((byte) 118, "MBMS Session Stop Request");

  /** Message type 119 (MBMS Registration Response) */
  public static final GtpV1MessageType MBMS_SESSION_STOP_RESPONSE =
      new GtpV1MessageType((byte) 119, "MBMS Session Stop Response");

  /** Message type 120 (MBMS Session Update Request) */
  public static final GtpV1MessageType MBMS_SESSION_UPDATE_REQUEST =
      new GtpV1MessageType((byte) 120, "MBMS Session Update Request");

  /** Message type 121 (MBMS Session Update Response) */
  public static final GtpV1MessageType MBMS_SESSION_UPDATE_RESPONSE =
      new GtpV1MessageType((byte) 121, "MBMS Session Update Response");

  /** Message type 128 (MS Info Change Notification Request) */
  public static final GtpV1MessageType MS_INFO_CHANGE_NOTIFICATION_REQUEST =
      new GtpV1MessageType((byte) 128, "MS Info Change Notification Request");

  /** Message type 129 (MS Info Change Notification Response) */
  public static final GtpV1MessageType MS_INFO_CHANGE_NOTIFICATION_RESPONSE =
      new GtpV1MessageType((byte) 129, "MS Info Change Notification Response");

  /** Message type 240 (Data Record Transfer Request) */
  public static final GtpV1MessageType DATA_RECORD_TRANSFER_REQUEST =
      new GtpV1MessageType((byte) 240, "Data Record Transfer Request");

  /** Message type 241 (Data Record Transfer Response) */
  public static final GtpV1MessageType DATA_RECORD_TRANSFER_RESPONSE =
      new GtpV1MessageType((byte) 241, "Data Record Transfer Response");

  /** Message type 254 (End Marker) */
  public static final GtpV1MessageType END_MARKER = new GtpV1MessageType((byte) 254, "End Marker");

  /** Message type 255 (G-PDU) */
  public static final GtpV1MessageType G_PDU = new GtpV1MessageType((byte) 255, "G-PDU");

  private static final Map<Byte, GtpV1MessageType> registry = new HashMap<Byte, GtpV1MessageType>();

  static {
    registry.put(ECHO_REQUEST.value(), ECHO_REQUEST);
    registry.put(ECHO_RESPONSE.value(), ECHO_RESPONSE);
    registry.put(VERSION_NOT_SUPPORTED.value(), VERSION_NOT_SUPPORTED);
    registry.put(NODE_ALIVE_REQUEST.value(), NODE_ALIVE_REQUEST);
    registry.put(NODE_ALIVE_RESPONSE.value(), NODE_ALIVE_RESPONSE);
    registry.put(REDIRECTION_REQUEST.value(), REDIRECTION_REQUEST);
    registry.put(REDIRECTION_RESPONSE.value(), REDIRECTION_RESPONSE);
    registry.put(CREATE_PDP_CONTEXT_REQUEST.value(), CREATE_PDP_CONTEXT_REQUEST);
    registry.put(CREATE_PDP_CONTEXT_RESPONSE.value(), CREATE_PDP_CONTEXT_RESPONSE);
    registry.put(UPDATE_PDP_CONTEXT_REQUEST.value(), UPDATE_PDP_CONTEXT_REQUEST);
    registry.put(UPDATE_PDP_CONTEXT_RESPONSE.value(), UPDATE_PDP_CONTEXT_RESPONSE);
    registry.put(DELETE_PDP_CONTEXT_REQUEST.value(), DELETE_PDP_CONTEXT_REQUEST);
    registry.put(DELETE_PDP_CONTEXT_RESPONSE.value(), DELETE_PDP_CONTEXT_RESPONSE);
    registry.put(
        INITIATE_PDP_CONTEXT_ACTIVATION_REQUEST.value(), INITIATE_PDP_CONTEXT_ACTIVATION_REQUEST);
    registry.put(
        INITIATE_PDP_CONTEXT_ACTIVATION_RESPONSE.value(), INITIATE_PDP_CONTEXT_ACTIVATION_RESPONSE);
    registry.put(ERROR_INDICATION.value(), ERROR_INDICATION);
    registry.put(PDU_NOTIFICATION_REQUEST.value(), PDU_NOTIFICATION_REQUEST);
    registry.put(PDU_NOTIFICATION_RESPONSE.value(), PDU_NOTIFICATION_RESPONSE);
    registry.put(PDU_NOTIFICATION_REJECT_REQUEST.value(), PDU_NOTIFICATION_REJECT_REQUEST);
    registry.put(PDU_NOTIFICATION_REJECT_RESPONSE.value(), PDU_NOTIFICATION_REJECT_RESPONSE);
    registry.put(
        SUPPORTED_EXTENSION_HEADERS_NOTIFICATION.value(), SUPPORTED_EXTENSION_HEADERS_NOTIFICATION);
    registry.put(
        SEND_ROUTING_INFORMATION_FOR_GPRS_REQUEST.value(),
        SEND_ROUTING_INFORMATION_FOR_GPRS_REQUEST);
    registry.put(
        SEND_ROUTING_INFORMATION_FOR_GPRS_RESPONSE.value(),
        SEND_ROUTING_INFORMATION_FOR_GPRS_RESPONSE);
    registry.put(FAILURE_REPORT_REQUEST.value(), FAILURE_REPORT_REQUEST);
    registry.put(FAILURE_REPORT_RESPONSE.value(), FAILURE_REPORT_RESPONSE);
    registry.put(NOTE_MS_GPRS_PRESENT_REQUEST.value(), NOTE_MS_GPRS_PRESENT_REQUEST);
    registry.put(NOTE_MS_GPRS_PRESENT_RESPONSE.value(), NOTE_MS_GPRS_PRESENT_RESPONSE);
    registry.put(IDENTIFICATION_REQUEST.value(), IDENTIFICATION_REQUEST);
    registry.put(IDENTIFICATION_RESPONSE.value(), IDENTIFICATION_RESPONSE);
    registry.put(SGSN_CONTEXT_REQUEST.value(), SGSN_CONTEXT_REQUEST);
    registry.put(SGSN_CONTEXT_RESPONSE.value(), SGSN_CONTEXT_RESPONSE);
    registry.put(SGSN_CONTEXT_ACKNOWLEDGE.value(), SGSN_CONTEXT_ACKNOWLEDGE);
    registry.put(FORWARD_RELOCATION_REQUEST.value(), FORWARD_RELOCATION_REQUEST);
    registry.put(FORWARD_RELOCATION_RESPONSE.value(), FORWARD_RELOCATION_RESPONSE);
    registry.put(FORWARD_RELOCATION_COMPLETE.value(), FORWARD_RELOCATION_COMPLETE);
    registry.put(
        FORWARD_RELOCATION_COMPLETE_ACKNOWLEDGE.value(), FORWARD_RELOCATION_COMPLETE_ACKNOWLEDGE);
    registry.put(RELOCATION_CANCEL_REQUEST.value(), RELOCATION_CANCEL_REQUEST);
    registry.put(RELOCATION_CANCEL_RESPONSE.value(), RELOCATION_CANCEL_RESPONSE);
    registry.put(FORWARD_SNRS_CONTEXT.value(), FORWARD_SNRS_CONTEXT);
    registry.put(FORWARD_SNRS_CONTEXT_ACKNOWLEDGE.value(), FORWARD_SNRS_CONTEXT_ACKNOWLEDGE);
    registry.put(RAN_INFORMATION_RELAY.value(), RAN_INFORMATION_RELAY);
    registry.put(MBMS_NOTIFICATION_REQUEST.value(), MBMS_NOTIFICATION_REQUEST);
    registry.put(MBMS_NOTIFICATION_RESPONSE.value(), MBMS_NOTIFICATION_RESPONSE);
    registry.put(MBMS_NOTIFICATION_REJECT_REQUEST.value(), MBMS_NOTIFICATION_REJECT_REQUEST);
    registry.put(MBMS_NOTIFICATION_REJECT_RESPONSE.value(), MBMS_NOTIFICATION_REJECT_RESPONSE);
    registry.put(CREATE_MBMS_CONTEXT_REQUEST.value(), CREATE_MBMS_CONTEXT_REQUEST);
    registry.put(CREATE_MBMS_CONTEXT_RESPONSE.value(), CREATE_MBMS_CONTEXT_RESPONSE);
    registry.put(UPDATE_MBMS_CONTEXT_REQUEST.value(), UPDATE_MBMS_CONTEXT_REQUEST);
    registry.put(UPDATE_MBMS_CONTEXT_RESPONSE.value(), UPDATE_MBMS_CONTEXT_RESPONSE);
    registry.put(DELETE_MBMS_CONTEXT_REQUEST.value(), DELETE_MBMS_CONTEXT_REQUEST);
    registry.put(DELETE_MBMS_CONTEXT_RESPONSE.value(), DELETE_MBMS_CONTEXT_RESPONSE);
    registry.put(MBMS_REGISTRATION_REQUEST.value(), MBMS_REGISTRATION_REQUEST);
    registry.put(MBMS_REGISTRATION_RESPONSE.value(), MBMS_REGISTRATION_RESPONSE);
    registry.put(MBMS_DE_REGISTRATION_REQUEST.value(), MBMS_DE_REGISTRATION_REQUEST);
    registry.put(MBMS_DE_REGISTRATION_RESPONSE.value(), MBMS_DE_REGISTRATION_RESPONSE);
    registry.put(MBMS_SESSION_START_REQUEST.value(), MBMS_SESSION_START_REQUEST);
    registry.put(MBMS_SESSION_START_RESPONSE.value(), MBMS_SESSION_START_RESPONSE);
    registry.put(MBMS_SESSION_STOP_REQUEST.value(), MBMS_SESSION_STOP_REQUEST);
    registry.put(MBMS_SESSION_STOP_RESPONSE.value(), MBMS_SESSION_STOP_RESPONSE);
    registry.put(MBMS_SESSION_UPDATE_REQUEST.value(), MBMS_SESSION_UPDATE_REQUEST);
    registry.put(MBMS_SESSION_UPDATE_RESPONSE.value(), MBMS_SESSION_UPDATE_RESPONSE);
    registry.put(MS_INFO_CHANGE_NOTIFICATION_REQUEST.value(), MS_INFO_CHANGE_NOTIFICATION_REQUEST);
    registry.put(
        MS_INFO_CHANGE_NOTIFICATION_RESPONSE.value(), MS_INFO_CHANGE_NOTIFICATION_RESPONSE);
    registry.put(DATA_RECORD_TRANSFER_REQUEST.value(), DATA_RECORD_TRANSFER_REQUEST);
    registry.put(DATA_RECORD_TRANSFER_RESPONSE.value(), DATA_RECORD_TRANSFER_RESPONSE);
    registry.put(END_MARKER.value(), END_MARKER);
    registry.put(G_PDU.value(), G_PDU);
  }

  /**
   * @param value value
   * @param name name
   */
  public GtpV1MessageType(Byte value, String name) {
    super(value, name);
  }

  /**
   * @param value value
   * @return a GtpV1MessageType object.
   */
  public static GtpV1MessageType getInstance(Byte value) {
    if (registry.containsKey(value)) {
      return registry.get(value);
    } else {
      return new GtpV1MessageType(value, "unknown");
    }
  }

  /**
   * @param type type
   * @return a GtpV1MessageType object.
   */
  public static GtpV1MessageType register(GtpV1MessageType type) {
    return registry.put(type.value(), type);
  }

  @Override
  public String valueAsString() {
    return String.valueOf(value() & 0xFF);
  }

  @Override
  public int compareTo(GtpV1MessageType o) {
    return value().compareTo(o.value());
  }
}
