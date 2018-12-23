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
 * GTPv2 Message Type
 *
 * @see <a href="http://www.3gpp.org/ftp//Specs/archive/29_series/29.274/29274-e20.zip">3GPP TS
 *     29.274 V14.2.0</a>
 * @author misanek
 * @since pcap4j 1.7.1
 */
public class GtpV2MessageType extends NamedNumber<Byte, GtpV2MessageType> {

  /** */
  private static final long serialVersionUID = -1996685364080926844L;

  /** Message type 1 (Echo Request) */
  public static final GtpV2MessageType ECHO_REQUEST =
      new GtpV2MessageType((byte) 1, "Echo Request");

  /** Message type 2 (Echo Response) */
  public static final GtpV2MessageType ECHO_RESPONSE =
      new GtpV2MessageType((byte) 2, "Echo Response");

  /** Message type 3 (Version not Supported) */
  public static final GtpV2MessageType VERSION_NOT_SUPPORTED =
      new GtpV2MessageType((byte) 3, "Version Not Supported");

  /** Message type 32 (Create Session Request) */
  public static final GtpV2MessageType CREATE_SESSION_REQUEST =
      new GtpV2MessageType((byte) 32, "Create Session Request");

  /** Message type 33 (Create Session Response) */
  public static final GtpV2MessageType CREATE_SESSION_RESPONSE =
      new GtpV2MessageType((byte) 33, "Create Session Response");

  /** Message type 34 (Modify Bearer Request) */
  public static final GtpV2MessageType MODIFY_BEARER_REQUEST =
      new GtpV2MessageType((byte) 34, "Modify Bearer Request");

  /** Message type 35 (Modify Bearer Response) */
  public static final GtpV2MessageType MODIFY_BEARER_RESPONSE =
      new GtpV2MessageType((byte) 35, "Modify Bearer Response");

  /** Message type 36 (Delete Session Request ) */
  public static final GtpV2MessageType DELETE_SESSION_REQUEST =
      new GtpV2MessageType((byte) 36, "Delete Session Request");

  /** Message type 37 (Delete Session Response) */
  public static final GtpV2MessageType DELETE_SESSION_RESPONSE =
      new GtpV2MessageType((byte) 37, "Delete Session Response");

  /** Message type 38 (Change Notification Request) */
  public static final GtpV2MessageType CHANGE_NOTIFICATION_REQUEST =
      new GtpV2MessageType((byte) 38, "Change Notification Request");

  /** Message type 39 (Change Notification Response) */
  public static final GtpV2MessageType CHANGE_NOTIFICATION_RESPONSE =
      new GtpV2MessageType((byte) 39, "Change Notification Response");

  /** Message type 64 (Modify Bearer Command) */
  public static final GtpV2MessageType MODIFY_BEARER_COMMAND =
      new GtpV2MessageType((byte) 64, "Modify Bearer Command");

  /** Message type 65 (Modify Bearer Failure Indication) */
  public static final GtpV2MessageType MODIFY_BEARER_FAILURE_INDICATION =
      new GtpV2MessageType((byte) 65, "Modify Bearer Failure Indication");

  /** Message type 66 (Delete Bearer Command) */
  public static final GtpV2MessageType DELETE_BEARER_COMMAND =
      new GtpV2MessageType((byte) 66, "Delete Bearer Command");

  /** Message type 67 (Delete Bearer Failure Indication) */
  public static final GtpV2MessageType DELETE_BEARER_FAILURE_INDICATION =
      new GtpV2MessageType((byte) 67, "Delete Bearer Failure Indication");

  /** Message type 68 (Bearer Resource Command) */
  public static final GtpV2MessageType BEARER_RESOURCE_COMMAND =
      new GtpV2MessageType((byte) 68, "Bearer Resource Command");

  /** Message type 69 (Bearer Resource Failure Indication) */
  public static final GtpV2MessageType BEARER_RESOURCE_FAILURE_INDICATION =
      new GtpV2MessageType((byte) 69, "Bearer Resource Failure Indication");

  /** Message type 70 (Downlink Data Notification Failure Indication) */
  public static final GtpV2MessageType DOWNLINK_DATA_NOTIFICATION_FAILURE_INDICATION =
      new GtpV2MessageType((byte) 70, "Downlink Data Notification Failure Indication");

  /** Message type 71 (Trace Session Activation) */
  public static final GtpV2MessageType TRACE_SESSION_ACTIVATION =
      new GtpV2MessageType((byte) 71, "Trace Session Activation");

  /** Message type 72 (Trace Session Deactivation) */
  public static final GtpV2MessageType TRACE_SESSION_DEACTIVATION =
      new GtpV2MessageType((byte) 72, "Trace Session Deactivation");

  /** Message type 73 (Stop Paging Indication) */
  public static final GtpV2MessageType STOP_PAGING_INDICATION =
      new GtpV2MessageType((byte) 73, "Stop Paging Indication");

  /** Message type 95 (Create Bearer Request) */
  public static final GtpV2MessageType CREATE_BEARER_REQUEST =
      new GtpV2MessageType((byte) 95, "Create Bearer Request");

  /** Message type 96 (Create Bearer Response) */
  public static final GtpV2MessageType CREATE_BEARER_RESPONSE =
      new GtpV2MessageType((byte) 96, "Create Bearer Response");

  /** Message type 97 (Update Bearer Request) */
  public static final GtpV2MessageType UPDATE_BEARER_REQUEST =
      new GtpV2MessageType((byte) 97, "Update Bearer Request");

  /** Message type 98 (Update Bearer Response) */
  public static final GtpV2MessageType UPDATE_BEARER_RESPONSE =
      new GtpV2MessageType((byte) 98, "Update Bearer Response");

  /** Message type 99 (Delete Bearer Request) */
  public static final GtpV2MessageType DELETE_BEARER_REQUEST =
      new GtpV2MessageType((byte) 99, "Delete Bearer Request");

  /** Message type 100 (Delete Bearer Response) */
  public static final GtpV2MessageType DELETE_BEARER_RESPONSE =
      new GtpV2MessageType((byte) 100, "Delete Bearer Response");

  /** Message type 101 (Delete PDN Connection Set Request) */
  public static final GtpV2MessageType DELETE_PDN_CONNECTION_SET_REQUEST =
      new GtpV2MessageType((byte) 101, "Delete PDN Connection Set Request");

  /** Message type 102 (Delete PDN Connection Set Response) */
  public static final GtpV2MessageType DELETE_PDN_CONNECTION_SET_RESPONSE =
      new GtpV2MessageType((byte) 102, "Delete PDN Connection Set Response");

  /** Message type 128 (Identification Request) */
  public static final GtpV2MessageType IDENTIFICATION_REQUEST =
      new GtpV2MessageType((byte) 128, "Identification Request");

  /** Message type 129 (Identification Response) */
  public static final GtpV2MessageType IDENTIFICATION_RESPONSE =
      new GtpV2MessageType((byte) 129, "Identification Response");

  /** Message type 130 (Context Request) */
  public static final GtpV2MessageType CONTEXT_REQUEST =
      new GtpV2MessageType((byte) 130, "Context Request");

  /** Message type 131 (Context Response) */
  public static final GtpV2MessageType CONTEXT_RESPONSE =
      new GtpV2MessageType((byte) 131, "Context Response");

  /** Message type 132 (Context Acknowledge) */
  public static final GtpV2MessageType CONTEXT_ACKNOWLEDGE =
      new GtpV2MessageType((byte) 132, "Context Acknowledge");

  /** Message type 133 (Forward Relocation Request) */
  public static final GtpV2MessageType FORWARD_RELOCATION_REQUEST =
      new GtpV2MessageType((byte) 133, "Forward Relocation Request");

  /** Message type 134 (Forward Relocation Response */
  public static final GtpV2MessageType FORWARD_RELOCATION_RESPONSE =
      new GtpV2MessageType((byte) 134, "Forward Relocation Response");

  /** Message type 135 (Forward Relocation Complete Notification) */
  public static final GtpV2MessageType FORWARD_RELOCATION_COMPLETE_NOTIFICATION =
      new GtpV2MessageType((byte) 135, "Forward Relocation Complete Notification");

  /** Message type 136 (Forward Relocation Complete Acknowledge) */
  public static final GtpV2MessageType FORWARD_RELOCATION_COMPLETE_ACKNOWLEDGE =
      new GtpV2MessageType((byte) 136, "Forward Relocation Complete Acknowledge");

  /** Message type 137 (Forward Access Context Notification) */
  public static final GtpV2MessageType FORWARD_ACCESS_CONTEXT_NOTIFICATION =
      new GtpV2MessageType((byte) 137, "Forward Access Context Notification");

  /** Message type 138 (Forward Access Context Acknowledge) */
  public static final GtpV2MessageType FORWARD_ACCESS_CONTEXT_ACKNOWLEDGE =
      new GtpV2MessageType((byte) 138, "Forward Access Context Acknowledge");

  /** Message type 139 (Relocation Cancel Request) */
  public static final GtpV2MessageType RELOCATION_CANCEL_REQUEST =
      new GtpV2MessageType((byte) 139, "Relocation Cancel Request");

  /** Message type 140 (Relocation Cancel Response) */
  public static final GtpV2MessageType RELOCATION_CANCEL_RESPONSE =
      new GtpV2MessageType((byte) 140, "Relocation Cancel Response");

  /** Message type 141 (Configuration Transfer Tunnel) */
  public static final GtpV2MessageType CONFIGURATION_TRANSFER_TUNNEL =
      new GtpV2MessageType((byte) 141, "Configuration Transfer Tunnel");

  /** Message type 149 (Detach Notification) */
  public static final GtpV2MessageType DETACH_NOTIFICATION =
      new GtpV2MessageType((byte) 149, "Detach Notification");

  /** Message type 150 (Detach Acknowledge) */
  public static final GtpV2MessageType DETACH_ACKNOWLEDGE =
      new GtpV2MessageType((byte) 150, "Detach Acknowledge");

  /** Message type 151 (CS Paging Indication) */
  public static final GtpV2MessageType CS_PAGING_INDICATION =
      new GtpV2MessageType((byte) 151, "CS Paging Indication");

  /** Message type 152 (RAN Information Relay) */
  public static final GtpV2MessageType RAN_INFORMATION_RELAY =
      new GtpV2MessageType((byte) 152, "RAN Information Relay");

  /** Message type 160 (Create Forwarding Tunnel Request) */
  public static final GtpV2MessageType CREATE_FORWARDING_TUNNEL_REQUEST =
      new GtpV2MessageType((byte) 160, "Create Forwarding Tunnel Request");

  /** Message type 161 (Create Forwarding Tunnel Response) */
  public static final GtpV2MessageType CREATE_FORWARDING_TUNNEL_RESPONSE =
      new GtpV2MessageType((byte) 161, "Create Forwarding Tunnel Response");

  /** Message type 162 (Suspend Notification) */
  public static final GtpV2MessageType SUSPEND_NOTIFICATION =
      new GtpV2MessageType((byte) 162, "Suspend Notification");

  /** Message type 163 (Suspend Acknowledge) */
  public static final GtpV2MessageType SUSPEND_ACKNOWLEDGE =
      new GtpV2MessageType((byte) 163, "Suspend Acknowledge");

  /** Message type 164 (Resume Notification) */
  public static final GtpV2MessageType RESUME_NOTIFICATION =
      new GtpV2MessageType((byte) 164, "Resume Notification");

  /** Message type 165 (Resume Acknowledge) */
  public static final GtpV2MessageType RESUME_ACKNOWLEDGE =
      new GtpV2MessageType((byte) 165, "Resume Acknowledge");

  /** Message type 166 (Create Indirect Data Forwarding Tunnel Request) */
  public static final GtpV2MessageType CREATE_INDIRECT_DATA_FORWARDING_TUNNEL_REQUEST =
      new GtpV2MessageType((byte) 166, "Create Indirect Data Forwarding Tunnel Request");

  /** Message type 167 (Create Indirect Data Forwarding Tunnel Response) */
  public static final GtpV2MessageType CREATE_INDIRECT_DATA_FORWARDING_TUNNEL_RESPONSE =
      new GtpV2MessageType((byte) 167, "Create Indirect Data Forwarding Tunnel Response");

  /** Message type 168 (Delete Indirect Data Forwarding Tunnel Request) */
  public static final GtpV2MessageType DELETE_INDIRECT_DATA_FORWARDING_TUNNEL_REQUEST =
      new GtpV2MessageType((byte) 168, "Delete Indirect Data Forwarding Tunnel Request");

  /** Message type 169 (Delete Indirect Data Forwarding Tunnel Response) */
  public static final GtpV2MessageType DELETE_INDIRECT_DATA_FORWARDING_TUNNEL_RESPONSE =
      new GtpV2MessageType((byte) 169, "Delete Indirect Data Forwarding Tunnel Response");

  /** Message type 170 (Release Access Bearers Request) */
  public static final GtpV2MessageType RELEASE_ACCESS_BEARERS_REQUEST =
      new GtpV2MessageType((byte) 170, "Release Access Bearers Request");

  /** Message type 171 (Release Access Bearers Response) */
  public static final GtpV2MessageType RELEASE_ACCESS_BEARERS_RESPONSE =
      new GtpV2MessageType((byte) 171, "Release Access Bearers Response");

  /** Message type 176 (Downlink Data Notification) */
  public static final GtpV2MessageType DOWNLINK_DATA_NOTIFICATION =
      new GtpV2MessageType((byte) 176, "Downlink Data Notification");

  /** Message type 177 (Downlink Data Notification Acknowledge) */
  public static final GtpV2MessageType DOWNLINK_DATA_NOTIFICATION_ACKNOWLEDGE =
      new GtpV2MessageType((byte) 177, "Downlink Data Notification Acknowledge");

  /** Message type 200 (Update PDN Connection Set Request) */
  public static final GtpV2MessageType UPDATE_PDN_CONNECTION_SET_REQUEST =
      new GtpV2MessageType((byte) 200, "Update PDN Connection Set Request");

  /** Message type 201 (Update PDN Connection Set Response) */
  public static final GtpV2MessageType UPDATE_PDN_CONNECTION_SET_RESPONSE =
      new GtpV2MessageType((byte) 201, "Update PDN Connection Set Response");

  /** Message type 231 (MBMS Session Start Request) */
  public static final GtpV2MessageType MBMS_SESSION_START_REQUEST =
      new GtpV2MessageType((byte) 231, "MBMS Session Start Request");

  /** Message type 232 (MBMS Session Start Response) */
  public static final GtpV2MessageType MBMS_SESSION_START_RESPONSE =
      new GtpV2MessageType((byte) 232, "MBMS Session Start Response");

  /** Message type 233 (MBMS Session Update Request) */
  public static final GtpV2MessageType MBMS_SESSION_UPDATE_REQUEST =
      new GtpV2MessageType((byte) 233, "MBMS Session Update Request");

  /** Message type 234 (MBMS Session Update Response) */
  public static final GtpV2MessageType MBMS_SESSION_UPDATE_RESPONSE =
      new GtpV2MessageType((byte) 255, "MBMS Session Update Response");

  /** Message type 235 (MBMS Session Stop Request) */
  public static final GtpV2MessageType MBMS_SESSION_STOP_REQUEST =
      new GtpV2MessageType((byte) 235, "MBMS Session Stop Request");

  /** Message type 236 (MBMS Session Stop Response) */
  public static final GtpV2MessageType MBMS_SESSION_STOP_RESPONSE =
      new GtpV2MessageType((byte) 236, "MBMS Session Stop Response");

  private static final Map<Byte, GtpV2MessageType> registry = new HashMap<Byte, GtpV2MessageType>();

  static {
    registry.put(ECHO_REQUEST.value(), ECHO_REQUEST);
    registry.put(ECHO_RESPONSE.value(), ECHO_RESPONSE);
    registry.put(VERSION_NOT_SUPPORTED.value(), VERSION_NOT_SUPPORTED);
    registry.put(CREATE_SESSION_REQUEST.value(), CREATE_SESSION_REQUEST);
    registry.put(CREATE_SESSION_RESPONSE.value(), CREATE_SESSION_RESPONSE);
    registry.put(MODIFY_BEARER_REQUEST.value(), MODIFY_BEARER_REQUEST);
    registry.put(MODIFY_BEARER_RESPONSE.value(), MODIFY_BEARER_RESPONSE);
    registry.put(DELETE_SESSION_REQUEST.value(), DELETE_SESSION_REQUEST);
    registry.put(DELETE_SESSION_RESPONSE.value(), DELETE_SESSION_RESPONSE);
    registry.put(CHANGE_NOTIFICATION_REQUEST.value(), CHANGE_NOTIFICATION_REQUEST);
    registry.put(CHANGE_NOTIFICATION_RESPONSE.value(), CHANGE_NOTIFICATION_RESPONSE);
    registry.put(MODIFY_BEARER_COMMAND.value(), MODIFY_BEARER_COMMAND);
    registry.put(MODIFY_BEARER_FAILURE_INDICATION.value(), MODIFY_BEARER_FAILURE_INDICATION);
    registry.put(DELETE_BEARER_COMMAND.value(), DELETE_BEARER_COMMAND);
    registry.put(DELETE_BEARER_FAILURE_INDICATION.value(), DELETE_BEARER_FAILURE_INDICATION);
    registry.put(BEARER_RESOURCE_COMMAND.value(), BEARER_RESOURCE_COMMAND);
    registry.put(BEARER_RESOURCE_FAILURE_INDICATION.value(), BEARER_RESOURCE_FAILURE_INDICATION);
    registry.put(
        DOWNLINK_DATA_NOTIFICATION_FAILURE_INDICATION.value(),
        DOWNLINK_DATA_NOTIFICATION_FAILURE_INDICATION);
    registry.put(TRACE_SESSION_ACTIVATION.value(), TRACE_SESSION_ACTIVATION);
    registry.put(TRACE_SESSION_DEACTIVATION.value(), TRACE_SESSION_DEACTIVATION);
    registry.put(STOP_PAGING_INDICATION.value(), STOP_PAGING_INDICATION);
    registry.put(CREATE_BEARER_REQUEST.value(), CREATE_BEARER_REQUEST);
    registry.put(CREATE_BEARER_RESPONSE.value(), CREATE_BEARER_RESPONSE);
    registry.put(UPDATE_BEARER_REQUEST.value(), UPDATE_BEARER_REQUEST);
    registry.put(UPDATE_BEARER_RESPONSE.value(), UPDATE_BEARER_RESPONSE);
    registry.put(DELETE_BEARER_REQUEST.value(), DELETE_BEARER_REQUEST);
    registry.put(DELETE_BEARER_RESPONSE.value(), DELETE_BEARER_RESPONSE);
    registry.put(DELETE_PDN_CONNECTION_SET_REQUEST.value(), DELETE_PDN_CONNECTION_SET_REQUEST);
    registry.put(
        DELETE_INDIRECT_DATA_FORWARDING_TUNNEL_RESPONSE.value(),
        DELETE_INDIRECT_DATA_FORWARDING_TUNNEL_RESPONSE);
    registry.put(IDENTIFICATION_REQUEST.value(), IDENTIFICATION_REQUEST);
    registry.put(IDENTIFICATION_RESPONSE.value(), IDENTIFICATION_RESPONSE);
    registry.put(CONTEXT_REQUEST.value(), CONTEXT_REQUEST);
    registry.put(CONTEXT_RESPONSE.value(), CONTEXT_RESPONSE);
    registry.put(CONTEXT_ACKNOWLEDGE.value(), CONTEXT_ACKNOWLEDGE);
    registry.put(FORWARD_RELOCATION_REQUEST.value(), FORWARD_RELOCATION_REQUEST);
    registry.put(FORWARD_RELOCATION_RESPONSE.value(), FORWARD_RELOCATION_RESPONSE);
    registry.put(
        FORWARD_RELOCATION_COMPLETE_NOTIFICATION.value(), FORWARD_RELOCATION_COMPLETE_NOTIFICATION);
    registry.put(
        FORWARD_RELOCATION_COMPLETE_ACKNOWLEDGE.value(), FORWARD_RELOCATION_COMPLETE_ACKNOWLEDGE);
    registry.put(FORWARD_ACCESS_CONTEXT_NOTIFICATION.value(), FORWARD_ACCESS_CONTEXT_NOTIFICATION);
    registry.put(FORWARD_ACCESS_CONTEXT_ACKNOWLEDGE.value(), FORWARD_ACCESS_CONTEXT_ACKNOWLEDGE);
    registry.put(RELOCATION_CANCEL_REQUEST.value(), RELOCATION_CANCEL_REQUEST);
    registry.put(RELOCATION_CANCEL_RESPONSE.value(), RELOCATION_CANCEL_RESPONSE);
    registry.put(CONFIGURATION_TRANSFER_TUNNEL.value(), CONFIGURATION_TRANSFER_TUNNEL);
    registry.put(RAN_INFORMATION_RELAY.value(), RAN_INFORMATION_RELAY);
    registry.put(DETACH_NOTIFICATION.value(), DETACH_NOTIFICATION);
    registry.put(DETACH_ACKNOWLEDGE.value(), DETACH_ACKNOWLEDGE);
    registry.put(CS_PAGING_INDICATION.value(), CS_PAGING_INDICATION);
    registry.put(SUSPEND_NOTIFICATION.value(), SUSPEND_NOTIFICATION);
    registry.put(SUSPEND_ACKNOWLEDGE.value(), SUSPEND_ACKNOWLEDGE);
    registry.put(CREATE_FORWARDING_TUNNEL_REQUEST.value(), CREATE_FORWARDING_TUNNEL_REQUEST);
    registry.put(CREATE_FORWARDING_TUNNEL_RESPONSE.value(), CREATE_FORWARDING_TUNNEL_RESPONSE);
    registry.put(RESUME_NOTIFICATION.value(), RESUME_NOTIFICATION);
    registry.put(RESUME_ACKNOWLEDGE.value(), RESUME_ACKNOWLEDGE);
    registry.put(
        CREATE_INDIRECT_DATA_FORWARDING_TUNNEL_REQUEST.value(),
        CREATE_INDIRECT_DATA_FORWARDING_TUNNEL_REQUEST);
    registry.put(
        CREATE_INDIRECT_DATA_FORWARDING_TUNNEL_RESPONSE.value(),
        CREATE_INDIRECT_DATA_FORWARDING_TUNNEL_RESPONSE);
    registry.put(
        DELETE_INDIRECT_DATA_FORWARDING_TUNNEL_REQUEST.value(),
        DELETE_INDIRECT_DATA_FORWARDING_TUNNEL_REQUEST);
    registry.put(
        DELETE_INDIRECT_DATA_FORWARDING_TUNNEL_RESPONSE.value(),
        DELETE_INDIRECT_DATA_FORWARDING_TUNNEL_RESPONSE);
    registry.put(RELEASE_ACCESS_BEARERS_REQUEST.value(), RELEASE_ACCESS_BEARERS_REQUEST);
    registry.put(RELEASE_ACCESS_BEARERS_RESPONSE.value(), RELEASE_ACCESS_BEARERS_RESPONSE);
    registry.put(DOWNLINK_DATA_NOTIFICATION.value(), DOWNLINK_DATA_NOTIFICATION);
    registry.put(
        DOWNLINK_DATA_NOTIFICATION_ACKNOWLEDGE.value(), DOWNLINK_DATA_NOTIFICATION_ACKNOWLEDGE);
    registry.put(UPDATE_PDN_CONNECTION_SET_REQUEST.value(), UPDATE_PDN_CONNECTION_SET_REQUEST);
    registry.put(UPDATE_PDN_CONNECTION_SET_RESPONSE.value(), UPDATE_PDN_CONNECTION_SET_RESPONSE);
    registry.put(MBMS_SESSION_START_REQUEST.value(), MBMS_SESSION_START_REQUEST);
    registry.put(MBMS_SESSION_START_RESPONSE.value(), MBMS_SESSION_START_RESPONSE);
    registry.put(MBMS_SESSION_UPDATE_REQUEST.value(), MBMS_SESSION_UPDATE_REQUEST);
    registry.put(MBMS_SESSION_UPDATE_RESPONSE.value(), MBMS_SESSION_UPDATE_RESPONSE);
    registry.put(MBMS_SESSION_STOP_REQUEST.value(), MBMS_SESSION_STOP_REQUEST);
    registry.put(MBMS_SESSION_STOP_RESPONSE.value(), MBMS_SESSION_STOP_RESPONSE);
  }

  /**
   * @param value value
   * @param name name
   */
  public GtpV2MessageType(Byte value, String name) {
    super(value, name);
  }

  /**
   * @param value value
   * @return a GtpV2MessageType object.
   */
  public static GtpV2MessageType getInstance(Byte value) {
    if (registry.containsKey(value)) {
      return registry.get(value);
    } else {
      return new GtpV2MessageType(value, "unknown");
    }
  }

  /**
   * @param type type
   * @return a GtpV2MessageType object.
   */
  public static GtpV2MessageType register(GtpV2MessageType type) {
    return registry.put(type.value(), type);
  }

  @Override
  public String valueAsString() {
    return String.valueOf(value() & 0xFF);
  }

  @Override
  public int compareTo(GtpV2MessageType o) {
    return value().compareTo(o.value());
  }
}
