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
 * @see <a href="http://www.etsi.org/deliver/etsi_ts/129000_129099/129060/12.06.00_60/ts_129060v120600p.pdf">ETSI TS 129 060 V12.6.0</a>
 * @author Waveform
 * @since pcap4j 1.6.6
 */
public final class GtpV1MessageType extends NamedNumber<Byte, GtpV1MessageType> {

  /**
   *
   */
  private static final long serialVersionUID = 7592798859079852877L;

  /**
   * Message type 1 (Echo Request)
   */
  public static final GtpV1MessageType Echo_Request
    = new GtpV1MessageType((byte)1, "Echo_Request");

  /**
   * Message type 2 (Echo Response)
   */
  public static final GtpV1MessageType Echo_Response
    = new GtpV1MessageType((byte)2, "Echo_Response");

  /**
   * Message type 3 (Version not Supported)
   */
  public static final GtpV1MessageType Version_Not_Supported
    = new GtpV1MessageType((byte)3, "Version_Not_Supported");

  /**
   * Message type 4 (Node Alive Request)
   */
  public static final GtpV1MessageType Node_Alive_Request
    = new GtpV1MessageType((byte)4, "Node_Alive_Request");

  /**
   * Message type 5 (Node Alive Response)
   */
  public static final GtpV1MessageType Node_Alive_Response
    = new GtpV1MessageType((byte)5, "Node_Alive_Response");

  /**
   * Message type 6 (Redirection Request)
   */
  public static final GtpV1MessageType Redirection_Request
    = new GtpV1MessageType((byte)6, "Redirection_Request");

  /**
   * Message type 7 (Redirection Response)
   */
  public static final GtpV1MessageType Redirection_Response
    = new GtpV1MessageType((byte)7, "Redirection_Response");

  /**
   * Message type 16 (Create PDP Context Request)
   */
  public static final GtpV1MessageType Create_PDP_Context_Request
    = new GtpV1MessageType((byte)16, "Create_PDP_Context_Request");

  /**
   * Message type 17 (Create PDP Context Response)
   */
  public static final GtpV1MessageType Create_PDP_Context_Response
    = new GtpV1MessageType((byte)17, "Create_PDP_Context_Response");

  /**
   * Message type 18 (Update PDP Context Request)
   */
  public static final GtpV1MessageType Update_PDP_Context_Request
    = new GtpV1MessageType((byte)18, "Update_PDP_Context_Request");

  /**
   * Message type 19 (Update PDP Context Response)
   */
  public static final GtpV1MessageType Update_PDP_Context_Response
    = new GtpV1MessageType((byte)19, "Update_PDP_Context_Response");

  /**
   * Message type 20 (Delete PDP Context Request)
   */
  public static final GtpV1MessageType Delete_PDP_Context_Request
    = new GtpV1MessageType((byte)20, "Delete_PDP_Context_Request");

  /**
   * Message type 21 (Delete PDP Context Response)
   */
  public static final GtpV1MessageType Delete_PDP_Context_Response
    = new GtpV1MessageType((byte)21, "Delete_PDP_Context_Response");

  /**
   * Message type 22 (Initiate PDP Context Activation Request)
   */
  public static final GtpV1MessageType Initiate_PDP_Context_Activation_Request
    = new GtpV1MessageType((byte)22, "Initiate_PDP_Context_Activation_Request");

  /**
   * Message type 23 (Initiate PDP Context Activation Response)
   */
  public static final GtpV1MessageType Initiate_PDP_Context_Activation_Response
    = new GtpV1MessageType((byte)22, "Initiate_PDP_Context_Activation_Response");

  /**
   * Message type 26 (Error Indication)
   */
  public static final GtpV1MessageType Error_Indication
    = new GtpV1MessageType((byte)26, "Error_Indication");

  /**
   * Message type 27 (PDU Notification Request)
   */
  public static final GtpV1MessageType PDU_Notification_Request
    = new GtpV1MessageType((byte)27, "PDU_Notification_Request");

  /**
   * Message type 28 (PDU Notification Response)
   */
  public static final GtpV1MessageType PDU_Notification_Response
    = new GtpV1MessageType((byte)28, "PDU_Notification_Response");

  /**
   * Message type 29 (PDU Notification Reject Request)
   */
  public static final GtpV1MessageType PDU_Notification_Reject_Request
    = new GtpV1MessageType((byte)29, "PDU_Notification_Reject_Request");

  /**
   * Message type 30 (PDU Notification Reject Response)
   */
  public static final GtpV1MessageType PDU_Notification_Reject_Response
    = new GtpV1MessageType((byte)30, "PDU_Notification_Reject_Response");

  /**
   * Message type 31 (Supported Extension Headers Notification)
   */
  public static final GtpV1MessageType Supported_Extension_Headers_Notification
    = new GtpV1MessageType((byte)31, "Supported_Extension_Headers_Notification");

  /**
   * Message type 32 (Send Routing Information for GPRS Request)
   */
  public static final GtpV1MessageType Send_Routing_Information_for_GPRS_Request
    = new GtpV1MessageType((byte)32, "Send_Routing_Information_for_GPRS_Request");

  /**
   * Message type 33 (Send Routing Information for GPRS Response)
   */
  public static final GtpV1MessageType Send_Routing_Information_for_GPRS_Response
    = new GtpV1MessageType((byte)33, "Send_Routing_Information_for_GPRS_Response");

  /**
   * Message type 34 (Failure Report Request)
   */
  public static final GtpV1MessageType Failure_Report_Request
    = new GtpV1MessageType((byte)34, "Failure_Report_Request");

  /**
   * Message type 35 (Failure Report Response)
   */
  public static final GtpV1MessageType Failure_Report_Response
    = new GtpV1MessageType((byte)35, "Failure_Report_Response");

  /**
   * Message type 36 (Note MS GPRS Present Request )
   */
  public static final GtpV1MessageType Note_MS_GPRS_Present_Request
    = new GtpV1MessageType((byte)36, "Note_MS_GPRS_Present_Request");

  /**
   * Message type 37 (Note MS GPRS Present Response)
   */
  public static final GtpV1MessageType Note_MS_GPRS_Present_Response
    = new GtpV1MessageType((byte)37, "Note_MS_GPRS_Present_Response");

  /**
   * Message type 48 (Identification Request)
   */
  public static final GtpV1MessageType Identification_Request
    = new GtpV1MessageType((byte)48, "Identification_Request");

  /**
   * Message type 49 (Identification Response)
   */
  public static final GtpV1MessageType Identification_Response
    = new GtpV1MessageType((byte)49, "Identification_Response");

  /**
   * Message type 50 (SGSN Context Request)
   */
  public static final GtpV1MessageType SGSN_Context_Request
    = new GtpV1MessageType((byte)50, "SGSN_Context_Request");

  /**
   * Message type 51 (SGSN Context Response)
   */
  public static final GtpV1MessageType SGSN_Context_Response
    = new GtpV1MessageType((byte)51, "SGSN_Context_Response");

  /**
   * Message type 52 (SGSN Context Acknowledge)
   */
  public static final GtpV1MessageType SGSN_Context_Acknowledge
    = new GtpV1MessageType((byte)52, "SGSN_Context_Acknowledge");

  /**
   * Message type 53 (Forward Relocation Request)
   */
  public static final GtpV1MessageType Forward_Relocation_Request
    = new GtpV1MessageType((byte)53, "Forward_Relocation_Request");

  /**
   * Message type 54 (Forward Relocation Response)
   */
  public static final GtpV1MessageType Forward_Relocation_Response
    = new GtpV1MessageType((byte)54, "Forward_Relocation_Response");

  /**
   * Message type 55 (Forward Relocation Complete)
   */
  public static final GtpV1MessageType Forward_Relocation_Complete
    = new GtpV1MessageType((byte)55, "Forward_Relocation_Complete");

  /**
   * Message type 56 (Relocation Cancel Request)
   */
  public static final GtpV1MessageType Relocation_Cancel_Request
    = new GtpV1MessageType((byte)56, "Relocation_Cancel_Request");

  /**
   * Message type 57 (Relocation Cancel Response)
   */
  public static final GtpV1MessageType Relocation_Cancel_Response
    = new GtpV1MessageType((byte)57, "Relocation_Cancel_Response");

  /**
   * Message type 58 (Forward SNRS Context)
   */
  public static final GtpV1MessageType Forward_SNRS_Context
    = new GtpV1MessageType((byte)58, "Forward_SNRS_Context");

  /**
   * Message type 59 (Forward Relocation Complete Acknowledge)
   */
  public static final GtpV1MessageType Forward_Relocation_Complete_Acknowledge
    = new GtpV1MessageType((byte)59, "Forward_Relocation_Complete_Acknowledge");

  /**
   * Message type 60 (Forward SNRS Context Acknowledge)
   */
  public static final GtpV1MessageType Forward_SNRS_Context_Acknowledge
    = new GtpV1MessageType((byte)60, "Forward_SNRS_Context_Acknowledge");

  /**
   * Message type 70 (RAN Information Relay)
   */
  public static final GtpV1MessageType RAN_Information_Relay
    = new GtpV1MessageType((byte)70, "RAN_Information_Relay");

  /**
   * Message type 96 (MBMS Notification Request)
   */
  public static final GtpV1MessageType MBMS_Notification_Request
    = new GtpV1MessageType((byte)96, "MBMS_Notification_Request");

  /**
   * Message type 97 (MBMS Notification Response)
   */
  public static final GtpV1MessageType MBMS_Notification_Response
    = new GtpV1MessageType((byte)97, "MBMS_Notification_Response");

  /**
   * Message type 98 (MBMS Notification Reject Request)
   */
  public static final GtpV1MessageType MBMS_Notification_Reject_Request
    = new GtpV1MessageType((byte)98, "MBMS_Notification_Request");

  /**
   * Message type 99 (MBMS Notification Reject Response)
   */
  public static final GtpV1MessageType MBMS_Notification_Reject_Response
    = new GtpV1MessageType((byte)99, "MBMS_Notification_Response");

  /**
   * Message type 100 (Create MBMS Context Request)
   */
  public static final GtpV1MessageType Create_MBMS_Context_Request
    = new GtpV1MessageType((byte)100, "Create_MBMS_Context_Request");

  /**
   * Message type 101 (Create MBMS Context Response)
   */
  public static final GtpV1MessageType Create_MBMS_Context_Response
    = new GtpV1MessageType((byte)101, "Create_MBMS_Context_Response");

  /**
   * Message type 102 (Update MBMS Context Request)
   */
  public static final GtpV1MessageType Update_MBMS_Context_Request
    = new GtpV1MessageType((byte)102, "Update_MBMS_Context_Request");

  /**
   * Message type 103 (Update MBMS Context Response)
   */
  public static final GtpV1MessageType Update_MBMS_Context_Response
    = new GtpV1MessageType((byte)103, "Update_MBMS_Context_Response");

  /**
   * Message type 104 (Delete MBMS Context Request)
   */
  public static final GtpV1MessageType Delete_MBMS_Context_Request
    = new GtpV1MessageType((byte)104, "Delete_MBMS_Context_Request");

  /**
   * Message type 105 (Delete MBMS Context Response)
   */
  public static final GtpV1MessageType Delete_MBMS_Context_Response
    = new GtpV1MessageType((byte)105, "Delete_MBMS_Context_Response");

  /**
   * Message type 112 (MBMS Registration Request)
   */
  public static final GtpV1MessageType MBMS_Registration_Request
    = new GtpV1MessageType((byte)112, "MBMS_Registration_Request");

  /**
   * Message type 113 (MBMS Registration Response)
   */
  public static final GtpV1MessageType MBMS_Registration_Response
    = new GtpV1MessageType((byte)113, "MBMS_Registration_Response");

  /**
   * Message type 114 (MBMS De-Registration Request)
   */
  public static final GtpV1MessageType MBMS_De_Registration_Request
    = new GtpV1MessageType((byte)114, "MBMS_De_Registration_Request");

  /**
   * Message type 115 (MBMS De-Registration Response)
   */
  public static final GtpV1MessageType MBMS_De_Registration_Response
    = new GtpV1MessageType((byte)115, "MBMS_De_Registration_Response");

  /**
   * Message type 116 (MBMS Session Start Request)
   */
  public static final GtpV1MessageType MBMS_Session_Start_Request
    = new GtpV1MessageType((byte)116, "MBMS_Session_Start_Request");

  /**
   * Message type 117 (MBMS Session Start Response)
   */
  public static final GtpV1MessageType MBMS_Session_Start_Response
    = new GtpV1MessageType((byte)117, "MBMS_Session_Start_Response");

  /**
   * Message type 118 (MBMS Session Stop Request)
   */
  public static final GtpV1MessageType MBMS_Session_Stop_Request
    = new GtpV1MessageType((byte)118, "MBMS_Session_Stop_Request");

  /**
   * Message type 119 (MBMS Registration Response)
   */
  public static final GtpV1MessageType MBMS_Session_Stop_Response
    = new GtpV1MessageType((byte)119, "MBMS_Session_Stop_Response");

  /**
   * Message type 120 (MBMS Session Update Request)
   */
  public static final GtpV1MessageType MBMS_Session_Update_Request
    = new GtpV1MessageType((byte)120, "MBMS_Session_Update_Request");

  /**
   * Message type 121 (MBMS Session Update Response)
   */
  public static final GtpV1MessageType MBMS_Session_Update_Response
    = new GtpV1MessageType((byte)121, "MBMS_Session_Update_Response");

  /**
   * Message type 128 (MS Info Change Notification Request)
   */
  public static final GtpV1MessageType MS_Info_Change_Notification_Request
    = new GtpV1MessageType((byte)128, "MS_Info_Change_Notification_Request");

  /**
   * Message type 129 (MS Info Change Notification Response)
   */
  public static final GtpV1MessageType MS_Info_Change_Notification_Response
    = new GtpV1MessageType((byte)129, "MS_Info_Change_Notification_Response");

  /**
   * Message type 240 (Data Record Transfer Request)
   */
  public static final GtpV1MessageType Data_Record_Transfer_Request
    = new GtpV1MessageType((byte)240, "Data_Record_Transfer_Request");

  /**
   * Message type 241 (Data Record Transfer Response)
   */
  public static final GtpV1MessageType Data_Record_Transfer_Response
    = new GtpV1MessageType((byte)241, "Data_Record_Transfer_Response");

  /**
   * Message type 254 (End Marker)
   */
  public static final GtpV1MessageType End_Marker
    = new GtpV1MessageType((byte)254, "End_Marker");

  /**
   * Message type 255 (G-PDU)
   */
  public static final GtpV1MessageType G_PDU
    = new GtpV1MessageType((byte)255, "G_PDU");

  private static final Map<Byte, GtpV1MessageType> registry
    = new HashMap<Byte, GtpV1MessageType>();

  static {
    registry.put(Echo_Request.value(), Echo_Request);
    registry.put(Echo_Response.value(), Echo_Response);
    registry.put(Version_Not_Supported.value(), Version_Not_Supported);
    registry.put(Node_Alive_Request.value(), Node_Alive_Request);
    registry.put(Node_Alive_Response.value(), Node_Alive_Response);
    registry.put(Redirection_Request.value(), Redirection_Request);
    registry.put(Redirection_Response.value(), Redirection_Response);
    registry.put(Create_PDP_Context_Request.value(), Create_PDP_Context_Request);
    registry.put(Create_PDP_Context_Response.value(), Create_PDP_Context_Response);
    registry.put(Update_PDP_Context_Request.value(), Update_PDP_Context_Request);
    registry.put(Update_PDP_Context_Response.value(), Update_PDP_Context_Response);
    registry.put(Delete_PDP_Context_Request.value(), Delete_PDP_Context_Request);
    registry.put(Delete_PDP_Context_Response.value(), Delete_PDP_Context_Response);
    registry.put(Initiate_PDP_Context_Activation_Request.value(), Initiate_PDP_Context_Activation_Request);
    registry.put(Initiate_PDP_Context_Activation_Response.value(), Initiate_PDP_Context_Activation_Response);
    registry.put(Error_Indication.value(), Error_Indication);
    registry.put(PDU_Notification_Request.value(), PDU_Notification_Request);
    registry.put(PDU_Notification_Response.value(), PDU_Notification_Response);
    registry.put(PDU_Notification_Reject_Request.value(), PDU_Notification_Reject_Request);
    registry.put(PDU_Notification_Reject_Response.value(), PDU_Notification_Reject_Response);
    registry.put(Supported_Extension_Headers_Notification.value(), Supported_Extension_Headers_Notification);
    registry.put(Send_Routing_Information_for_GPRS_Request.value(), Send_Routing_Information_for_GPRS_Request);
    registry.put(Send_Routing_Information_for_GPRS_Response.value(), Send_Routing_Information_for_GPRS_Response);
    registry.put(Failure_Report_Request.value(), Failure_Report_Request);
    registry.put(Failure_Report_Response.value(), Failure_Report_Response);
    registry.put(Note_MS_GPRS_Present_Request.value(), Note_MS_GPRS_Present_Request);
    registry.put(Note_MS_GPRS_Present_Response.value(), Note_MS_GPRS_Present_Response);
    registry.put(Identification_Request.value(), Identification_Request);
    registry.put(Identification_Response.value(), Identification_Response);
    registry.put(SGSN_Context_Request.value(), SGSN_Context_Request);
    registry.put(SGSN_Context_Response.value(), SGSN_Context_Response);
    registry.put(SGSN_Context_Acknowledge.value(), SGSN_Context_Acknowledge);
    registry.put(Forward_Relocation_Request.value(), Forward_Relocation_Request);
    registry.put(Forward_Relocation_Response.value(), Forward_Relocation_Response);
    registry.put(Forward_Relocation_Complete.value(), Forward_Relocation_Complete);
    registry.put(Forward_Relocation_Complete_Acknowledge.value(), Forward_Relocation_Complete_Acknowledge);
    registry.put(Relocation_Cancel_Request.value(), Relocation_Cancel_Request);
    registry.put(Relocation_Cancel_Response.value(), Relocation_Cancel_Response);
    registry.put(Forward_SNRS_Context.value(), Forward_SNRS_Context);
    registry.put(Forward_SNRS_Context_Acknowledge.value(), Forward_SNRS_Context_Acknowledge);
    registry.put(RAN_Information_Relay.value(), RAN_Information_Relay);
    registry.put(MBMS_Notification_Request.value(), MBMS_Notification_Request);
    registry.put(MBMS_Notification_Response.value(), MBMS_Notification_Response);
    registry.put(MBMS_Notification_Reject_Request.value(), MBMS_Notification_Reject_Request);
    registry.put(MBMS_Notification_Reject_Response.value(), MBMS_Notification_Reject_Response);
    registry.put(Create_MBMS_Context_Request.value(), Create_MBMS_Context_Request);
    registry.put(Create_MBMS_Context_Response.value(), Create_MBMS_Context_Response);
    registry.put(Update_MBMS_Context_Request.value(), Update_MBMS_Context_Request);
    registry.put(Update_MBMS_Context_Response.value(), Update_MBMS_Context_Response);
    registry.put(Delete_MBMS_Context_Request.value(), Delete_MBMS_Context_Request);
    registry.put(Delete_MBMS_Context_Response.value(), Delete_MBMS_Context_Response);
    registry.put(MBMS_Registration_Request.value(), MBMS_Registration_Request);
    registry.put(MBMS_Registration_Response.value(), MBMS_Registration_Response);
    registry.put(MBMS_De_Registration_Request.value(), MBMS_De_Registration_Request);
    registry.put(MBMS_De_Registration_Response.value(), MBMS_De_Registration_Response);
    registry.put(MBMS_Session_Start_Request.value(), MBMS_Session_Start_Request);
    registry.put(MBMS_Session_Start_Response.value(), MBMS_Session_Start_Response);
    registry.put(MBMS_Session_Stop_Request.value(), MBMS_Session_Stop_Request);
    registry.put(MBMS_Session_Stop_Response.value(), MBMS_Session_Stop_Response);
    registry.put(MBMS_Session_Update_Request.value(), MBMS_Session_Update_Request);
    registry.put(MBMS_Session_Update_Response.value(), MBMS_Session_Update_Response);
    registry.put(MS_Info_Change_Notification_Request.value(), MS_Info_Change_Notification_Request);
    registry.put(MS_Info_Change_Notification_Response.value(), MS_Info_Change_Notification_Response);
    registry.put(Data_Record_Transfer_Request.value(), Data_Record_Transfer_Request);
    registry.put(Data_Record_Transfer_Response.value(), Data_Record_Transfer_Response);
    registry.put(End_Marker.value(), End_Marker);
    registry.put(G_PDU.value(), G_PDU);
  }

  /**
   *
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
    }
    else {
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
