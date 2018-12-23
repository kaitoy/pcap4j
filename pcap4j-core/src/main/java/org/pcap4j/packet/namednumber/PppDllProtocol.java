/*_##########################################################################
  _##
  _##  Copyright (C) 2015  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.namednumber;

import java.util.HashMap;
import java.util.Map;
import org.pcap4j.util.ByteArrays;

/**
 * PPP DLL Protocol
 *
 * @see <a href="http://www.iana.org/assignments/ppp-numbers/ppp-numbers.xhtml#ppp-numbers-2">IANA
 *     Registry</a>
 * @author Kaito Yamada
 * @since pcap4j 1.4.0
 */
public final class PppDllProtocol extends NamedNumber<Short, PppDllProtocol> {

  /** */
  private static final long serialVersionUID = -6344960553361779564L;

  /** Padding Protocol: 0x0001 */
  public static final PppDllProtocol PADDING_PROTOCOL =
      new PppDllProtocol((short) 0x0001, "Padding Protocol");

  /** ROHC small-CID: 0x0003 */
  public static final PppDllProtocol ROHC_SMALL_CID =
      new PppDllProtocol((short) 0x0003, "ROHC small-CID");

  /** ROHC large-CID: 0x0005 */
  public static final PppDllProtocol ROHC_LARGE_CID =
      new PppDllProtocol((short) 0x0005, "ROHC large-CID");

  /** IPv4: 0x0021 */
  public static final PppDllProtocol IPV4 = new PppDllProtocol((short) 0x0021, "IPv4");

  /** OSI Network Layer: 0x0023 */
  public static final PppDllProtocol OSI_NETWORK_LAYER =
      new PppDllProtocol((short) 0x0023, "OSI Network Layer");

  /** Xerox NS IDP: 0x0025 */
  public static final PppDllProtocol XEROX_NS_IDP =
      new PppDllProtocol((short) 0x0025, "Xerox NS IDP");

  /** DECnet Phase IV: 0x0027 */
  public static final PppDllProtocol DECNET_PHASE_IV =
      new PppDllProtocol((short) 0x0027, "DECnet Phase IV");

  /** Appletalk: 0x0029 */
  public static final PppDllProtocol APPLETALK = new PppDllProtocol((short) 0x0029, "Appletalk");

  /** Novell IPX: 0x002b */
  public static final PppDllProtocol NOVELL_IPX = new PppDllProtocol((short) 0x002b, "Novell IPX");

  /** Van Jacobson Compressed TCP/IP: 0x002d */
  public static final PppDllProtocol VAN_JACOBSON_COMPRESSED_TCP_IP =
      new PppDllProtocol((short) 0x002d, "Van Jacobson Compressed TCP/IP");

  /** Van Jacobson Uncompressed TCP/IP: 0x002f */
  public static final PppDllProtocol VAN_JACOBSON_UNCOMPRESSED_TCP_IP =
      new PppDllProtocol((short) 0x002f, "Van Jacobson Uncompressed TCP/IP");

  /** Bridging PDU: 0x0031 */
  public static final PppDllProtocol BRIDGING_PDU =
      new PppDllProtocol((short) 0x0031, "Bridging PDU");

  /** ST-II: 0x0033 */
  public static final PppDllProtocol ST_II = new PppDllProtocol((short) 0x0033, "ST-II");

  /** Banyan Vines: 0x0035 */
  public static final PppDllProtocol BANYAN_VINES =
      new PppDllProtocol((short) 0x0035, "Banyan Vines");

  /** AppleTalk EDDP: 0x0039 */
  public static final PppDllProtocol APPLETALK_EDDP =
      new PppDllProtocol((short) 0x0039, "AppleTalk EDDP");

  /** AppleTalk SmartBuffered: 0x003b */
  public static final PppDllProtocol APPLETALK_SMARTBUFFERED =
      new PppDllProtocol((short) 0x003b, "AppleTalk SmartBuffered");

  /** Multi-Link: 0x003d */
  public static final PppDllProtocol MULTI_LINK = new PppDllProtocol((short) 0x003d, "Multi-Link");

  /** NETBIOS Framing: 0x003f */
  public static final PppDllProtocol NETBIOS_FRAMING =
      new PppDllProtocol((short) 0x003f, "NETBIOS Framing");

  /** Cisco Systems: 0x0041 */
  public static final PppDllProtocol CISCO_SYSTEMS =
      new PppDllProtocol((short) 0x0041, "Cisco Systems");

  /** Ascom Timeplex: 0x0043 */
  public static final PppDllProtocol ASCOM_TIMEPLEX_0043 =
      new PppDllProtocol((short) 0x0043, "Ascom Timeplex");

  /** Fujitsu Link Backup and Load Balancing (LBLB): 0x0045 */
  public static final PppDllProtocol LBLB = new PppDllProtocol((short) 0x0045, "LBLB");

  /** DCA Remote Lan: 0x0047 */
  public static final PppDllProtocol DCA_REMOTE_LAN =
      new PppDllProtocol((short) 0x0047, "DCA Remote Lan");

  /** Serial Data Transport Protocol (PPP-SDTP): 0x0049 */
  public static final PppDllProtocol PPP_SDTP = new PppDllProtocol((short) 0x0049, "PPP-SDTP");

  /** SNA over 802.2: 0x004b */
  public static final PppDllProtocol SNA_OVER_802_2 =
      new PppDllProtocol((short) 0x004b, "SNA over 802.2");

  /** SNA: 0x004d */
  public static final PppDllProtocol SNA = new PppDllProtocol((short) 0x004d, "SNA");

  /** IPv6 Header Compression: 0x004f */
  public static final PppDllProtocol IPV6_HEADER_COMPRESSION =
      new PppDllProtocol((short) 0x004f, "IPv6 Header Compression");

  /** KNX Bridging Data: 0x0051 */
  public static final PppDllProtocol KNX_BRIDGING_DATA =
      new PppDllProtocol((short) 0x0051, "KNX Bridging Data");

  /** Encryption: 0x0053 */
  public static final PppDllProtocol ENCRYPTION = new PppDllProtocol((short) 0x0053, "Encryption");

  /** Individual Link Encryption: 0x0055 */
  public static final PppDllProtocol INDIVIDUAL_LINK_ENCRYPTION =
      new PppDllProtocol((short) 0x0055, "Individual Link Encryption");

  /** IPv6: 0x0057 */
  public static final PppDllProtocol IPV6 = new PppDllProtocol((short) 0x0057, "IPv6");

  /** PPP Muxing: 0x0059 */
  public static final PppDllProtocol PPP_MUXING = new PppDllProtocol((short) 0x0059, "PPP Muxing");

  /** Vendor-Specific Network Protocol (VSNP): 0x005b */
  public static final PppDllProtocol VSNP = new PppDllProtocol((short) 0x005b, "VSNP");

  /** TRILL Network Protocol (TNP): 0x005d */
  public static final PppDllProtocol TNP = new PppDllProtocol((short) 0x005d, "TNP");

  /** RTP IPHC Full Header: 0x0061 */
  public static final PppDllProtocol RTP_IPHC_FULL_HEADER =
      new PppDllProtocol((short) 0x0061, "RTP IPHC Full Header");

  /** RTP IPHC Compressed TCP: 0x0063 */
  public static final PppDllProtocol RTP_IPHC_COMPRESSED_TCP =
      new PppDllProtocol((short) 0x0063, "RTP IPHC Compressed TCP");

  /** RTP IPHC Compressed Non TCP: 0x0065 */
  public static final PppDllProtocol RTP_IPHC_COMPRESSED_NON_TCP =
      new PppDllProtocol((short) 0x0065, "RTP IPHC Compressed Non TCP");

  /** RTP IPHC Compressed UDP 8: 0x0067 */
  public static final PppDllProtocol RTP_IPHC_COMPRESSED_UDP_8 =
      new PppDllProtocol((short) 0x0067, "RTP IPHC Compressed UDP 8");

  /** RTP IPHC Compressed RTP 8: 0x0069 */
  public static final PppDllProtocol RTP_IPHC_COMPRESSED_RTP_8 =
      new PppDllProtocol((short) 0x0069, "RTP IPHC Compressed RTP 8");

  /** Stampede Bridging: 0x006f */
  public static final PppDllProtocol STAMPEDE_BRIDGING =
      new PppDllProtocol((short) 0x006f, "Stampede Bridging");

  /** MP+ Protocol: 0x0073 */
  public static final PppDllProtocol MP_PLUS_PROTOCOL =
      new PppDllProtocol((short) 0x0073, "MP+ Protocol");

  /** NTCITS IPI: 0x00c1 */
  public static final PppDllProtocol NTCITS_IPI = new PppDllProtocol((short) 0x00c1, "NTCITS IPI");

  /** Single link compression in multilink: 0x00fb */
  public static final PppDllProtocol SINGLE_LINK_COMPRESSION_IN_MULTILINK =
      new PppDllProtocol((short) 0x00fb, "Single link compression in multilink");

  /** Compressed datagram: 0x00fd */
  public static final PppDllProtocol COMPRESSED_DATAGRAM =
      new PppDllProtocol((short) 0x00fd, "Compressed datagram");

  /** 802.1d Hello Packets: 0x0201 */
  public static final PppDllProtocol IEEE_802_1D_HELLO_PACKETS =
      new PppDllProtocol((short) 0x0201, "802.1d Hello Packets");

  /** IBM Source Routing BPDU: 0x0203 */
  public static final PppDllProtocol IBM_SOURCE_ROUTING_BPDU =
      new PppDllProtocol((short) 0x0203, "IBM Source Routing BPDU");

  /** DEC LANBridge100 Spanning Tree: 0x0205 */
  public static final PppDllProtocol DEC_LANBRIDGE100_SPANNING_TREE =
      new PppDllProtocol((short) 0x0205, "DEC LANBridge100 Spanning Tree");

  /** Cisco Discovery Protocol (CDP): 0x0207 */
  public static final PppDllProtocol CDP = new PppDllProtocol((short) 0x0207, "CDP");

  /** Netcs Twin Routing: 0x0209 */
  public static final PppDllProtocol NETCS_TWIN_ROUTING_0209 =
      new PppDllProtocol((short) 0x0209, "Netcs Twin Routing");

  /** Scheduled Transfer Protocol (STP): 0x020b */
  public static final PppDllProtocol STP = new PppDllProtocol((short) 0x020b, "STP");

  /** Extreme Discovery Protocol (EDP): 0x020d */
  public static final PppDllProtocol EDP = new PppDllProtocol((short) 0x020d, "EDP");

  /** Optical Supervisory Channel Protocol (OSCP): 0x0211 */
  public static final PppDllProtocol OSCP_0211 = new PppDllProtocol((short) 0x0211, "OSCP");

  /** Optical Supervisory Channel Protocol (OSCP): 0x0213 */
  public static final PppDllProtocol OSCP_0213 = new PppDllProtocol((short) 0x0213, "OSCP");

  /** Luxcom: 0x0231 */
  public static final PppDllProtocol LUXCOM = new PppDllProtocol((short) 0x0231, "Luxcom");

  /** Sigma Network Systems: 0x0233 */
  public static final PppDllProtocol SIGMA_NETWORK_SYSTEMS =
      new PppDllProtocol((short) 0x0233, "Sigma Network Systems");

  /** Apple Client Server Protocol: 0x0235 */
  public static final PppDllProtocol APPLE_CLIENT_SERVER_PROTOCOL =
      new PppDllProtocol((short) 0x0235, "Apple Client Server Protocol");

  /** MPLS Unicast: 0x0281 */
  public static final PppDllProtocol MPLS_UNICAST =
      new PppDllProtocol((short) 0x0281, "MPLS Unicast");

  /** MPLS Multicast: 0x0283 */
  public static final PppDllProtocol MPLS_MULTICAST =
      new PppDllProtocol((short) 0x0283, "MPLS Multicast");

  /** IEEE p1284.4 standard - data packets: 0x0285 */
  public static final PppDllProtocol IEEE_P1284_4_STANDARD_DATA_PACKETS =
      new PppDllProtocol((short) 0x0285, "IEEE p1284.4 standard - data packets");

  /** ETSI TETRA Network Protocol Type 1: 0x0287 */
  public static final PppDllProtocol ETSI_TETRA_NETWORK_PROTOCOL_TYPE_1 =
      new PppDllProtocol((short) 0x0287, "ETSI TETRA Network Protocol Type 1");

  /** Multichannel Flow Treatment Protocol: 0x0289 */
  public static final PppDllProtocol MULTICHANNEL_FLOW_TREATMENT_PROTOCOL_0289 =
      new PppDllProtocol((short) 0x0289, "Multichannel Flow Treatment Protocol");

  /** RTP IPHC Compressed TCP No Delta: 0x2063 */
  public static final PppDllProtocol RTP_IPHC_COMPRESSED_TCP_NO_DELTA =
      new PppDllProtocol((short) 0x2063, "RTP IPHC Compressed TCP No Delta");

  /** RTP IPHC Context State: 0x2065 */
  public static final PppDllProtocol RTP_IPHC_CONTEXT_STATE =
      new PppDllProtocol((short) 0x2065, "RTP IPHC Context State");

  /** RTP IPHC Compressed UDP 16: 0x2067 */
  public static final PppDllProtocol RTP_IPHC_COMPRESSED_UDP_16 =
      new PppDllProtocol((short) 0x2067, "RTP IPHC Compressed UDP 16");

  /** RTP IPHC Compressed RTP 16: 0x2069 */
  public static final PppDllProtocol RTP_IPHC_COMPRESSED_RTP_16 =
      new PppDllProtocol((short) 0x2069, "RTP IPHC Compressed RTP 16");

  /** Cray Communications Control Protocol: 0x4001 */
  public static final PppDllProtocol CRAY_COMMUNICATIONS_CONTROL_PROTOCOL =
      new PppDllProtocol((short) 0x4001, "Cray Communications Control Protocol");

  /** CDPD Mobile Network Registration Protocol: 0x4003 */
  public static final PppDllProtocol CDPD_MOBILE_NETWORK_REGISTRATION_PROTOCOL =
      new PppDllProtocol((short) 0x4003, "CDPD Mobile Network Registration Protocol");

  /** Expand accelerator protocol: 0x4005 */
  public static final PppDllProtocol EXPAND_ACCELERATOR_PROTOCOL =
      new PppDllProtocol((short) 0x4005, "Expand accelerator protocol");

  /** ODSICP NCP: 0x4007 */
  public static final PppDllProtocol ODSICP_NCP = new PppDllProtocol((short) 0x4007, "ODSICP NCP");

  /** DOCSIS DLL: 0x4009 */
  public static final PppDllProtocol DOCSIS_DLL = new PppDllProtocol((short) 0x4009, "DOCSIS DLL");

  /** Cetacean Network Detection Protocol: 0x400B */
  public static final PppDllProtocol CETACEAN_NETWORK_DETECTION_PROTOCOL =
      new PppDllProtocol((short) 0x400B, "Cetacean Network Detection Protocol");

  /** Stacker LZS: 0x4021 */
  public static final PppDllProtocol STACKER_LZS =
      new PppDllProtocol((short) 0x4021, "Stacker LZS");

  /** RefTek Protocol: 0x4023 */
  public static final PppDllProtocol REFTEK_PROTOCOL =
      new PppDllProtocol((short) 0x4023, "RefTek Protocol");

  /** Fibre Channel: 0x4025 */
  public static final PppDllProtocol FIBRE_CHANNEL =
      new PppDllProtocol((short) 0x4025, "Fibre Channel");

  /** EMIT Protocols: 0x4027 */
  public static final PppDllProtocol EMIT_PROTOCOLS =
      new PppDllProtocol((short) 0x4027, "EMIT Protocols");

  /** Vendor-Specific Protocol (VSP): 0x405b */
  public static final PppDllProtocol VSP = new PppDllProtocol((short) 0x405b, "VSP");

  /** TRILL Link State Protocol (TLSP): 0x405d */
  public static final PppDllProtocol TLSP = new PppDllProtocol((short) 0x405d, "TLSP");

  /** Internet Protocol Control Protocol: 0x8021 */
  public static final PppDllProtocol INTERNET_PROTOCOL_CONTROL_PROTOCOL =
      new PppDllProtocol((short) 0x8021, "Internet Protocol Control Protocol");

  /** OSI Network Layer Control Protocol: 0x8023 */
  public static final PppDllProtocol OSI_NETWORK_LAYER_CONTROL_PROTOCOL =
      new PppDllProtocol((short) 0x8023, "OSI Network Layer Control Protocol");

  /** Xerox NS IDP Control Protocol: 0x8025 */
  public static final PppDllProtocol XEROX_NS_IDP_CONTROL_PROTOCOL =
      new PppDllProtocol((short) 0x8025, "Xerox NS IDP Control Protocol");

  /** DECnet Phase IV Control Protocol: 0x8027 */
  public static final PppDllProtocol DECNET_PHASE_IV_CONTROL_PROTOCOL =
      new PppDllProtocol((short) 0x8027, "DECnet Phase IV Control Protocol");

  /** Appletalk Control Protocol: 0x8029 */
  public static final PppDllProtocol APPLETALK_CONTROL_PROTOCOL =
      new PppDllProtocol((short) 0x8029, "Appletalk Control Protocol");

  /** Novell IPX Control Protocol: 0x802b */
  public static final PppDllProtocol NOVELL_IPX_CONTROL_PROTOCOL =
      new PppDllProtocol((short) 0x802b, "Novell IPX Control Protocol");

  /** Bridging NCP: 0x8031 */
  public static final PppDllProtocol BRIDGING_NCP =
      new PppDllProtocol((short) 0x8031, "Bridging NCP");

  /** Stream Protocol Control Protocol: 0x8033 */
  public static final PppDllProtocol STREAM_PROTOCOL_CONTROL_PROTOCOL =
      new PppDllProtocol((short) 0x8033, "Stream Protocol Control Protocol");

  /** Banyan Vines Control Protocol: 0x8035 */
  public static final PppDllProtocol BANYAN_VINES_CONTROL_PROTOCOL =
      new PppDllProtocol((short) 0x8035, "Banyan Vines Control Protocol");

  /** Multi-Link Control Protocol: 0x803d */
  public static final PppDllProtocol MULTI_LINK_CONTROL_PROTOCOL =
      new PppDllProtocol((short) 0x803d, "Multi-Link Control Protocol");

  /** NETBIOS Framing Control Protocol: 0x803f */
  public static final PppDllProtocol NETBIOS_FRAMING_CONTROL_PROTOCOL =
      new PppDllProtocol((short) 0x803f, "NETBIOS Framing Control Protocol");

  /** Cisco Systems Control Protocol: 0x8041 */
  public static final PppDllProtocol CISCO_SYSTEMS_CONTROL_PROTOCOL =
      new PppDllProtocol((short) 0x8041, "Cisco Systems Control Protocol");

  /** Ascom Timeplex: 0x8043 */
  public static final PppDllProtocol ASCOM_TIMEPLEX_8043 =
      new PppDllProtocol((short) 0x8043, "Ascom Timeplex");

  /** Fujitsu LBLB Control Protocol: 0x8045 */
  public static final PppDllProtocol FUJITSU_LBLB_CONTROL_PROTOCOL =
      new PppDllProtocol((short) 0x8045, "Fujitsu LBLB Control Protocol");

  /** DCA Remote Lan Network Control Protocol (RLNCP): 0x8047 */
  public static final PppDllProtocol RLNCP = new PppDllProtocol((short) 0x8047, "RLNCP");

  /** Serial Data Control Protocol (PPP-SDCP): 0x8049 */
  public static final PppDllProtocol PPP_SDCP = new PppDllProtocol((short) 0x8049, "PPP-SDCP");

  /** SNA over 802.2 Control Protocol: 0x804b */
  public static final PppDllProtocol SNA_OVER_802_2_CONTROL_PROTOCOL =
      new PppDllProtocol((short) 0x804b, "SNA over 802.2 Control Protocol");

  /** SNA Control Protocol: 0x804d */
  public static final PppDllProtocol SNA_CONTROL_PROTOCOL =
      new PppDllProtocol((short) 0x804d, "SNA Control Protocol");

  /** IP6 Header Compression Control Protocol: 0x804f */
  public static final PppDllProtocol IP6_HEADER_COMPRESSION_CONTROL_PROTOCOL =
      new PppDllProtocol((short) 0x804f, "IP6 Header Compression Control Protocol");

  /** KNX Bridging Control Protocol: 0x8051 */
  public static final PppDllProtocol KNX_BRIDGING_CONTROL_PROTOCOL =
      new PppDllProtocol((short) 0x8051, "KNX Bridging Control Protocol");

  /** Encryption Control Protocol: 0x8053 */
  public static final PppDllProtocol ENCRYPTION_CONTROL_PROTOCOL =
      new PppDllProtocol((short) 0x8053, "Encryption Control Protocol");

  /** Individual Link Encryption Control Protocol: 0x8055 */
  public static final PppDllProtocol INDIVIDUAL_LINK_ENCRYPTION_CONTROL_PROTOCOL =
      new PppDllProtocol((short) 0x8055, "Individual Link Encryption Control Protocol");

  /** IPv6 Control Protocol: 0x8057 */
  public static final PppDllProtocol IPV6_CONTROL_PROTOCOL =
      new PppDllProtocol((short) 0x8057, "IPv6 Control Protocol");

  /** PPP Muxing Control Protocol: 0x8059 */
  public static final PppDllProtocol PPP_MUXING_CONTROL_PROTOCOL =
      new PppDllProtocol((short) 0x8059, "PPP Muxing Control Protocol");

  /** Vendor-Specific Network Control Protocol (VSNCP): 0x805b */
  public static final PppDllProtocol VSNCP = new PppDllProtocol((short) 0x805b, "VSNCP");

  /** TRILL Network Control Protocol (TNCP): 0x805d */
  public static final PppDllProtocol TNCP = new PppDllProtocol((short) 0x805d, "TNCP");

  /** Stampede Bridging Control Protocol: 0x806f */
  public static final PppDllProtocol STAMPEDE_BRIDGING_CONTROL_PROTOCOL =
      new PppDllProtocol((short) 0x806f, "Stampede Bridging Control Protocol");

  /** MP+ Control Protocol: 0x8073 */
  public static final PppDllProtocol MP_PLUS_CONTROL_PROTOCOL =
      new PppDllProtocol((short) 0x8073, "MP+ Control Protocol");

  /** NTCITS IPI Control Protocol: 0x80c1 */
  public static final PppDllProtocol NTCITS_IPI_CONTROL_PROTOCOL =
      new PppDllProtocol((short) 0x80c1, "NTCITS IPI Control Protocol");

  /** single link compression in multilink control: 0x80fb */
  public static final PppDllProtocol SINGLE_LINK_COMPRESSION_IN_MULTILINK_CONTROL =
      new PppDllProtocol((short) 0x80fb, "single link compression in multilink control");

  /** Compression Control Protocol: 0x80fd */
  public static final PppDllProtocol COMPRESSION_CONTROL_PROTOCOL =
      new PppDllProtocol((short) 0x80fd, "Compression Control Protocol");

  /** Cisco Discovery Protocol Control: 0x8207 */
  public static final PppDllProtocol CISCO_DISCOVERY_PROTOCOL_CONTROL =
      new PppDllProtocol((short) 0x8207, "Cisco Discovery Protocol Control");

  /** Netcs Twin Routing: 0x8209 */
  public static final PppDllProtocol NETCS_TWIN_ROUTING_8209 =
      new PppDllProtocol((short) 0x8209, "Netcs Twin Routing");

  /** STP - Control Protocol: 0x820b */
  public static final PppDllProtocol STP_CONTROL_PROTOCOL =
      new PppDllProtocol((short) 0x820b, "STP - Control Protocol");

  /** Extreme Discovery Protocol Control Protocol (EDPCP): 0x820d */
  public static final PppDllProtocol EDPCP = new PppDllProtocol((short) 0x820d, "EDPCP");

  /** Apple Client Server Protocol Control: 0x8235 */
  public static final PppDllProtocol APPLE_CLIENT_SERVER_PROTOCOL_CONTROL =
      new PppDllProtocol((short) 0x8235, "Apple Client Server Protocol Control");

  /** MPLSCP: 0x8281 */
  public static final PppDllProtocol MPLSCP = new PppDllProtocol((short) 0x8281, "MPLSCP");

  /** IEEE p1284.4 standard - Protocol Control: 0x8285 */
  public static final PppDllProtocol IEEE_P1284_4_STANDARD_PROTOCOL_CONTROL =
      new PppDllProtocol((short) 0x8285, "IEEE p1284.4 standard - Protocol Control");

  /** ETSI TETRA TNP1 Control Protocol: 0x8287 */
  public static final PppDllProtocol ETSI_TETRA_TNP1_CONTROL_PROTOCOL =
      new PppDllProtocol((short) 0x8287, "ETSI TETRA TNP1 Control Protocol");

  /** Multichannel Flow Treatment Protocol: 0x8289 */
  public static final PppDllProtocol MULTICHANNEL_FLOW_TREATMENT_PROTOCOL_8289 =
      new PppDllProtocol((short) 0x8289, "Multichannel Flow Treatment Protocol");

  /** Link Control Protocol: 0xc021 */
  public static final PppDllProtocol LINK_CONTROL_PROTOCOL =
      new PppDllProtocol((short) 0xc021, "Link Control Protocol");

  /** Password Authentication Protocol: 0xc023 */
  public static final PppDllProtocol PASSWORD_AUTHENTICATION_PROTOCOL =
      new PppDllProtocol((short) 0xc023, "Password Authentication Protocol");

  /** Link Quality Report: 0xc025 */
  public static final PppDllProtocol LINK_QUALITY_REPORT =
      new PppDllProtocol((short) 0xc025, "Link Quality Report");

  /** Shiva Password Authentication Protocol: 0xc027 */
  public static final PppDllProtocol SHIVA_PASSWORD_AUTHENTICATION_PROTOCOL =
      new PppDllProtocol((short) 0xc027, "Shiva Password Authentication Protocol");

  /** CallBack Control Protocol (CBCP): 0xc029 */
  public static final PppDllProtocol CBCP = new PppDllProtocol((short) 0xc029, "CBCP");

  /** BACP Bandwidth Allocation Control Protocol: 0xc02b */
  public static final PppDllProtocol BACP_BANDWIDTH_ALLOCATION_CONTROL_PROTOCOL =
      new PppDllProtocol((short) 0xc02b, "BACP Bandwidth Allocation Control Protocol");

  /** BAP: 0xc02d */
  public static final PppDllProtocol BAP = new PppDllProtocol((short) 0xc02d, "BAP");

  /** Vendor-Specific Authentication Protocol (VSAP): 0xc05b */
  public static final PppDllProtocol VSAP = new PppDllProtocol((short) 0xc05b, "VSAP");

  /** Container Control Protocol: 0xc081 */
  public static final PppDllProtocol CONTAINER_CONTROL_PROTOCOL =
      new PppDllProtocol((short) 0xc081, "Container Control Protocol");

  /** Challenge Handshake Authentication Protocol: 0xc223 */
  public static final PppDllProtocol CHALLENGE_HANDSHAKE_AUTHENTICATION_PROTOCOL =
      new PppDllProtocol((short) 0xc223, "Challenge Handshake Authentication Protocol");

  /** RSA Authentication Protocol: 0xc225 */
  public static final PppDllProtocol RSA_AUTHENTICATION_PROTOCOL =
      new PppDllProtocol((short) 0xc225, "RSA Authentication Protocol");

  /** Extensible Authentication Protocol: 0xc227 */
  public static final PppDllProtocol EXTENSIBLE_AUTHENTICATION_PROTOCOL =
      new PppDllProtocol((short) 0xc227, "Extensible Authentication Protocol");

  /** Mitsubishi Security Info Exch Ptcl (SIEP): 0xc229 */
  public static final PppDllProtocol SIEP = new PppDllProtocol((short) 0xc229, "SIEP");

  /** Stampede Bridging Authorization Protocol: 0xc26f */
  public static final PppDllProtocol STAMPEDE_BRIDGING_AUTHORIZATION_PROTOCOL =
      new PppDllProtocol((short) 0xc26f, "Stampede Bridging Authorization Protocol");

  /** Proprietary Authentication Protocol: 0xc281 */
  public static final PppDllProtocol PROPRIETARY_AUTHENTICATION_PROTOCOL_C281 =
      new PppDllProtocol((short) 0xc281, "Proprietary Authentication Protocol");

  /** Proprietary Authentication Protocol: 0xc283 */
  public static final PppDllProtocol PROPRIETARY_AUTHENTICATION_PROTOCOL_C283 =
      new PppDllProtocol((short) 0xc283, "Proprietary Authentication Protocol");

  /** Proprietary Node ID Authentication Protocol: 0xc481 */
  public static final PppDllProtocol PROPRIETARY_NODE_ID_AUTHENTICATION_PROTOCOL =
      new PppDllProtocol((short) 0xc481, "Proprietary Node ID Authentication Protocol");

  private static final Map<Short, PppDllProtocol> registry = new HashMap<Short, PppDllProtocol>();

  static {
    registry.put(PADDING_PROTOCOL.value(), PADDING_PROTOCOL);
    registry.put(ROHC_SMALL_CID.value(), ROHC_SMALL_CID);
    registry.put(ROHC_LARGE_CID.value(), ROHC_LARGE_CID);
    registry.put(IPV4.value(), IPV4);
    registry.put(OSI_NETWORK_LAYER.value(), OSI_NETWORK_LAYER);
    registry.put(XEROX_NS_IDP.value(), XEROX_NS_IDP);
    registry.put(DECNET_PHASE_IV.value(), DECNET_PHASE_IV);
    registry.put(APPLETALK.value(), APPLETALK);
    registry.put(NOVELL_IPX.value(), NOVELL_IPX);
    registry.put(VAN_JACOBSON_COMPRESSED_TCP_IP.value(), VAN_JACOBSON_COMPRESSED_TCP_IP);
    registry.put(VAN_JACOBSON_UNCOMPRESSED_TCP_IP.value(), VAN_JACOBSON_UNCOMPRESSED_TCP_IP);
    registry.put(BRIDGING_PDU.value(), BRIDGING_PDU);
    registry.put(ST_II.value(), ST_II);
    registry.put(BANYAN_VINES.value(), BANYAN_VINES);
    registry.put(APPLETALK_EDDP.value(), APPLETALK_EDDP);
    registry.put(APPLETALK_SMARTBUFFERED.value(), APPLETALK_SMARTBUFFERED);
    registry.put(MULTI_LINK.value(), MULTI_LINK);
    registry.put(NETBIOS_FRAMING.value(), NETBIOS_FRAMING);
    registry.put(CISCO_SYSTEMS.value(), CISCO_SYSTEMS);
    registry.put(ASCOM_TIMEPLEX_0043.value(), ASCOM_TIMEPLEX_0043);
    registry.put(LBLB.value(), LBLB);
    registry.put(DCA_REMOTE_LAN.value(), DCA_REMOTE_LAN);
    registry.put(PPP_SDTP.value(), PPP_SDTP);
    registry.put(SNA_OVER_802_2.value(), SNA_OVER_802_2);
    registry.put(SNA.value(), SNA);
    registry.put(IPV6_HEADER_COMPRESSION.value(), IPV6_HEADER_COMPRESSION);
    registry.put(KNX_BRIDGING_DATA.value(), KNX_BRIDGING_DATA);
    registry.put(ENCRYPTION.value(), ENCRYPTION);
    registry.put(INDIVIDUAL_LINK_ENCRYPTION.value(), INDIVIDUAL_LINK_ENCRYPTION);
    registry.put(IPV6.value(), IPV6);
    registry.put(PPP_MUXING.value(), PPP_MUXING);
    registry.put(VSNP.value(), VSNP);
    registry.put(TNP.value(), TNP);
    registry.put(RTP_IPHC_FULL_HEADER.value(), RTP_IPHC_FULL_HEADER);
    registry.put(RTP_IPHC_COMPRESSED_TCP.value(), RTP_IPHC_COMPRESSED_TCP);
    registry.put(RTP_IPHC_COMPRESSED_NON_TCP.value(), RTP_IPHC_COMPRESSED_NON_TCP);
    registry.put(RTP_IPHC_COMPRESSED_UDP_8.value(), RTP_IPHC_COMPRESSED_UDP_8);
    registry.put(RTP_IPHC_COMPRESSED_RTP_8.value(), RTP_IPHC_COMPRESSED_RTP_8);
    registry.put(STAMPEDE_BRIDGING.value(), STAMPEDE_BRIDGING);
    registry.put(MP_PLUS_PROTOCOL.value(), MP_PLUS_PROTOCOL);
    registry.put(NTCITS_IPI.value(), NTCITS_IPI);
    registry.put(
        SINGLE_LINK_COMPRESSION_IN_MULTILINK.value(), SINGLE_LINK_COMPRESSION_IN_MULTILINK);
    registry.put(COMPRESSED_DATAGRAM.value(), COMPRESSED_DATAGRAM);
    registry.put(IEEE_802_1D_HELLO_PACKETS.value(), IEEE_802_1D_HELLO_PACKETS);
    registry.put(IBM_SOURCE_ROUTING_BPDU.value(), IBM_SOURCE_ROUTING_BPDU);
    registry.put(DEC_LANBRIDGE100_SPANNING_TREE.value(), DEC_LANBRIDGE100_SPANNING_TREE);
    registry.put(CDP.value(), CDP);
    registry.put(NETCS_TWIN_ROUTING_0209.value(), NETCS_TWIN_ROUTING_0209);
    registry.put(STP.value(), STP);
    registry.put(EDP.value(), EDP);
    registry.put(OSCP_0211.value(), OSCP_0211);
    registry.put(OSCP_0213.value(), OSCP_0213);
    registry.put(LUXCOM.value(), LUXCOM);
    registry.put(SIGMA_NETWORK_SYSTEMS.value(), SIGMA_NETWORK_SYSTEMS);
    registry.put(APPLE_CLIENT_SERVER_PROTOCOL.value(), APPLE_CLIENT_SERVER_PROTOCOL);
    registry.put(MPLS_UNICAST.value(), MPLS_UNICAST);
    registry.put(MPLS_MULTICAST.value(), MPLS_MULTICAST);
    registry.put(IEEE_P1284_4_STANDARD_DATA_PACKETS.value(), IEEE_P1284_4_STANDARD_DATA_PACKETS);
    registry.put(ETSI_TETRA_NETWORK_PROTOCOL_TYPE_1.value(), ETSI_TETRA_NETWORK_PROTOCOL_TYPE_1);
    registry.put(
        MULTICHANNEL_FLOW_TREATMENT_PROTOCOL_0289.value(),
        MULTICHANNEL_FLOW_TREATMENT_PROTOCOL_0289);
    registry.put(RTP_IPHC_COMPRESSED_TCP_NO_DELTA.value(), RTP_IPHC_COMPRESSED_TCP_NO_DELTA);
    registry.put(RTP_IPHC_CONTEXT_STATE.value(), RTP_IPHC_CONTEXT_STATE);
    registry.put(RTP_IPHC_COMPRESSED_UDP_16.value(), RTP_IPHC_COMPRESSED_UDP_16);
    registry.put(RTP_IPHC_COMPRESSED_RTP_16.value(), RTP_IPHC_COMPRESSED_RTP_16);
    registry.put(
        CRAY_COMMUNICATIONS_CONTROL_PROTOCOL.value(), CRAY_COMMUNICATIONS_CONTROL_PROTOCOL);
    registry.put(
        CDPD_MOBILE_NETWORK_REGISTRATION_PROTOCOL.value(),
        CDPD_MOBILE_NETWORK_REGISTRATION_PROTOCOL);
    registry.put(EXPAND_ACCELERATOR_PROTOCOL.value(), EXPAND_ACCELERATOR_PROTOCOL);
    registry.put(ODSICP_NCP.value(), ODSICP_NCP);
    registry.put(DOCSIS_DLL.value(), DOCSIS_DLL);
    registry.put(CETACEAN_NETWORK_DETECTION_PROTOCOL.value(), CETACEAN_NETWORK_DETECTION_PROTOCOL);
    registry.put(STACKER_LZS.value(), STACKER_LZS);
    registry.put(REFTEK_PROTOCOL.value(), REFTEK_PROTOCOL);
    registry.put(FIBRE_CHANNEL.value(), FIBRE_CHANNEL);
    registry.put(EMIT_PROTOCOLS.value(), EMIT_PROTOCOLS);
    registry.put(VSP.value(), VSP);
    registry.put(TLSP.value(), TLSP);
    registry.put(INTERNET_PROTOCOL_CONTROL_PROTOCOL.value(), INTERNET_PROTOCOL_CONTROL_PROTOCOL);
    registry.put(OSI_NETWORK_LAYER_CONTROL_PROTOCOL.value(), OSI_NETWORK_LAYER_CONTROL_PROTOCOL);
    registry.put(XEROX_NS_IDP_CONTROL_PROTOCOL.value(), XEROX_NS_IDP_CONTROL_PROTOCOL);
    registry.put(DECNET_PHASE_IV_CONTROL_PROTOCOL.value(), DECNET_PHASE_IV_CONTROL_PROTOCOL);
    registry.put(APPLETALK_CONTROL_PROTOCOL.value(), APPLETALK_CONTROL_PROTOCOL);
    registry.put(NOVELL_IPX_CONTROL_PROTOCOL.value(), NOVELL_IPX_CONTROL_PROTOCOL);
    registry.put(BRIDGING_NCP.value(), BRIDGING_NCP);
    registry.put(STREAM_PROTOCOL_CONTROL_PROTOCOL.value(), STREAM_PROTOCOL_CONTROL_PROTOCOL);
    registry.put(BANYAN_VINES_CONTROL_PROTOCOL.value(), BANYAN_VINES_CONTROL_PROTOCOL);
    registry.put(MULTI_LINK_CONTROL_PROTOCOL.value(), MULTI_LINK_CONTROL_PROTOCOL);
    registry.put(NETBIOS_FRAMING_CONTROL_PROTOCOL.value(), NETBIOS_FRAMING_CONTROL_PROTOCOL);
    registry.put(CISCO_SYSTEMS_CONTROL_PROTOCOL.value(), CISCO_SYSTEMS_CONTROL_PROTOCOL);
    registry.put(ASCOM_TIMEPLEX_8043.value(), ASCOM_TIMEPLEX_8043);
    registry.put(FUJITSU_LBLB_CONTROL_PROTOCOL.value(), FUJITSU_LBLB_CONTROL_PROTOCOL);
    registry.put(RLNCP.value(), RLNCP);
    registry.put(PPP_SDCP.value(), PPP_SDCP);
    registry.put(SNA_OVER_802_2_CONTROL_PROTOCOL.value(), SNA_OVER_802_2_CONTROL_PROTOCOL);
    registry.put(SNA_CONTROL_PROTOCOL.value(), SNA_CONTROL_PROTOCOL);
    registry.put(
        IP6_HEADER_COMPRESSION_CONTROL_PROTOCOL.value(), IP6_HEADER_COMPRESSION_CONTROL_PROTOCOL);
    registry.put(KNX_BRIDGING_CONTROL_PROTOCOL.value(), KNX_BRIDGING_CONTROL_PROTOCOL);
    registry.put(ENCRYPTION_CONTROL_PROTOCOL.value(), ENCRYPTION_CONTROL_PROTOCOL);
    registry.put(
        INDIVIDUAL_LINK_ENCRYPTION_CONTROL_PROTOCOL.value(),
        INDIVIDUAL_LINK_ENCRYPTION_CONTROL_PROTOCOL);
    registry.put(IPV6_CONTROL_PROTOCOL.value(), IPV6_CONTROL_PROTOCOL);
    registry.put(PPP_MUXING_CONTROL_PROTOCOL.value(), PPP_MUXING_CONTROL_PROTOCOL);
    registry.put(VSNCP.value(), VSNCP);
    registry.put(TNCP.value(), TNCP);
    registry.put(STAMPEDE_BRIDGING_CONTROL_PROTOCOL.value(), STAMPEDE_BRIDGING_CONTROL_PROTOCOL);
    registry.put(MP_PLUS_CONTROL_PROTOCOL.value(), MP_PLUS_CONTROL_PROTOCOL);
    registry.put(NTCITS_IPI_CONTROL_PROTOCOL.value(), NTCITS_IPI_CONTROL_PROTOCOL);
    registry.put(
        SINGLE_LINK_COMPRESSION_IN_MULTILINK_CONTROL.value(),
        SINGLE_LINK_COMPRESSION_IN_MULTILINK_CONTROL);
    registry.put(COMPRESSION_CONTROL_PROTOCOL.value(), COMPRESSION_CONTROL_PROTOCOL);
    registry.put(CISCO_DISCOVERY_PROTOCOL_CONTROL.value(), CISCO_DISCOVERY_PROTOCOL_CONTROL);
    registry.put(NETCS_TWIN_ROUTING_8209.value(), NETCS_TWIN_ROUTING_8209);
    registry.put(STP_CONTROL_PROTOCOL.value(), STP_CONTROL_PROTOCOL);
    registry.put(EDPCP.value(), EDPCP);
    registry.put(
        APPLE_CLIENT_SERVER_PROTOCOL_CONTROL.value(), APPLE_CLIENT_SERVER_PROTOCOL_CONTROL);
    registry.put(MPLSCP.value(), MPLSCP);
    registry.put(
        IEEE_P1284_4_STANDARD_PROTOCOL_CONTROL.value(), IEEE_P1284_4_STANDARD_PROTOCOL_CONTROL);
    registry.put(ETSI_TETRA_TNP1_CONTROL_PROTOCOL.value(), ETSI_TETRA_TNP1_CONTROL_PROTOCOL);
    registry.put(
        MULTICHANNEL_FLOW_TREATMENT_PROTOCOL_8289.value(),
        MULTICHANNEL_FLOW_TREATMENT_PROTOCOL_8289);
    registry.put(LINK_CONTROL_PROTOCOL.value(), LINK_CONTROL_PROTOCOL);
    registry.put(PASSWORD_AUTHENTICATION_PROTOCOL.value(), PASSWORD_AUTHENTICATION_PROTOCOL);
    registry.put(LINK_QUALITY_REPORT.value(), LINK_QUALITY_REPORT);
    registry.put(
        SHIVA_PASSWORD_AUTHENTICATION_PROTOCOL.value(), SHIVA_PASSWORD_AUTHENTICATION_PROTOCOL);
    registry.put(CBCP.value(), CBCP);
    registry.put(
        BACP_BANDWIDTH_ALLOCATION_CONTROL_PROTOCOL.value(),
        BACP_BANDWIDTH_ALLOCATION_CONTROL_PROTOCOL);
    registry.put(BAP.value(), BAP);
    registry.put(VSAP.value(), VSAP);
    registry.put(CONTAINER_CONTROL_PROTOCOL.value(), CONTAINER_CONTROL_PROTOCOL);
    registry.put(
        CHALLENGE_HANDSHAKE_AUTHENTICATION_PROTOCOL.value(),
        CHALLENGE_HANDSHAKE_AUTHENTICATION_PROTOCOL);
    registry.put(RSA_AUTHENTICATION_PROTOCOL.value(), RSA_AUTHENTICATION_PROTOCOL);
    registry.put(EXTENSIBLE_AUTHENTICATION_PROTOCOL.value(), EXTENSIBLE_AUTHENTICATION_PROTOCOL);
    registry.put(SIEP.value(), SIEP);
    registry.put(
        STAMPEDE_BRIDGING_AUTHORIZATION_PROTOCOL.value(), STAMPEDE_BRIDGING_AUTHORIZATION_PROTOCOL);
    registry.put(
        PROPRIETARY_AUTHENTICATION_PROTOCOL_C281.value(), PROPRIETARY_AUTHENTICATION_PROTOCOL_C281);
    registry.put(
        PROPRIETARY_AUTHENTICATION_PROTOCOL_C283.value(), PROPRIETARY_AUTHENTICATION_PROTOCOL_C283);
    registry.put(
        PROPRIETARY_NODE_ID_AUTHENTICATION_PROTOCOL.value(),
        PROPRIETARY_NODE_ID_AUTHENTICATION_PROTOCOL);
  }

  /**
   * @param value value
   * @param name name
   * @throws IllegalArgumentException if an invalid value is passed.
   */
  public PppDllProtocol(Short value, String name) throws IllegalArgumentException {
    super(value, name);
    if (((value & 0x0100) != 0)) {
      throw new IllegalArgumentException(
          value
              + " is invalid value. "
              + "Its least significant bit of the most significant octet must be 0.");
    }
    if (((value & 0x0001) == 0)) {
      throw new IllegalArgumentException(
          value
              + " is invalid value. "
              + "Its least significant bit of the least significant octet must be 1.");
    }
  }

  /**
   * @param value value
   * @return a PppDllProtocol object.
   * @throws IllegalArgumentException if an invalid value is passed.
   */
  public static PppDllProtocol getInstance(Short value) throws IllegalArgumentException {
    if (registry.containsKey(value)) {
      return registry.get(value);
    } else {
      return new PppDllProtocol(value, "unknown");
    }
  }

  /**
   * @param type type
   * @return a PppDllProtocol object.
   */
  public static PppDllProtocol register(PppDllProtocol type) {
    return registry.put(type.value(), type);
  }

  /** @return a string representation of this value. */
  @Override
  public String valueAsString() {
    return "0x" + ByteArrays.toHexString(value(), "");
  }

  @Override
  public int compareTo(PppDllProtocol o) {
    return value().compareTo(o.value());
  }
}
