/*_##########################################################################
  _##
  _##  Copyright (C) 2015  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet.namednumber;

import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Map;

import org.pcap4j.util.ByteArrays;

/**
 * http://www.iana.org/assignments/ppp-numbers/ppp-numbers.xhtml#ppp-numbers-2
 *
 * @author Kaito Yamada
 * @since pcap4j 1.3.1
 */
public final class PppDllProtocol extends NamedNumber<Short, PppDllProtocol> {

  /**
   *
   */
  private static final long serialVersionUID = -6344960553361779564L;

  /**
   *
   */
  public static final PppDllProtocol PADDING_PROTOCOL
    = new PppDllProtocol((short)0x0001, "Padding Protocol");

  /**
   *
   */
  public static final PppDllProtocol ROHC_SMALL_CID
    = new PppDllProtocol((short)0x0003, "ROHC small-CID");

  /**
   *
   */
  public static final PppDllProtocol ROHC_LARGE_CID
    = new PppDllProtocol((short)0x0005, "ROHC large-CID");

  /**
   *
   */
  public static final PppDllProtocol INTERNET_PROTOCOL_VERSION_4
    = new PppDllProtocol((short)0x0021, "Internet Protocol version 4");

  /**
   *
   */
  public static final PppDllProtocol OSI_NETWORK_LAYER
    = new PppDllProtocol((short)0x0023, "OSI Network Layer");

  /**
   *
   */
  public static final PppDllProtocol XEROX_NS_IDP
    = new PppDllProtocol((short)0x0025, "Xerox NS IDP");

  /**
   *
   */
  public static final PppDllProtocol DECNET_PHASE_IV
    = new PppDllProtocol((short)0x0027, "DECnet Phase IV");

  /**
   *
   */
  public static final PppDllProtocol APPLETALK
    = new PppDllProtocol((short)0x0029, "Appletalk");

  /**
   *
   */
  public static final PppDllProtocol NOVELL_IPX
    = new PppDllProtocol((short)0x002b, "Novell IPX");

  /**
   *
   */
  public static final PppDllProtocol VAN_JACOBSON_COMPRESSED_TCP_IP
    = new PppDllProtocol((short)0x002d, "Van Jacobson Compressed TCP/IP");

  /**
   *
   */
  public static final PppDllProtocol VAN_JACOBSON_UNCOMPRESSED_TCP_IP
    = new PppDllProtocol((short)0x002f, "Van Jacobson Uncompressed TCP/IP");

  /**
   *
   */
  public static final PppDllProtocol BRIDGING_PDU
    = new PppDllProtocol((short)0x0031, "Bridging PDU");

  /**
   *
   */
  public static final PppDllProtocol ST_II
    = new PppDllProtocol((short)0x0033, "Stream Protocol (ST-II)");

  /**
   *
   */
  public static final PppDllProtocol BANYAN_VINES
    = new PppDllProtocol((short)0x0035, "Banyan Vines");

  /**
   *
   */
  public static final PppDllProtocol APPLETALK_EDDP
    = new PppDllProtocol((short)0x0039, "AppleTalk EDDP");

  /**
   *
   */
  public static final PppDllProtocol APPLETALK_SMARTBUFFERED
    = new PppDllProtocol((short)0x003b, "AppleTalk SmartBuffered");

  /**
   *
   */
  public static final PppDllProtocol MULTI_LINK
    = new PppDllProtocol((short)0x003d, "Multi-Link");

  /**
   *
   */
  public static final PppDllProtocol NETBIOS_FRAMING
    = new PppDllProtocol((short)0x003f, "NETBIOS Framing");

  /**
   *
   */
  public static final PppDllProtocol CISCO_SYSTEMS
    = new PppDllProtocol((short)0x0041, "Cisco Systems");

  /**
   *
   */
  public static final PppDllProtocol ASCOM_TIMEPLEX_0043
    = new PppDllProtocol((short)0x0043, "Ascom Timeplex");

  /**
   *
   */
  public static final PppDllProtocol LBLB
    = new PppDllProtocol((short)0x0045, "Fujitsu Link Backup and Load Balancing (LBLB)");

  /**
   *
   */
  public static final PppDllProtocol DCA_REMOTE_LAN
    = new PppDllProtocol((short)0x0047, "DCA Remote Lan");

  /**
   *
   */
  public static final PppDllProtocol PPP_SDTP
    = new PppDllProtocol((short)0x0049, "Serial Data Transport Protocol (PPP-SDTP)");

  /**
   *
   */
  public static final PppDllProtocol SNA_OVER_802_2
    = new PppDllProtocol((short)0x004b, "SNA over 802.2");

  /**
   *
   */
  public static final PppDllProtocol SNA
    = new PppDllProtocol((short)0x004d, "SNA");

  /**
   *
   */
  public static final PppDllProtocol IPV6_HEADER_COMPRESSION
    = new PppDllProtocol((short)0x004f, "IPv6 Header Compression");

  /**
   *
   */
  public static final PppDllProtocol KNX_BRIDGING_DATA
    = new PppDllProtocol((short)0x0051, "KNX Bridging Data");

  /**
   *
   */
  public static final PppDllProtocol ENCRYPTION
    = new PppDllProtocol((short)0x0053, "Encryption");

  /**
   *
   */
  public static final PppDllProtocol INDIVIDUAL_LINK_ENCRYPTION
    = new PppDllProtocol((short)0x0055, "Individual Link Encryption");

  /**
   *
   */
  public static final PppDllProtocol INTERNET_PROTOCOL_VERSION_6
    = new PppDllProtocol((short)0x0057, "Internet Protocol version 6");

  /**
   *
   */
  public static final PppDllProtocol PPP_MUXING
    = new PppDllProtocol((short)0x0059, "PPP Muxing");

  /**
   *
   */
  public static final PppDllProtocol VSNP
    = new PppDllProtocol((short)0x005b, "Vendor-Specific Network Protocol (VSNP)");

  /**
   *
   */
  public static final PppDllProtocol TNP
    = new PppDllProtocol((short)0x005d, "TRILL Network Protocol (TNP)");

  /**
   *
   */
  public static final PppDllProtocol RTP_IPHC_FULL_HEADER
    = new PppDllProtocol((short)0x0061, "RTP IPHC Full Header");

  /**
   *
   */
  public static final PppDllProtocol RTP_IPHC_COMPRESSED_TCP
    = new PppDllProtocol((short)0x0063, "RTP IPHC Compressed TCP");

  /**
   *
   */
  public static final PppDllProtocol RTP_IPHC_COMPRESSED_NON_TCP
    = new PppDllProtocol((short)0x0065, "RTP IPHC Compressed Non TCP");

  /**
   *
   */
  public static final PppDllProtocol RTP_IPHC_COMPRESSED_UDP_8
    = new PppDllProtocol((short)0x0067, "RTP IPHC Compressed UDP 8");

  /**
   *
   */
  public static final PppDllProtocol RTP_IPHC_COMPRESSED_RTP_8
    = new PppDllProtocol((short)0x0069, "RTP IPHC Compressed RTP 8");

  /**
   *
   */
  public static final PppDllProtocol STAMPEDE_BRIDGING
    = new PppDllProtocol((short)0x006f, "Stampede Bridging");

  /**
   *
   */
  public static final PppDllProtocol MP_PLUS_PROTOCOL
    = new PppDllProtocol((short)0x0073, "MP+ Protocol");

  /**
   *
   */
  public static final PppDllProtocol NTCITS_IPI
    = new PppDllProtocol((short)0x00c1, "NTCITS IPI");

  /**
   *
   */
  public static final PppDllProtocol SINGLE_LINK_COMPRESSION_IN_MULTILINK
    = new PppDllProtocol((short)0x00fb, "Single link compression in multilink");

  /**
   *
   */
  public static final PppDllProtocol COMPRESSED_DATAGRAM
    = new PppDllProtocol((short)0x00fd, "Compressed datagram");

  /**
   *
   */
  public static final PppDllProtocol IEEE_802_1D_HELLO_PACKETS
    = new PppDllProtocol((short)0x0201, "802.1d Hello Packets");

  /**
   *
   */
  public static final PppDllProtocol IBM_SOURCE_ROUTING_BPDU
    = new PppDllProtocol((short)0x0203, "IBM Source Routing BPDU");

  /**
   *
   */
  public static final PppDllProtocol DEC_LANBRIDGE100_SPANNING_TREE
    = new PppDllProtocol((short)0x0205, "DEC LANBridge100 Spanning Tree");

  /**
   *
   */
  public static final PppDllProtocol CISCO_DISCOVERY_PROTOCOL
    = new PppDllProtocol((short)0x0207, "Cisco Discovery Protocol");

  /**
   *
   */
  public static final PppDllProtocol NETCS_TWIN_ROUTING_0209
    = new PppDllProtocol((short)0x0209, "Netcs Twin Routing");

  /**
   *
   */
  public static final PppDllProtocol STP
    = new PppDllProtocol((short)0x020b, "STP - Scheduled Transfer Protocol");

  /**
   *
   */
  public static final PppDllProtocol EDP
    = new PppDllProtocol((short)0x020d, "EDP - Extreme Discovery Protocol");

  /**
   *
   */
  public static final PppDllProtocol OSCP_0211
    = new PppDllProtocol((short)0x0211, "Optical Supervisory Channel Protocol (OSCP)");

  /**
   *
   */
  public static final PppDllProtocol OSCP_0213
    = new PppDllProtocol((short)0x0213, "Optical Supervisory Channel Protocol (OSCP)");

  /**
   *
   */
  public static final PppDllProtocol LUXCOM
    = new PppDllProtocol((short)0x0231, "Luxcom");

  /**
   *
   */
  public static final PppDllProtocol SIGMA_NETWORK_SYSTEMS
    = new PppDllProtocol((short)0x0233, "Sigma Network Systems");

  /**
   *
   */
  public static final PppDllProtocol APPLE_CLIENT_SERVER_PROTOCOL
    = new PppDllProtocol((short)0x0235, "Apple Client Server Protocol");

  /**
   *
   */
  public static final PppDllProtocol MPLS_UNICAST
    = new PppDllProtocol((short)0x0281, "MPLS Unicast");

  /**
   *
   */
  public static final PppDllProtocol MPLS_MULTICAST
    = new PppDllProtocol((short)0x0283, "MPLS Multicast");

  /**
   *
   */
  public static final PppDllProtocol IEEE_P1284_4_STANDARD_DATA_PACKETS
    = new PppDllProtocol((short)0x0285, "IEEE p1284.4 standard - data packets");

  /**
   *
   */
  public static final PppDllProtocol ETSI_TETRA_NETWORK_PROTOCOL_TYPE_1
    = new PppDllProtocol((short)0x0287, "ETSI TETRA Network Protocol Type 1");

  /**
   *
   */
  public static final PppDllProtocol MULTICHANNEL_FLOW_TREATMENT_PROTOCOL_0289
    = new PppDllProtocol((short)0x0289, "Multichannel Flow Treatment Protocol");

  /**
   *
   */
  public static final PppDllProtocol RTP_IPHC_COMPRESSED_TCP_NO_DELTA
    = new PppDllProtocol((short)0x2063, "RTP IPHC Compressed TCP No Delta");

  /**
   *
   */
  public static final PppDllProtocol RTP_IPHC_CONTEXT_STATE
    = new PppDllProtocol((short)0x2065, "RTP IPHC Context State");

  /**
   *
   */
  public static final PppDllProtocol RTP_IPHC_COMPRESSED_UDP_16
    = new PppDllProtocol((short)0x2067, "RTP IPHC Compressed UDP 16");

  /**
   *
   */
  public static final PppDllProtocol RTP_IPHC_COMPRESSED_RTP_16
    = new PppDllProtocol((short)0x2069, "RTP IPHC Compressed RTP 16");

  /**
   *
   */
  public static final PppDllProtocol CRAY_COMMUNICATIONS_CONTROL_PROTOCOL
    = new PppDllProtocol((short)0x4001, "Cray Communications Control Protocol");

  /**
   *
   */
  public static final PppDllProtocol CDPD_MOBILE_NETWORK_REGISTRATION_PROTOCOL
    = new PppDllProtocol((short)0x4003, "CDPD Mobile Network Registration Protocol");

  /**
   *
   */
  public static final PppDllProtocol EXPAND_ACCELERATOR_PROTOCOL
    = new PppDllProtocol((short)0x4005, "Expand accelerator protocol");

  /**
   *
   */
  public static final PppDllProtocol ODSICP_NCP
    = new PppDllProtocol((short)0x4007, "ODSICP NCP");

  /**
   *
   */
  public static final PppDllProtocol DOCSIS_DLL
    = new PppDllProtocol((short)0x4009, "DOCSIS DLL");

  /**
   *
   */
  public static final PppDllProtocol CETACEAN_NETWORK_DETECTION_PROTOCOL
    = new PppDllProtocol((short)0x400B, "Cetacean Network Detection Protocol");

  /**
   *
   */
  public static final PppDllProtocol STACKER_LZS
    = new PppDllProtocol((short)0x4021, "Stacker LZS");

  /**
   *
   */
  public static final PppDllProtocol REFTEK_PROTOCOL
    = new PppDllProtocol((short)0x4023, "RefTek Protocol");

  /**
   *
   */
  public static final PppDllProtocol FIBRE_CHANNEL
    = new PppDllProtocol((short)0x4025, "Fibre Channel");

  /**
   *
   */
  public static final PppDllProtocol EMIT_PROTOCOLS
    = new PppDllProtocol((short)0x4027, "EMIT Protocols");

  /**
   *
   */
  public static final PppDllProtocol VSP
    = new PppDllProtocol((short)0x405b, "Vendor-Specific Protocol (VSP)");

  /**
   *
   */
  public static final PppDllProtocol TLSP
    = new PppDllProtocol((short)0x405d, "TRILL Link State Protocol (TLSP)");

  /**
   *
   */
  public static final PppDllProtocol INTERNET_PROTOCOL_CONTROL_PROTOCOL
    = new PppDllProtocol((short)0x8021, "Internet Protocol Control Protocol");

  /**
   *
   */
  public static final PppDllProtocol OSI_NETWORK_LAYER_CONTROL_PROTOCOL
    = new PppDllProtocol((short)0x8023, "OSI Network Layer Control Protocol");

  /**
   *
   */
  public static final PppDllProtocol XEROX_NS_IDP_CONTROL_PROTOCOL
    = new PppDllProtocol((short)0x8025, "Xerox NS IDP Control Protocol");

  /**
   *
   */
  public static final PppDllProtocol DECNET_PHASE_IV_CONTROL_PROTOCOL
    = new PppDllProtocol((short)0x8027, "DECnet Phase IV Control Protocol");

  /**
   *
   */
  public static final PppDllProtocol APPLETALK_CONTROL_PROTOCOL
    = new PppDllProtocol((short)0x8029, "Appletalk Control Protocol");

  /**
   *
   */
  public static final PppDllProtocol NOVELL_IPX_CONTROL_PROTOCOL
    = new PppDllProtocol((short)0x802b, "Novell IPX Control Protocol");

  /**
   *
   */
  public static final PppDllProtocol BRIDGING_NCP
    = new PppDllProtocol((short)0x8031, "Bridging NCP");

  /**
   *
   */
  public static final PppDllProtocol STREAM_PROTOCOL_CONTROL_PROTOCOL
    = new PppDllProtocol((short)0x8033, "Stream Protocol Control Protocol");

  /**
   *
   */
  public static final PppDllProtocol BANYAN_VINES_CONTROL_PROTOCOL
    = new PppDllProtocol((short)0x8035, "Banyan Vines Control Protocol");

  /**
   *
   */
  public static final PppDllProtocol MULTI_LINK_CONTROL_PROTOCOL
    = new PppDllProtocol((short)0x803d, "Multi-Link Control Protocol");

  /**
   *
   */
  public static final PppDllProtocol NETBIOS_FRAMING_CONTROL_PROTOCOL
    = new PppDllProtocol((short)0x803f, "NETBIOS Framing Control Protocol");

  /**
   *
   */
  public static final PppDllProtocol CISCO_SYSTEMS_CONTROL_PROTOCOL
    = new PppDllProtocol((short)0x8041, "Cisco Systems Control Protocol");

  /**
   *
   */
  public static final PppDllProtocol ASCOM_TIMEPLEX_8043
    = new PppDllProtocol((short)0x8043, "Ascom Timeplex");

  /**
   *
   */
  public static final PppDllProtocol FUJITSU_LBLB_CONTROL_PROTOCOL
    = new PppDllProtocol((short)0x8045, "Fujitsu LBLB Control Protocol");

  /**
   *
   */
  public static final PppDllProtocol RLNCP
    = new PppDllProtocol((short)0x8047, "DCA Remote Lan Network Control Protocol (RLNCP)");

  /**
   *
   */
  public static final PppDllProtocol PPP_SDCP
    = new PppDllProtocol((short)0x8049, "Serial Data Control Protocol (PPP-SDCP)");

  /**
   *
   */
  public static final PppDllProtocol SNA_OVER_802_2_CONTROL_PROTOCOL
    = new PppDllProtocol((short)0x804b, "SNA over 802.2 Control Protocol");

  /**
   *
   */
  public static final PppDllProtocol SNA_CONTROL_PROTOCOL
    = new PppDllProtocol((short)0x804d, "SNA Control Protocol");

  /**
   *
   */
  public static final PppDllProtocol IP6_HEADER_COMPRESSION_CONTROL_PROTOCOL
    = new PppDllProtocol((short)0x804f, "IP6 Header Compression Control Protocol");

  /**
   *
   */
  public static final PppDllProtocol KNX_BRIDGING_CONTROL_PROTOCOL
    = new PppDllProtocol((short)0x8051, "KNX Bridging Control Protocol");

  /**
   *
   */
  public static final PppDllProtocol ENCRYPTION_CONTROL_PROTOCOL
    = new PppDllProtocol((short)0x8053, "Encryption Control Protocol");

  /**
   *
   */
  public static final PppDllProtocol INDIVIDUAL_LINK_ENCRYPTION_CONTROL_PROTOCOL
    = new PppDllProtocol((short)0x8055, "Individual Link Encryption Control Protocol");

  /**
   *
   */
  public static final PppDllProtocol IPV6_CONTROL_PROTOCOL
    = new PppDllProtocol((short)0x8057, "IPv6 Control Protocol");

  /**
   *
   */
  public static final PppDllProtocol PPP_MUXING_CONTROL_PROTOCOL
    = new PppDllProtocol((short)0x8059, "PPP Muxing Control Protocol");

  /**
   *
   */
  public static final PppDllProtocol VSNCP
    = new PppDllProtocol((short)0x805b, "Vendor-Specific Network Control Protocol (VSNCP)");

  /**
   *
   */
  public static final PppDllProtocol TNCP
    = new PppDllProtocol((short)0x805d, "TRILL Network Control Protocol (TNCP)");

  /**
   *
   */
  public static final PppDllProtocol STAMPEDE_BRIDGING_CONTROL_PROTOCOL
    = new PppDllProtocol((short)0x806f, "Stampede Bridging Control Protocol");

  /**
   *
   */
  public static final PppDllProtocol MP_PLUS_CONTROL_PROTOCOL
    = new PppDllProtocol((short)0x8073, "MP+ Control Protocol");

  /**
   *
   */
  public static final PppDllProtocol NTCITS_IPI_CONTROL_PROTOCOL
    = new PppDllProtocol((short)0x80c1, "NTCITS IPI Control Protocol");

  /**
   *
   */
  public static final PppDllProtocol SINGLE_LINK_COMPRESSION_IN_MULTILINK_CONTROL
    = new PppDllProtocol((short)0x80fb, "single link compression in multilink control");

  /**
   *
   */
  public static final PppDllProtocol COMPRESSION_CONTROL_PROTOCOL
    = new PppDllProtocol((short)0x80fd, "Compression Control Protocol");

  /**
   *
   */
  public static final PppDllProtocol CISCO_DISCOVERY_PROTOCOL_CONTROL
    = new PppDllProtocol((short)0x8207, "Cisco Discovery Protocol Control");

  /**
   *
   */
  public static final PppDllProtocol NETCS_TWIN_ROUTING_8209
    = new PppDllProtocol((short)0x8209, "Netcs Twin Routing");

  /**
   *
   */
  public static final PppDllProtocol STP_CONTROL_PROTOCOL
    = new PppDllProtocol((short)0x820b, "STP - Control Protocol");

  /**
   *
   */
  public static final PppDllProtocol EDPCP
    = new PppDllProtocol((short)0x820d, "EDPCP - Extreme Discovery Protocol Ctrl Prtcl");

  /**
   *
   */
  public static final PppDllProtocol APPLE_CLIENT_SERVER_PROTOCOL_CONTROL
    = new PppDllProtocol((short)0x8235, "Apple Client Server Protocol Control");

  /**
   *
   */
  public static final PppDllProtocol MPLSCP
    = new PppDllProtocol((short)0x8281, "MPLSCP");

  /**
   *
   */
  public static final PppDllProtocol IEEE_P1284_4_STANDARD_PROTOCOL_CONTROL
    = new PppDllProtocol((short)0x8285, "IEEE p1284.4 standard - Protocol Control");

  /**
   *
   */
  public static final PppDllProtocol ETSI_TETRA_TNP1_CONTROL_PROTOCOL
    = new PppDllProtocol((short)0x8287, "ETSI TETRA TNP1 Control Protocol");

  /**
   *
   */
  public static final PppDllProtocol MULTICHANNEL_FLOW_TREATMENT_PROTOCOL_8289
    = new PppDllProtocol((short)0x8289, "Multichannel Flow Treatment Protocol");

  /**
   *
   */
  public static final PppDllProtocol LINK_CONTROL_PROTOCOL
    = new PppDllProtocol((short)0xc021, "Link Control Protocol");

  /**
   *
   */
  public static final PppDllProtocol PASSWORD_AUTHENTICATION_PROTOCOL
    = new PppDllProtocol((short)0xc023, "Password Authentication Protocol");

  /**
   *
   */
  public static final PppDllProtocol LINK_QUALITY_REPORT
    = new PppDllProtocol((short)0xc025, "Link Quality Report");

  /**
   *
   */
  public static final PppDllProtocol SHIVA_PASSWORD_AUTHENTICATION_PROTOCOL
    = new PppDllProtocol((short)0xc027, "Shiva Password Authentication Protocol");

  /**
   *
   */
  public static final PppDllProtocol CBCP
    = new PppDllProtocol((short)0xc029, "CallBack Control Protocol (CBCP)");

  /**
   *
   */
  public static final PppDllProtocol BACP
    = new PppDllProtocol((short)0xc02b, "BACP Bandwidth Allocation Control Protocol");

  /**
   *
   */
  public static final PppDllProtocol BAP
    = new PppDllProtocol((short)0xc02d, "BAP");

  /**
   *
   */
  public static final PppDllProtocol VSAP
    = new PppDllProtocol((short)0xc05b, "Vendor-Specific Authentication Protocol (VSAP)");

  /**
   *
   */
  public static final PppDllProtocol CONTAINER_CONTROL_PROTOCOL
    = new PppDllProtocol((short)0xc081, "Container Control Protocol");

  /**
   *
   */
  public static final PppDllProtocol CHALLENGE_HANDSHAKE_AUTHENTICATION_PROTOCOL
    = new PppDllProtocol((short)0xc223, "Challenge Handshake Authentication Protocol");

  /**
   *
   */
  public static final PppDllProtocol RSA_AUTHENTICATION_PROTOCOL
    = new PppDllProtocol((short)0xc225, "RSA Authentication Protocol");

  /**
   *
   */
  public static final PppDllProtocol EXTENSIBLE_AUTHENTICATION_PROTOCOL
    = new PppDllProtocol((short)0xc227, "Extensible Authentication Protocol");

  /**
   *
   */
  public static final PppDllProtocol SIEP
    = new PppDllProtocol((short)0xc229, "Mitsubishi Security Info Exch Ptcl (SIEP)");

  /**
   *
   */
  public static final PppDllProtocol STAMPEDE_BRIDGING_AUTHORIZATION_PROTOCOL
    = new PppDllProtocol((short)0xc26f, "Stampede Bridging Authorization Protocol");

  /**
   *
   */
  public static final PppDllProtocol PROPRIETARY_AUTHENTICATION_PROTOCOL_C281
    = new PppDllProtocol((short)0xc281, "Proprietary Authentication Protocol");

  /**
   *
   */
  public static final PppDllProtocol PROPRIETARY_AUTHENTICATION_PROTOCOL_C283
    = new PppDllProtocol((short)0xc283, "Proprietary Authentication Protocol");

  /**
   *
   */
  public static final PppDllProtocol PROPRIETARY_NODE_ID_AUTHENTICATION_PROTOCOL
    = new PppDllProtocol((short)0xc481, "Proprietary Node ID Authentication Protocol");

  private static final Map<Short, PppDllProtocol> registry
    = new HashMap<Short, PppDllProtocol>();

  static {
    for (Field field: PppDllProtocol.class.getFields()) {
      if (PppDllProtocol.class.isAssignableFrom(field.getType())) {
        try {
          PppDllProtocol f = (PppDllProtocol)field.get(null);
          registry.put(f.value(), f);
        } catch (IllegalArgumentException e) {
          throw new AssertionError(e);
        } catch (IllegalAccessException e) {
          throw new AssertionError(e);
        } catch (NullPointerException e) {
          continue;
        }
      }
    }
  }

  /**
   *
   * @param value
   * @param name
   * @throws IllegalArgumentException
   */
  public PppDllProtocol(Short value, String name) throws IllegalArgumentException {
    super(value, name);
    if (((value & 0x0100) != 0)) {
      throw new IllegalArgumentException(
              value + " is invalid value. "
                +"Its least significant bit of the most significant octet must be 0."
            );
    }
    if (((value & 0x0001) == 0)) {
      throw new IllegalArgumentException(
              value + " is invalid value. "
                +"Its least significant bit of the least significant octet must be 1."
            );
    }
  }

  /**
   *
   * @param value
   * @return a PppDllProtocol object.
   * @throws IllegalArgumentException
   */
  public static PppDllProtocol getInstance(Short value) throws IllegalArgumentException {
    if (registry.containsKey(value)) {
      return registry.get(value);
    }
    else {
      return new PppDllProtocol(value, "unknown");
    }
  }

  /**
   *
   * @param type
   * @return a PppDllProtocol object.
   */
  public static PppDllProtocol register(PppDllProtocol type) {
    return registry.put(type.value(), type);
  }

  /**
   *
   * @return a string representation of this value.
   */
  @Override
  public String valueAsString() {
    return "0x" + ByteArrays.toHexString(value(), "");
  }

  @Override
  public int compareTo(PppDllProtocol o) {
    return value().compareTo(o.value());
  }

}
