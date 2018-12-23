/*_##########################################################################
  _##
  _##  Copyright (C) 2011-2015  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.namednumber;

import java.util.HashMap;
import java.util.Map;

/**
 * IP Number
 *
 * @see <a href="http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xml">IANA
 *     Registry</a>
 * @author Kaito Yamada
 * @since pcap4j 0.9.1
 */
public final class IpNumber extends NamedNumber<Byte, IpNumber> {

  /** */
  private static final long serialVersionUID = -3109332132272568136L;

  /** IPv6 Hop-by-Hop Option: 0 */
  public static final IpNumber IPV6_HOPOPT = new IpNumber((byte) 0, "IPv6 Hop-by-Hop Option");

  /** Internet Control Message (ICMPv4): 1 */
  public static final IpNumber ICMPV4 = new IpNumber((byte) 1, "ICMPv4");

  /** Internet Group Management (IGMP): 2 */
  public static final IpNumber IGMP = new IpNumber((byte) 2, "IGMP");

  /** Gateway-to-Gateway (GGP): 3 */
  public static final IpNumber GGP = new IpNumber((byte) 3, "GGP");

  /** IPv4 encapsulation: 4 */
  public static final IpNumber IPV4 = new IpNumber((byte) 4, "IPv4 encapsulation");

  /** Stream (ST): 5 */
  public static final IpNumber ST = new IpNumber((byte) 5, "Stream");

  /** Transmission Control (TCP): 6 */
  public static final IpNumber TCP = new IpNumber((byte) 6, "TCP");

  /** CBT: 7 */
  public static final IpNumber CBT = new IpNumber((byte) 7, "CBT");

  /** Exterior Gateway Protocol (EGP): 8 */
  public static final IpNumber EGP = new IpNumber((byte) 8, "EGP");

  /** any private interior gateway (IGP, used by Cisco for their IGRP): 9 */
  public static final IpNumber IGP = new IpNumber((byte) 9, "IGP");

  /** BBN RCC Monitoring: 10 */
  public static final IpNumber BBN_RCC_MON = new IpNumber((byte) 10, "BBN RCC Monitoring");

  /** Network Voice Protocol (NVP-II): 11 */
  public static final IpNumber NVP_II = new IpNumber((byte) 11, "NVP-II");

  /** PUP: 12 */
  public static final IpNumber PUP = new IpNumber((byte) 12, "PUP");

  /** ARGUS: 13 */
  public static final IpNumber ARGUS = new IpNumber((byte) 13, "ARGUS");

  /** EMCON: 14 */
  public static final IpNumber EMCON = new IpNumber((byte) 14, "EMCON");

  /** Cross Net Debugger (XNET): 15 */
  public static final IpNumber XNET = new IpNumber((byte) 15, "XNET");

  /** Chaos: 16 */
  public static final IpNumber CHAOS = new IpNumber((byte) 16, "Chaos");

  /** User Datagram (UDP): 17 */
  public static final IpNumber UDP = new IpNumber((byte) 17, "UDP");

  /** Multiplexing: 18 */
  public static final IpNumber MUX = new IpNumber((byte) 18, "Multiplexing");

  /** DCN Measurement Subsystems (DCN-MEAS): 19 */
  public static final IpNumber DCN_MEAS = new IpNumber((byte) 19, "DCN-MEAS");

  /** Host Monitoring (HMP): 20 */
  public static final IpNumber HMP = new IpNumber((byte) 20, "HMP");

  /** Packet Radio Measurement (PRM): 21 */
  public static final IpNumber PRM = new IpNumber((byte) 21, "PRM");

  /** XEROX NS IDP: 22 */
  public static final IpNumber XNS_IDP = new IpNumber((byte) 22, "XEROX NS IDP");

  /** Trunk-1: 23 */
  public static final IpNumber TRUNK_1 = new IpNumber((byte) 23, "Trunk-1");

  /** Trunk-2: 24 */
  public static final IpNumber TRUNK_2 = new IpNumber((byte) 24, "Trunk-2");

  /** Leaf-1: 25 */
  public static final IpNumber LEAF_1 = new IpNumber((byte) 25, "Leaf-1");

  /** Leaf-2: 26 */
  public static final IpNumber LEAF_2 = new IpNumber((byte) 26, "Leaf-2");

  /** Reliable Data Protocol (RDP): 27 */
  public static final IpNumber RDP = new IpNumber((byte) 27, "RDP");

  /** Internet Reliable Transaction (IRTP): 28 */
  public static final IpNumber IRTP = new IpNumber((byte) 28, "IRTP");

  /** ISO Transport Protocol Class 4 (ISO-TP4): 29 */
  public static final IpNumber ISO_TP4 = new IpNumber((byte) 29, "ISO-TP4");

  /** Bulk Data Transfer Protocol (NETBLT): 30 */
  public static final IpNumber NETBLT = new IpNumber((byte) 30, "NETBLT");

  /** MFE Network Services Protocol (MFE-NSP): 31 */
  public static final IpNumber MFE_NSP = new IpNumber((byte) 31, "MFE-NSP");

  /** MERIT Internodal Protocol (MERIT-INP): 32 */
  public static final IpNumber MERIT_INP = new IpNumber((byte) 32, "MERIT-INP");

  /** Datagram Congestion Control Protocol (DCCP): 33 */
  public static final IpNumber DCCP = new IpNumber((byte) 33, "DCCP");

  /** Third Party Connect Protocol (3PC): 34 */
  public static final IpNumber TPC = new IpNumber((byte) 34, "3PC");

  /** Inter-Domain Policy Routing Protocol (IDPR): 35 */
  public static final IpNumber IDPR = new IpNumber((byte) 35, "IDPR");

  /** XTP: 36 */
  public static final IpNumber XTP = new IpNumber((byte) 36, "XTP");

  /** Datagram Delivery Protocol (DDP): 37 */
  public static final IpNumber DDP = new IpNumber((byte) 37, "DDP");

  /** IDPR Control Message Transport Protocol (IDPR-CMTP): 38 */
  public static final IpNumber IDPR_CMTP = new IpNumber((byte) 38, "IDPR-CMTP");

  /** TP++ Transport Protocol: 39 */
  public static final IpNumber TP_PP = new IpNumber((byte) 39, "TP++");

  /** IL Transport Protocol: 40 */
  public static final IpNumber IL = new IpNumber((byte) 40, "IL");

  /** IPv6 encapsulation: 41 */
  public static final IpNumber IPV6 = new IpNumber((byte) 41, "IPv6 encapsulation");

  /** Source Demand Routing Protocol (SDRP): 42 */
  public static final IpNumber SDRP = new IpNumber((byte) 42, "SDRP");

  /** Routing Header for IPv6: 43 */
  public static final IpNumber IPV6_ROUTE = new IpNumber((byte) 43, "Routing Header for IPv6");

  /** Fragment Header for IPv6: 44 */
  public static final IpNumber IPV6_FRAG = new IpNumber((byte) 44, "Fragment Header for IPv6");

  /** Inter-Domain Routing Protocol (IDRP): 45 */
  public static final IpNumber IDRP = new IpNumber((byte) 45, "IDRP");

  /** Reservation Protocol (RSVP): 46 */
  public static final IpNumber RSVP = new IpNumber((byte) 46, "RSVP");

  /** Generic Routing Encapsulation (GRE): 47 */
  public static final IpNumber GRE = new IpNumber((byte) 47, "GRE");

  /** Dynamic Source Routing Protocol (DSR): 48 */
  public static final IpNumber DSR = new IpNumber((byte) 48, "DSR");

  /** BNA: 49 */
  public static final IpNumber BNA = new IpNumber((byte) 49, "BNA");

  /** Encap Security Payload (ESP): 50 */
  public static final IpNumber ESP = new IpNumber((byte) 50, "ESP");

  /** Authentication Header: 51 */
  public static final IpNumber AH = new IpNumber((byte) 51, "Authentication Header");

  /** Integrated Net Layer Security TUBA (I-NLSP): 52 */
  public static final IpNumber I_NLSP = new IpNumber((byte) 52, "I-NLSP");

  /** IP with Encryption (SWIPE): 53 */
  public static final IpNumber SWIPE = new IpNumber((byte) 53, "SWIPE");

  /** NBMA Address Resolution Protocol (NARP): 54 */
  public static final IpNumber NARP = new IpNumber((byte) 54, "NARP");

  /** IP Mobility: 55 */
  public static final IpNumber MOBILE = new IpNumber((byte) 55, "IP Mobility");

  /** Transport Layer Security Protocol using Kryptonet key management (TLSP): 56 */
  public static final IpNumber TLSP = new IpNumber((byte) 56, "TLSP");

  /** SKIP: 57 */
  public static final IpNumber SKIP = new IpNumber((byte) 57, "SKIP");

  /** ICMP for IPv6: 58 */
  public static final IpNumber ICMPV6 = new IpNumber((byte) 58, "ICMPv6");

  /** No Next Header for IPv6: 59 */
  public static final IpNumber IPV6_NONXT = new IpNumber((byte) 59, "No Next Header for IPv6");

  /** Destination Options for IPv6: 60 */
  public static final IpNumber IPV6_DST_OPTS =
      new IpNumber((byte) 60, "Destination Options for IPv6");

  /** CFTP: 62 */
  public static final IpNumber CFTP = new IpNumber((byte) 62, "CFTP");

  /** SATNET and Backroom EXPAK: 64 */
  public static final IpNumber SAT_EXPAK = new IpNumber((byte) 64, "SATNET and Backroom EXPAK");

  /** Kryptolan: 65 */
  public static final IpNumber KRYPTOLAN = new IpNumber((byte) 65, "Kryptolan");

  /** MIT Remote Virtual Disk Protocol (RVD): 66 */
  public static final IpNumber RVD = new IpNumber((byte) 66, "RVD");

  /** Internet Pluribus Packet Core (IPPC): 67 */
  public static final IpNumber IPPC = new IpNumber((byte) 67, "IPPC");

  /** SATNET Monitoring: 69 */
  public static final IpNumber SAT_MON = new IpNumber((byte) 69, "SATNET Monitoring");

  /** VISA Protocol: 70 */
  public static final IpNumber VISA = new IpNumber((byte) 70, "VISA");

  /** Internet Packet Core Utility (IPCV): 71 */
  public static final IpNumber IPCV = new IpNumber((byte) 71, "IPCV");

  /** Computer Protocol Network Executive (CPNX): 72 */
  public static final IpNumber CPNX = new IpNumber((byte) 72, "CPNX");

  /** Computer Protocol Heart Beat (CPHB): 73 */
  public static final IpNumber CPHB = new IpNumber((byte) 73, "CPHB");

  /** Wang Span Network (WSN): 74 */
  public static final IpNumber WSN = new IpNumber((byte) 74, "WSN");

  /** Packet Video Protocol (PVP): 75 */
  public static final IpNumber PVP = new IpNumber((byte) 75, "PVP");

  /** Backroom SATNET Monitoring: 76 */
  public static final IpNumber BR_SAT_MON = new IpNumber((byte) 76, "Backroom SATNET Monitoring");

  /** SUN ND PROTOCOL: 77 */
  public static final IpNumber SUN_ND = new IpNumber((byte) 77, "SUN-ND");

  /** WIDEBAND Monitoring: 78 */
  public static final IpNumber WB_MON = new IpNumber((byte) 78, "WIDEBAND Monitoring");

  /** WIDEBAND EXPAK: 79 */
  public static final IpNumber WB_EXPAK = new IpNumber((byte) 79, "WIDEBAND EXPAK");

  /** ISO Internet Protocol (ISO-IP): 80 */
  public static final IpNumber ISO_IP = new IpNumber((byte) 80, "ISO-IP");

  /** VMTP: 81 */
  public static final IpNumber VMTP = new IpNumber((byte) 81, "VMTP");

  /** SECURE-VMTP: 82 */
  public static final IpNumber SECURE_VMTP = new IpNumber((byte) 82, "SECURE-VMTP");

  /** VINES: 83 */
  public static final IpNumber VINES = new IpNumber((byte) 83, "VINES");

  /** Transaction Transport Protocol (TTP): 84 */
  public static final IpNumber TTP = new IpNumber((byte) 84, "TTP");

  /** Internet Protocol Traffic Manager (IPTM): 84 */
  public static final IpNumber IPTM = new IpNumber((byte) 84, "IPTM");

  /** NSFNET-IGP: 85 */
  public static final IpNumber NSFNET_IGP = new IpNumber((byte) 85, "NSFNET-IGP");

  /** Dissimilar Gateway Protocol (DGP): 86 */
  public static final IpNumber DGP = new IpNumber((byte) 86, "DGP");

  /** TCF: 87 */
  public static final IpNumber TCF = new IpNumber((byte) 87, "TCF");

  /** EIGRP: 88 */
  public static final IpNumber EIGRP = new IpNumber((byte) 88, "EIGRP");

  /** OSPFIGP: 89 */
  public static final IpNumber OSPFIGP = new IpNumber((byte) 89, "OSPFIGP");

  /** Sprite RPC Protocol: 90 */
  public static final IpNumber SPRITE_RPC = new IpNumber((byte) 90, "Sprite RPC");

  /** Locus Address Resolution Protocol (LARP): 91 */
  public static final IpNumber LARP = new IpNumber((byte) 91, "LARP");

  /** Multicast Transport Protocol (MTP): 92 */
  public static final IpNumber MTP = new IpNumber((byte) 92, "MTP");

  /** AX.25 Frames: 93 */
  public static final IpNumber AX_25 = new IpNumber((byte) 93, "AX.25");

  /** IP-within-IP Encapsulation Protocol (IPIP): 94 */
  public static final IpNumber IPIP = new IpNumber((byte) 94, "IPIP");

  /** Mobile Internetworking Control Protocol (MICP): 95 */
  public static final IpNumber MICP = new IpNumber((byte) 95, "MICP");

  /** Semaphore Communications Security Protocol: 96 */
  public static final IpNumber SCC_SP = new IpNumber((byte) 96, "SCC-SP");

  /** Ethernet-within-IP Encapsulation: 97 */
  public static final IpNumber ETHERIP =
      new IpNumber((byte) 97, "Ethernet-within-IP Encapsulation");

  /** Encapsulation Header: 98 */
  public static final IpNumber ENCAP = new IpNumber((byte) 98, "Encapsulation Header");

  /** GMTP: 100 */
  public static final IpNumber GMTP = new IpNumber((byte) 100, "GMTP");

  /** Ipsilon Flow Management Protocol (IFMP): 101 */
  public static final IpNumber IFMP = new IpNumber((byte) 101, "IFMP");

  /** PNNI over IP: 102 */
  public static final IpNumber PNNI = new IpNumber((byte) 102, "PNNI over IP");

  /** Protocol Independent Multicast (PIM): 103 */
  public static final IpNumber PIM = new IpNumber((byte) 103, "PIM");

  /** ARIS: 104 */
  public static final IpNumber ARIS = new IpNumber((byte) 104, "ARIS");

  /** SCPS: 105 */
  public static final IpNumber SCPS = new IpNumber((byte) 105, "SCPS");

  /** QNX: 106 */
  public static final IpNumber QNX = new IpNumber((byte) 106, "QNX");

  /** Active Networks: 107 */
  public static final IpNumber ACTIVE_NETWORKS = new IpNumber((byte) 107, "Active Networks");

  /** IP Payload Compression Protocol (IPCOMP): 108 */
  public static final IpNumber IPCOMP = new IpNumber((byte) 108, "IPCOMP");

  /** Sitara Networks Protocol (SNP): 109 */
  public static final IpNumber SNP = new IpNumber((byte) 109, "SNP");

  /** Compaq Peer Protocol: 110 */
  public static final IpNumber COMPAQ_PEER = new IpNumber((byte) 110, "Compaq Peer");

  /** IPX in IP: 111 */
  public static final IpNumber IPX_IN_IP = new IpNumber((byte) 111, "IPX in IP");

  /** Virtual Router Redundancy Protocol: 112 */
  public static final IpNumber VRRP = new IpNumber((byte) 112, "VRRP");

  /** Pragmatic General Multicast (PGM): 113 */
  public static final IpNumber PGM = new IpNumber((byte) 113, "PGM");

  /** Layer Two Tunneling Protocol (L2TP): 115 */
  public static final IpNumber L2TP = new IpNumber((byte) 115, "L2TP");

  /** D-II Data Exchange (DDX): 116 */
  public static final IpNumber DDX = new IpNumber((byte) 116, "DDX");

  /** Interactive Agent Transfer Protocol (IATP): 117 */
  public static final IpNumber IATP = new IpNumber((byte) 117, "IATP");

  /** Schedule Transfer Protocol (STP): 118 */
  public static final IpNumber STP = new IpNumber((byte) 118, "STP");

  /** SpectraLink Radio Protocol (SRP): 119 */
  public static final IpNumber SRP = new IpNumber((byte) 119, "SRP");

  /** UTI: 120 */
  public static final IpNumber UTI = new IpNumber((byte) 120, "UTI");

  /** Simple Message Protocol (SMP): 121 */
  public static final IpNumber SMP = new IpNumber((byte) 121, "SMP");

  /** Simple Multicast Protocol (SM): 122 */
  public static final IpNumber SM = new IpNumber((byte) 122, "SM");

  /** Performance Transparency Protocol (PTP): 123 */
  public static final IpNumber PTP = new IpNumber((byte) 123, "PTP");

  /** ISIS over IPv4: 124 */
  public static final IpNumber ISIS_OVER_IPV4 = new IpNumber((byte) 124, "ISIS over IPv4");

  /** FIRE: 125 */
  public static final IpNumber FIRE = new IpNumber((byte) 125, "FIRE");

  /** Combat Radio Transport Protocol (CRTP): 126 */
  public static final IpNumber CRTP = new IpNumber((byte) 126, "CRTP");

  /** Combat Radio User Datagram (CRUDP): 127 */
  public static final IpNumber CRUDP = new IpNumber((byte) 127, "CRUDP");

  /** SSCOPMCE: 128 */
  public static final IpNumber SSCOPMCE = new IpNumber((byte) 128, "SSCOPMCE");

  /** IPLT: 129 */
  public static final IpNumber IPLT = new IpNumber((byte) 129, "IPLT");

  /** Secure Packet Shield (SPS): 130 */
  public static final IpNumber SPS = new IpNumber((byte) 130, "SPS");

  /** Private IP Encapsulation within IP (PIPE): 131 */
  public static final IpNumber PIPE = new IpNumber((byte) 131, "PIPE");

  /** Stream Control Transmission Protocol (SCTP): 132 */
  public static final IpNumber SCTP = new IpNumber((byte) 132, "SCTP");

  /** Fibre Channel: 133 */
  public static final IpNumber FC = new IpNumber((byte) 133, "Fibre Channel");

  /** RSVP-E2E-IGNORE: 134 */
  public static final IpNumber RSVP_E2E_IGNORE = new IpNumber((byte) 134, "RSVP-E2E-IGNORE");

  /** Mobility Header: 135 */
  public static final IpNumber MOBILITY_HEADER = new IpNumber((byte) 135, "Mobility Header");

  /** UDPLite: 136 */
  public static final IpNumber UDPLITE = new IpNumber((byte) 136, "UDPLite");

  /** MPLS-in-IP: 137 */
  public static final IpNumber MPLS_IN_IP = new IpNumber((byte) 137, "MPLS-in-IP");

  /** MANET Protocols: 138 */
  public static final IpNumber MANET = new IpNumber((byte) 138, "MANET");

  /** Host Identity Protocol (HIP): 139 */
  public static final IpNumber HIP = new IpNumber((byte) 139, "HIP");

  /** Shim6 Protocol: 140 */
  public static final IpNumber SHIM6 = new IpNumber((byte) 140, "Shim6");

  /** Wrapped Encapsulating Security Payload (WESP): 141 */
  public static final IpNumber WESP = new IpNumber((byte) 141, "WESP");

  /** Robust Header Compression (ROHC): 142 */
  public static final IpNumber ROHC = new IpNumber((byte) 142, "ROHC");

  private static final Map<Byte, IpNumber> registry = new HashMap<Byte, IpNumber>();

  static {
    registry.put(IPV6_HOPOPT.value(), IPV6_HOPOPT);
    registry.put(ICMPV4.value(), ICMPV4);
    registry.put(IGMP.value(), IGMP);
    registry.put(GGP.value(), GGP);
    registry.put(IPV4.value(), IPV4);
    registry.put(ST.value(), ST);
    registry.put(TCP.value(), TCP);
    registry.put(CBT.value(), CBT);
    registry.put(EGP.value(), EGP);
    registry.put(IGP.value(), IGP);
    registry.put(BBN_RCC_MON.value(), BBN_RCC_MON);
    registry.put(NVP_II.value(), NVP_II);
    registry.put(PUP.value(), PUP);
    registry.put(ARGUS.value(), ARGUS);
    registry.put(EMCON.value(), EMCON);
    registry.put(XNET.value(), XNET);
    registry.put(CHAOS.value(), CHAOS);
    registry.put(UDP.value(), UDP);
    registry.put(MUX.value(), MUX);
    registry.put(DCN_MEAS.value(), DCN_MEAS);
    registry.put(HMP.value(), HMP);
    registry.put(PRM.value(), PRM);
    registry.put(XNS_IDP.value(), XNS_IDP);
    registry.put(TRUNK_1.value(), TRUNK_1);
    registry.put(TRUNK_2.value(), TRUNK_2);
    registry.put(LEAF_1.value(), LEAF_1);
    registry.put(LEAF_2.value(), LEAF_2);
    registry.put(RDP.value(), RDP);
    registry.put(IRTP.value(), IRTP);
    registry.put(ISO_TP4.value(), ISO_TP4);
    registry.put(NETBLT.value(), NETBLT);
    registry.put(MFE_NSP.value(), MFE_NSP);
    registry.put(MERIT_INP.value(), MERIT_INP);
    registry.put(DCCP.value(), DCCP);
    registry.put(TPC.value(), TPC);
    registry.put(IDPR.value(), IDPR);
    registry.put(XTP.value(), XTP);
    registry.put(DDP.value(), DDP);
    registry.put(IDPR_CMTP.value(), IDPR_CMTP);
    registry.put(TP_PP.value(), TP_PP);
    registry.put(IL.value(), IL);
    registry.put(IPV6.value(), IPV6);
    registry.put(SDRP.value(), SDRP);
    registry.put(IPV6_ROUTE.value(), IPV6_ROUTE);
    registry.put(IPV6_FRAG.value(), IPV6_FRAG);
    registry.put(IDRP.value(), IDRP);
    registry.put(RSVP.value(), RSVP);
    registry.put(GRE.value(), GRE);
    registry.put(DSR.value(), DSR);
    registry.put(BNA.value(), BNA);
    registry.put(ESP.value(), ESP);
    registry.put(AH.value(), AH);
    registry.put(I_NLSP.value(), I_NLSP);
    registry.put(SWIPE.value(), SWIPE);
    registry.put(NARP.value(), NARP);
    registry.put(MOBILE.value(), MOBILE);
    registry.put(TLSP.value(), TLSP);
    registry.put(SKIP.value(), SKIP);
    registry.put(ICMPV6.value(), ICMPV6);
    registry.put(IPV6_NONXT.value(), IPV6_NONXT);
    registry.put(IPV6_DST_OPTS.value(), IPV6_DST_OPTS);
    registry.put(CFTP.value(), CFTP);
    registry.put(SAT_EXPAK.value(), SAT_EXPAK);
    registry.put(KRYPTOLAN.value(), KRYPTOLAN);
    registry.put(RVD.value(), RVD);
    registry.put(IPPC.value(), IPPC);
    registry.put(SAT_MON.value(), SAT_MON);
    registry.put(VISA.value(), VISA);
    registry.put(IPCV.value(), IPCV);
    registry.put(CPNX.value(), CPNX);
    registry.put(CPHB.value(), CPHB);
    registry.put(WSN.value(), WSN);
    registry.put(PVP.value(), PVP);
    registry.put(BR_SAT_MON.value(), BR_SAT_MON);
    registry.put(SUN_ND.value(), SUN_ND);
    registry.put(WB_MON.value(), WB_MON);
    registry.put(WB_EXPAK.value(), WB_EXPAK);
    registry.put(ISO_IP.value(), ISO_IP);
    registry.put(VMTP.value(), VMTP);
    registry.put(SECURE_VMTP.value(), SECURE_VMTP);
    registry.put(VINES.value(), VINES);
    registry.put(TTP.value(), TTP);
    registry.put(IPTM.value(), IPTM);
    registry.put(NSFNET_IGP.value(), NSFNET_IGP);
    registry.put(DGP.value(), DGP);
    registry.put(TCF.value(), TCF);
    registry.put(EIGRP.value(), EIGRP);
    registry.put(OSPFIGP.value(), OSPFIGP);
    registry.put(SPRITE_RPC.value(), SPRITE_RPC);
    registry.put(LARP.value(), LARP);
    registry.put(MTP.value(), MTP);
    registry.put(AX_25.value(), AX_25);
    registry.put(IPIP.value(), IPIP);
    registry.put(MICP.value(), MICP);
    registry.put(SCC_SP.value(), SCC_SP);
    registry.put(ETHERIP.value(), ETHERIP);
    registry.put(ENCAP.value(), ENCAP);
    registry.put(GMTP.value(), GMTP);
    registry.put(IFMP.value(), IFMP);
    registry.put(PNNI.value(), PNNI);
    registry.put(PIM.value(), PIM);
    registry.put(ARIS.value(), ARIS);
    registry.put(SCPS.value(), SCPS);
    registry.put(QNX.value(), QNX);
    registry.put(ACTIVE_NETWORKS.value(), ACTIVE_NETWORKS);
    registry.put(IPCOMP.value(), IPCOMP);
    registry.put(SNP.value(), SNP);
    registry.put(COMPAQ_PEER.value(), COMPAQ_PEER);
    registry.put(IPX_IN_IP.value(), IPX_IN_IP);
    registry.put(VRRP.value(), VRRP);
    registry.put(PGM.value(), PGM);
    registry.put(L2TP.value(), L2TP);
    registry.put(DDX.value(), DDX);
    registry.put(IATP.value(), IATP);
    registry.put(STP.value(), STP);
    registry.put(SRP.value(), SRP);
    registry.put(UTI.value(), UTI);
    registry.put(SMP.value(), SMP);
    registry.put(SM.value(), SM);
    registry.put(PTP.value(), PTP);
    registry.put(ISIS_OVER_IPV4.value(), ISIS_OVER_IPV4);
    registry.put(FIRE.value(), FIRE);
    registry.put(CRTP.value(), CRTP);
    registry.put(CRUDP.value(), CRUDP);
    registry.put(SSCOPMCE.value(), SSCOPMCE);
    registry.put(IPLT.value(), IPLT);
    registry.put(SPS.value(), SPS);
    registry.put(PIPE.value(), PIPE);
    registry.put(SCTP.value(), SCTP);
    registry.put(FC.value(), FC);
    registry.put(RSVP_E2E_IGNORE.value(), RSVP_E2E_IGNORE);
    registry.put(MOBILITY_HEADER.value(), MOBILITY_HEADER);
    registry.put(UDPLITE.value(), UDPLITE);
    registry.put(MPLS_IN_IP.value(), MPLS_IN_IP);
    registry.put(MANET.value(), MANET);
    registry.put(HIP.value(), HIP);
    registry.put(SHIM6.value(), SHIM6);
    registry.put(WESP.value(), WESP);
    registry.put(ROHC.value(), ROHC);
  }

  /**
   * @param value value
   * @param name name
   */
  public IpNumber(Byte value, String name) {
    super(value, name);
  }

  /**
   * @param value value
   * @return a IpNumber object.
   */
  public static IpNumber getInstance(Byte value) {
    if (registry.containsKey(value)) {
      return registry.get(value);
    } else {
      return new IpNumber(value, "unknown");
    }
  }

  /**
   * @param number number
   * @return a IpNumber object.
   */
  public static IpNumber register(IpNumber number) {
    return registry.put(number.value(), number);
  }

  @Override
  public String valueAsString() {
    return String.valueOf(value() & 0xFF);
  }

  @Override
  public int compareTo(IpNumber o) {
    return value().compareTo(o.value());
  }
}
