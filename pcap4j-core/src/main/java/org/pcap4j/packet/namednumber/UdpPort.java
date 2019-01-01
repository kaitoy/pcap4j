/*_##########################################################################
  _##
  _##  Copyright (C) 2011-2019  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.namednumber;

import java.util.HashMap;
import java.util.Map;

/**
 * UDP Port
 *
 * @see <a
 *     href="http://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xml">IANA
 *     Registry</a>
 * @author Kaito Yamada
 * @since pcap4j 0.9.6
 */
public final class UdpPort extends Port {

  /** */
  private static final long serialVersionUID = -7898348444366318292L;

  /** TCP Port Service Multiplexer: 1 */
  public static final UdpPort TCPMUX = new UdpPort((short) 1, "TCP Port Service Multiplexer");

  /** Compressnet Management Utility: 2 */
  public static final UdpPort COMPRESSNET_MANAGEMENT_UTILITY =
      new UdpPort((short) 2, "Compressnet Management Utility");

  /** Compressnet Compression Process: 3 */
  public static final UdpPort COMPRESSNET_COMPRESSION_PROCESS =
      new UdpPort((short) 3, "Compressnet Compression Process");

  /** Remote Job Entry: 5 */
  public static final UdpPort RJE = new UdpPort((short) 5, "Remote Job Entry");

  /** Echo: 7 */
  public static final UdpPort ECHO = new UdpPort((short) 7, "Echo");

  /** Discard: 9 */
  public static final UdpPort DISCARD = new UdpPort((short) 9, "Discard");

  /** systat: 11 */
  public static final UdpPort SYSTAT = new UdpPort((short) 11, "systat");

  /** Daytime: 13 */
  public static final UdpPort DAYTIME = new UdpPort((short) 13, "Daytime");

  /** Quote of the Day: 17 */
  public static final UdpPort QOTD = new UdpPort((short) 17, "Quote of the Day");

  /** Message Send Protocol: 18 */
  public static final UdpPort MSP = new UdpPort((short) 18, "Message Send Protocol");

  /** Character Generator: 19 */
  public static final UdpPort CHARGEN = new UdpPort((short) 19, "Character Generator");

  /** File Transfer [Default Data]: 20 */
  public static final UdpPort FTP_DATA = new UdpPort((short) 20, "File Transfer [Default Data]");

  /** File Transfer [Control]: 21 */
  public static final UdpPort FTP = new UdpPort((short) 21, "File Transfer [Control]");

  /** The Secure Shell (SSH): 22 */
  public static final UdpPort SSH = new UdpPort((short) 22, "SSH");

  /** Telnet: 23 */
  public static final UdpPort TELNET = new UdpPort((short) 23, "Telnet");

  /** Simple Mail Transfer: 25 */
  public static final UdpPort SMTP = new UdpPort((short) 25, "Simple Mail Transfer");

  /** NSW User System FE: 27 */
  public static final UdpPort NSW_FE = new UdpPort((short) 27, "NSW User System FE");

  /** MSG ICP: 29 */
  public static final UdpPort MSG_ICP = new UdpPort((short) 29, "MSG ICP");

  /** MSG Authentication: 31 */
  public static final UdpPort MSG_AUTH = new UdpPort((short) 31, "MSG Authentication");

  /** Display Support Protocol: 33 */
  public static final UdpPort DSP = new UdpPort((short) 33, "Display Support Protocol");

  /** Time: 37 */
  public static final UdpPort TIME = new UdpPort((short) 37, "Time");

  /** Route Access Protocol: 38 */
  public static final UdpPort RAP = new UdpPort((short) 38, "Route Access Protocol");

  /** Resource Location Protocol: 39 */
  public static final UdpPort RLP = new UdpPort((short) 39, "Resource Location Protocol");

  /** Graphics: 41 */
  public static final UdpPort GRAPHICS = new UdpPort((short) 41, "Graphics");

  /** Host Name Server: 42 */
  public static final UdpPort NAMESERVER = new UdpPort((short) 42, "Host Name Server");

  /** Who Is: 43 */
  public static final UdpPort WHOIS = new UdpPort((short) 43, "Who Is");

  /** MPM FLAGS Protocol: 44 */
  public static final UdpPort MPM_FLAGS = new UdpPort((short) 44, "MPM FLAGS Protocol");

  /** Message Processing Module [recv]: 45 */
  public static final UdpPort MPM = new UdpPort((short) 45, "Message Processing Module [recv]");

  /** MPM [default send]: 46 */
  public static final UdpPort MPM_SND = new UdpPort((short) 46, "MPM [default send]");

  /** NI FTP: 47 */
  public static final UdpPort NI_FTP = new UdpPort((short) 47, "NI FTP");

  /** Digital Audit Daemon: 48 */
  public static final UdpPort AUDITD = new UdpPort((short) 48, "Digital Audit Daemon");

  /** Login Host Protocol (TACACS): 49 */
  public static final UdpPort TACACS = new UdpPort((short) 49, "Login Host Protocol (TACACS)");

  /** Remote Mail Checking Protocol: 50 */
  public static final UdpPort RE_MAIL_CK = new UdpPort((short) 50, "Remote Mail Checking Protocol");

  /** XNS Time Protocol: 52 */
  public static final UdpPort XNS_TIME = new UdpPort((short) 52, "XNS Time Protocol");

  /** Domain Name Server: 53 */
  public static final UdpPort DOMAIN = new UdpPort((short) 53, "Domain Name Server");

  /** XNS Clearinghouse: 54 */
  public static final UdpPort XNS_CH = new UdpPort((short) 54, "XNS Clearinghouse");

  /** ISI Graphics Language: 55 */
  public static final UdpPort ISI_GL = new UdpPort((short) 55, "ISI Graphics Language");

  /** XNS Authentication: 56 */
  public static final UdpPort XNS_AUTH = new UdpPort((short) 56, "XNS Authentication");

  /** XNS Mail: 58 */
  public static final UdpPort XNS_MAIL = new UdpPort((short) 58, "XNS Mail");

  /** NI MAIL: 61 */
  public static final UdpPort NI_MAIL = new UdpPort((short) 61, "NI MAIL");

  /** ACA Services: 62 */
  public static final UdpPort ACAS = new UdpPort((short) 62, "ACA Services");

  /** whois++: 63 */
  public static final UdpPort WHOIS_PP = new UdpPort((short) 63, "whois++");

  /** Communications Integrator (CI): 64 */
  public static final UdpPort COVIA = new UdpPort((short) 64, "Communications Integrator (CI)");

  /** TACACS-Database Service: 65 */
  public static final UdpPort TACACS_DS = new UdpPort((short) 65, "TACACS-Database Service");

  /** Oracle SQL*NET: 66 */
  public static final UdpPort ORACLE_SQL_NET = new UdpPort((short) 66, "Oracle SQL*NET");

  /** Bootstrap Protocol Server: 67 */
  public static final UdpPort BOOTPS = new UdpPort((short) 67, "Bootstrap Protocol Server");

  /** Bootstrap Protocol Client: 68 */
  public static final UdpPort BOOTPC = new UdpPort((short) 68, "Bootstrap Protocol Client");

  /** Trivial File Transfer: 69 */
  public static final UdpPort TFTP = new UdpPort((short) 69, "Trivial File Transfer");

  /** Gopher: 70 */
  public static final UdpPort GOPHER = new UdpPort((short) 70, "Gopher");

  /** Remote Job Service 1: 71 */
  public static final UdpPort NETRJS_1 = new UdpPort((short) 71, "Remote Job Service 1");

  /** Remote Job Service 2: 72 */
  public static final UdpPort NETRJS_2 = new UdpPort((short) 72, "Remote Job Service 2");

  /** Remote Job Service 3: 73 */
  public static final UdpPort NETRJS_3 = new UdpPort((short) 73, "Remote Job Service3");

  /** Remote Job Service 4: 74 */
  public static final UdpPort NETRJS_4 = new UdpPort((short) 74, "Remote Job Service 4");

  /** Distributed External Object Store: 76 */
  public static final UdpPort DEOS = new UdpPort((short) 76, "Distributed External Object Store");

  /** vettcp: 78 */
  public static final UdpPort VETTCP = new UdpPort((short) 78, "vettcp");

  /** Finger: 79 */
  public static final UdpPort FINGER = new UdpPort((short) 79, "Finger");

  /** HTTP: 80 */
  public static final UdpPort HTTP = new UdpPort((short) 80, "HTTP");

  /** XFER Utility: 82 */
  public static final UdpPort XFER = new UdpPort((short) 82, "XFER Utility");

  /** MIT ML Device: 83 */
  public static final UdpPort MIT_ML_DEV_83 = new UdpPort((short) 83, "MIT ML Device");

  /** Common Trace Facility: 84 */
  public static final UdpPort CTF = new UdpPort((short) 84, "Common Trace Facility");

  /** MIT ML Device: 85 */
  public static final UdpPort MIT_ML_DEV_85 = new UdpPort((short) 85, "MIT ML Device");

  /** Micro Focus Cobol: 86 */
  public static final UdpPort MFCOBOL = new UdpPort((short) 86, "Micro Focus Cobol");

  /** Kerberos: 88 */
  public static final UdpPort KERBEROS = new UdpPort((short) 88, "Kerberos");

  /** SU/MIT Telnet Gateway: 89 */
  public static final UdpPort SU_MIT_TG = new UdpPort((short) 89, "SU/MIT Telnet Gateway");

  /** DNSIX Securit Attribute Token Map: 90 */
  public static final UdpPort DNSIX = new UdpPort((short) 90, "DNSIX Securit Attribute Token Map");

  /** MIT Dover Spooler: 91 */
  public static final UdpPort MIT_DOV = new UdpPort((short) 91, "MIT Dover Spooler");

  /** Network Printing Protocol: 92 */
  public static final UdpPort NPP = new UdpPort((short) 92, "Network Printing Protocol");

  /** Device Control Protocol: 93 */
  public static final UdpPort DCP = new UdpPort((short) 93, "Device Control Protocol");

  /** Tivoli Object Dispatcher: 94 */
  public static final UdpPort OBJCALL = new UdpPort((short) 94, "Tivoli Object Dispatcher");

  /** SUPDUP: 95 */
  public static final UdpPort SUPDUP = new UdpPort((short) 95, "SUPDUP");

  /** DIXIE Protocol Specification: 96 */
  public static final UdpPort DIXIE = new UdpPort((short) 96, "DIXIE Protocol Specification");

  /** Swift Remote Virtural File Protocol: 97 */
  public static final UdpPort SWIFT_RVF =
      new UdpPort((short) 97, "Swift Remote Virtural File Protocol");

  /** TAC News: 98 */
  public static final UdpPort TACNEWS = new UdpPort((short) 98, "TAC News");

  /** Metagram Relay: 99 */
  public static final UdpPort METAGRAM = new UdpPort((short) 99, "Metagram Relay");

  /** NIC Host Name Server: 101 */
  public static final UdpPort HOSTNAME = new UdpPort((short) 101, "NIC Host Name Server");

  /** ISO-TSAP Class 0: 102 */
  public static final UdpPort ISO_TSAP = new UdpPort((short) 102, "ISO-TSAP Class 0");

  /** Genesis Point-to-Point Trans Net: 103 */
  public static final UdpPort GPPITNP =
      new UdpPort((short) 103, "Genesis Point-to-Point Trans Net");

  /** ACR-NEMA Digital Imag. &amp; Comm. 300: 104 */
  public static final UdpPort ACR_NEMA =
      new UdpPort((short) 104, "ACR-NEMA Digital Imag. & Comm. 300");

  /** CCSO Nameserver protocol: 105 */
  public static final UdpPort CSO = new UdpPort((short) 105, "CCSO Nameserver protocol");

  /** 3COM-TSMUX: 106 */
  public static final UdpPort UDP_3COM_TSMUX = new UdpPort((short) 106, "3COM-TSMUX");

  /** Remote Telnet Service: 107 */
  public static final UdpPort RTELNET = new UdpPort((short) 107, "Remote Telnet Service");

  /** SNA Gateway Access Server: 108 */
  public static final UdpPort SNAGAS = new UdpPort((short) 108, "SNA Gateway Access Server");

  /** Post Office Protocol - Version 2: 109 */
  public static final UdpPort POP2 = new UdpPort((short) 109, "Post Office Protocol - Version 2");

  /** Post Office Protocol - Version 3: 110 */
  public static final UdpPort POP3 = new UdpPort((short) 110, "Post Office Protocol - Version 3");

  /** SUN Remote Procedure Call: 111 */
  public static final UdpPort SUNRPC = new UdpPort((short) 111, "SUN Remote Procedure Call");

  /** McIDAS Data Transmission Protocol: 112 */
  public static final UdpPort MCIDAS =
      new UdpPort((short) 112, "McIDAS Data Transmission Protocol");

  /** Authentication Service: 113 */
  public static final UdpPort AUTH = new UdpPort((short) 113, "Authentication Service");

  /** Simple File Transfer Protocol: 115 */
  public static final UdpPort SFTP = new UdpPort((short) 115, "Simple File Transfer Protocol");

  /** ANSA REX Notify: 116 */
  public static final UdpPort ANSANOTIFY = new UdpPort((short) 116, "ANSA REX Notify");

  /** UUCP Path Service: 117 */
  public static final UdpPort UUCP_PATH = new UdpPort((short) 117, "UUCP Path Service");

  /** SQL Services: 118 */
  public static final UdpPort SQLSERV = new UdpPort((short) 118, "SQL Services");

  /** Network News Transfer Protocol: 119 */
  public static final UdpPort NNTP = new UdpPort((short) 119, "Network News Transfer Protocol");

  /** CFDPTKT: 120 */
  public static final UdpPort CFDPTKT = new UdpPort((short) 120, "CFDPTKT");

  /** Encore Expedited Remote Pro.Call: 121 */
  public static final UdpPort ERPC = new UdpPort((short) 121, "Encore Expedited Remote Pro.Call");

  /** SMAKYNET: 122 */
  public static final UdpPort SMAKYNET = new UdpPort((short) 122, "SMAKYNET");

  /** Network Time Protocol: 123 */
  public static final UdpPort NTP = new UdpPort((short) 123, "Network Time Protocol");

  /** ANSA REX Trader: 124 */
  public static final UdpPort ANSATRADER = new UdpPort((short) 124, "ANSA REX Trader");

  /** Locus PC-Interface Net Map Ser: 125 */
  public static final UdpPort LOCUS_MAP =
      new UdpPort((short) 125, "Locus PC-Interface Net Map Ser");

  /** NXEdit: 126 */
  public static final UdpPort NXEDIT = new UdpPort((short) 126, "NXEdit");

  /** Locus PC-Interface Conn Server: 127 */
  public static final UdpPort LOCUS_CON =
      new UdpPort((short) 127, "Locus PC-Interface Conn Server");

  /** GSS X License Verification: 128 */
  public static final UdpPort GSS_XLICEN = new UdpPort((short) 128, "GSS X License Verification");

  /** Password Generator Protocol: 129 */
  public static final UdpPort PWDGEN = new UdpPort((short) 129, "Password Generator Protocol");

  /** Cisco FNATIVE: 130 */
  public static final UdpPort CISCO_FNA = new UdpPort((short) 130, "Cisco FNATIVE");

  /** Cisco TNATIVE: 131 */
  public static final UdpPort CISCO_TNA = new UdpPort((short) 131, "Cisco TNATIVE");

  /** Cisco SYSMAINT: 132 */
  public static final UdpPort CISCO_SYS = new UdpPort((short) 132, "Cisco SYSMAINT");

  /** Statistics Service: 133 */
  public static final UdpPort STATSRV = new UdpPort((short) 133, "Statistics Service");

  /** INGRES-NET Service: 134 */
  public static final UdpPort INGRES_NET = new UdpPort((short) 134, "INGRES-NET Service");

  /** DCE endpoint resolution: 135 */
  public static final UdpPort EPMAP = new UdpPort((short) 135, "DCE endpoint resolution");

  /** PROFILE Naming System: 136 */
  public static final UdpPort PROFILE = new UdpPort((short) 136, "PROFILE Naming System");

  /** NETBIOS Name Service: 137 */
  public static final UdpPort NETBIOS_NS = new UdpPort((short) 137, "NETBIOS Name Service");

  /** NETBIOS Datagram Service: 138 */
  public static final UdpPort NETBIOS_DGM = new UdpPort((short) 138, "NETBIOS Datagram Service");

  /** NETBIOS Session Service: 139 */
  public static final UdpPort NETBIOS_SSN = new UdpPort((short) 139, "NETBIOS Session Service");

  /** EMFIS Data Service: 140 */
  public static final UdpPort EMFIS_DATA = new UdpPort((short) 140, "EMFIS Data Service");

  /** EMFIS Control Service: 141 */
  public static final UdpPort EMFIS_CNTL = new UdpPort((short) 141, "EMFIS Control Service");

  /** Britton-Lee IDM: 142 */
  public static final UdpPort BL_IDM = new UdpPort((short) 142, "Britton-Lee IDM");

  /** Internet Message Access Protocol: 143 */
  public static final UdpPort IMAP = new UdpPort((short) 143, "Internet Message Access Protocol");

  /** Universal Management Architecture: 144 */
  public static final UdpPort UMA = new UdpPort((short) 144, "Universal Management Architecture");

  /** UAAC Protocol: 145 */
  public static final UdpPort UAAC = new UdpPort((short) 145, "UAAC Protocol");

  /** ISO-IP0: 146 */
  public static final UdpPort ISO_TP0 = new UdpPort((short) 146, "ISO-IP0");

  /** ISO-IP: 147 */
  public static final UdpPort ISO_IP = new UdpPort((short) 147, "ISO-IP");

  /** Jargon: 148 */
  public static final UdpPort JARGON = new UdpPort((short) 148, "Jargon");

  /** AED 512 Emulation Service: 149 */
  public static final UdpPort AED_512 = new UdpPort((short) 149, "AED 512 Emulation Service");

  /** SQL-NET: 150 */
  public static final UdpPort SQL_NET = new UdpPort((short) 150, "SQL-NET");

  /** HEMS: 151 */
  public static final UdpPort HEMS = new UdpPort((short) 151, "HEMS");

  /** Background File Transfer Program: 152 */
  public static final UdpPort BFTP = new UdpPort((short) 152, "Background File Transfer Program");

  /** SGMP: 153 */
  public static final UdpPort SGMP = new UdpPort((short) 153, "SGMP");

  /** NETSC: 154 */
  public static final UdpPort NETSC_PROD = new UdpPort((short) 154, "NETSC");

  /** NETSC: 155 */
  public static final UdpPort NETSC_DEV = new UdpPort((short) 155, "NETSC");

  /** SQL Service: 156 */
  public static final UdpPort SQLSRV = new UdpPort((short) 156, "SQL Service");

  /** KNET/VM Command/Message Protocol: 157 */
  public static final UdpPort KNET_CMP =
      new UdpPort((short) 157, "KNET/VM Command/Message Protocol");

  /** PCMail Server: 158 */
  public static final UdpPort PCMAIL_SRV = new UdpPort((short) 158, "PCMail Server");

  /** NSS-Routing: 159 */
  public static final UdpPort NSS_ROUTING = new UdpPort((short) 159, "NSS-Routing");

  /** SGMP-TRAPS: 160 */
  public static final UdpPort SGMP_TRAPS = new UdpPort((short) 160, "SGMP-TRAPS");

  /** SNMP: 161 */
  public static final UdpPort SNMP = new UdpPort((short) 161, "SNMP");

  /** SNMP Trap: 162 */
  public static final UdpPort SNMP_TRAP = new UdpPort((short) 162, "SNMP Trap");

  /** CMIP/TCP Manager: 163 */
  public static final UdpPort CMIP_MAN = new UdpPort((short) 163, "CMIP/TCP Manager");

  /** CMIP/TCP Agent: 164 */
  public static final UdpPort CMIP_AGENT = new UdpPort((short) 164, "CMIP/TCP Agent");

  /** XNS Courier: 165 */
  public static final UdpPort XNS_COURIER = new UdpPort((short) 165, "XNS Courier");

  /** Sirius Systems: 166 */
  public static final UdpPort S_NET = new UdpPort((short) 166, "Sirius Systems");

  /** NAMP: 167 */
  public static final UdpPort NAMP = new UdpPort((short) 167, "NAMP");

  /** RSVD: 168 */
  public static final UdpPort RSVD = new UdpPort((short) 168, "RSVD");

  /** SEND: 169 */
  public static final UdpPort SEND = new UdpPort((short) 169, "SEND");

  /** Network PostScript: 170 */
  public static final UdpPort PRINT_SRV = new UdpPort((short) 170, "Network PostScript");

  /** Network Innovations Multiplex: 171 */
  public static final UdpPort MULTIPLEX = new UdpPort((short) 171, "Network Innovations Multiplex");

  /** Network Innovations CL/1: 172 */
  public static final UdpPort CL_1 = new UdpPort((short) 172, "Network Innovations CL/1");

  /** Xyplex: 173 */
  public static final UdpPort XYPLEX_MUX = new UdpPort((short) 173, "Xyplex");

  /** MAILQ: 174 */
  public static final UdpPort MAILQ = new UdpPort((short) 174, "MAILQ");

  /** VMNET: 175 */
  public static final UdpPort VMNET = new UdpPort((short) 175, "VMNET");

  /** GENRAD-MUX: 176 */
  public static final UdpPort GENRAD_MUX = new UdpPort((short) 176, "GENRAD-MUX");

  /** X Display Manager Control Protocol: 177 */
  public static final UdpPort XDMCP =
      new UdpPort((short) 177, "X Display Manager Control Protocol");

  /** NextStep Window Server: 178 */
  public static final UdpPort NEXTSTEP = new UdpPort((short) 178, "NextStep Window Server");

  /** Border Gateway Protocol: 179 */
  public static final UdpPort BGP = new UdpPort((short) 179, "Border Gateway Protocol");

  /** Intergraph: 180 */
  public static final UdpPort RIS = new UdpPort((short) 180, "Intergraph");

  /** Unify: 181 */
  public static final UdpPort UNIFY = new UdpPort((short) 181, "Unify");

  /** Unisys Audit SITP: 182 */
  public static final UdpPort AUDIT = new UdpPort((short) 182, "Unisys Audit SITP");

  /** OCBinder: 183 */
  public static final UdpPort OCBINDER = new UdpPort((short) 183, "OCBinder");

  /** OCServer: 184 */
  public static final UdpPort OCSERVER = new UdpPort((short) 184, "OCServer");

  /** Remote-KIS: 185 */
  public static final UdpPort REMOTE_KIS = new UdpPort((short) 185, "Remote-KIS");

  /** KIS Protocol: 186 */
  public static final UdpPort KIS = new UdpPort((short) 186, "KIS Protocol");

  /** Application Communication Interface: 187 */
  public static final UdpPort ACI = new UdpPort((short) 187, "Application Communication Interface");

  /** Plus Five's MUMPS: 188 */
  public static final UdpPort MUMPS = new UdpPort((short) 188, "Plus Five's MUMPS");

  /** Queued File Transport: 189 */
  public static final UdpPort QFT = new UdpPort((short) 189, "Queued File Transport");

  /** Gateway Access Control Protocol: 190 */
  public static final UdpPort GACP = new UdpPort((short) 190, "Gateway Access Control Protocol");

  /** Prospero Directory Service: 191 */
  public static final UdpPort PROSPERO = new UdpPort((short) 191, "Prospero Directory Service");

  /** OSU Network Monitoring System: 192 */
  public static final UdpPort OSU_NMS = new UdpPort((short) 192, "OSU Network Monitoring System");

  /** Spider Remote Monitoring Protocol: 193 */
  public static final UdpPort SRMP = new UdpPort((short) 193, "Spider Remote Monitoring Protocol");

  /** Internet Relay Chat Protocol: 194 */
  public static final UdpPort IRC = new UdpPort((short) 194, "Internet Relay Chat Protocol");

  /** DNSIX Network Level Module Audit: 195 */
  public static final UdpPort DN6_NLM_AUD =
      new UdpPort((short) 195, "DNSIX Network Level Module Audit");

  /** DNSIX Session Mgt Module Audit Redir: 196 */
  public static final UdpPort DN6_SMM_RED =
      new UdpPort((short) 196, "DNSIX Session Mgt Module Audit Redir");

  /** Directory Location Service: 197 */
  public static final UdpPort DLS = new UdpPort((short) 197, "Directory Location Service");

  /** Directory Location Service Monitor: 198 */
  public static final UdpPort DLS_MON =
      new UdpPort((short) 198, "Directory Location Service Monitor");

  /** SMUX: 199 */
  public static final UdpPort SMUX = new UdpPort((short) 199, "SMUX");

  /** IBM System Resource Controller: 200 */
  public static final UdpPort SRC = new UdpPort((short) 200, "IBM System Resource Controller");

  /** AppleTalk Routing Maintenance: 201 */
  public static final UdpPort AT_RTMP = new UdpPort((short) 201, "AppleTalk Routing Maintenance");

  /** AppleTalk Name Binding: 202 */
  public static final UdpPort AT_NBP = new UdpPort((short) 202, "AppleTalk Name Binding");

  /** AppleTalk Unused: 203 */
  public static final UdpPort AT_3 = new UdpPort((short) 203, "AppleTalk Unused");

  /** AppleTalk Echo: 204 */
  public static final UdpPort AT_ECHO = new UdpPort((short) 204, "AppleTalk Echo");

  /** AppleTalk Unused: 205 */
  public static final UdpPort AT_5 = new UdpPort((short) 205, "AppleTalk Unused");

  /** AppleTalk Zone Information: 206 */
  public static final UdpPort AT_ZIS = new UdpPort((short) 206, "AppleTalk Zone Information");

  /** AppleTalk Unused: 207 */
  public static final UdpPort AT_7 = new UdpPort((short) 207, "AppleTalk Unused");

  /** AppleTalk Unused: 208 */
  public static final UdpPort AT_8 = new UdpPort((short) 208, "AppleTalk Unused");

  /** The Quick Mail Transfer Protocol: 209 */
  public static final UdpPort QMTP = new UdpPort((short) 209, "The Quick Mail Transfer Protocol");

  /** ANSI Z39.50: 210 */
  public static final UdpPort Z39_50 = new UdpPort((short) 210, "ANSI Z39.50");

  /** Texas Instruments 914C/G Terminal: 211 */
  public static final UdpPort TEXAS_INSTRUMENTS_914C_G =
      new UdpPort((short) 211, "Texas Instruments 914C/G Terminal");

  /** ATEXSSTR: 212 */
  public static final UdpPort ANET = new UdpPort((short) 212, "ATEXSSTR");

  /** IPX: 213 */
  public static final UdpPort IPX = new UdpPort((short) 213, "IPX");

  /** VM PWSCS: 214 */
  public static final UdpPort VMPWSCS = new UdpPort((short) 214, "VM PWSCS");

  /** Insignia Solutions SoftPC: 215 */
  public static final UdpPort SOFTPC = new UdpPort((short) 215, "Insignia Solutions SoftPC");

  /** Computer Associates Int'l License Server: 216 */
  public static final UdpPort CAILIC =
      new UdpPort((short) 216, "Computer Associates Int'l License Server");

  /** dBASE Unix: 217 */
  public static final UdpPort DBASE = new UdpPort((short) 217, "dBASE Unix");

  /** Netix Message Posting Protocol: 218 */
  public static final UdpPort MPP = new UdpPort((short) 218, "Netix Message Posting Protocol");

  /** Unisys ARPs: 219 */
  public static final UdpPort UARPS = new UdpPort((short) 219, "Unisys ARPs");

  /** Interactive Mail Access Protocol v3: 220 */
  public static final UdpPort IMAP3 =
      new UdpPort((short) 220, "Interactive Mail Access Protocol v3");

  /** Berkeley rlogind with SPX auth: 221 */
  public static final UdpPort FLN_SPX = new UdpPort((short) 221, "Berkeley rlogind with SPX auth");

  /** Berkeley rshd with SPX auth: 222 */
  public static final UdpPort RSH_SPX = new UdpPort((short) 222, "Berkeley rshd with SPX auth");

  /** Certificate Distribution Center: 223 */
  public static final UdpPort CDC = new UdpPort((short) 223, "Certificate Distribution Center");

  /** masqdialer: 224 */
  public static final UdpPort MASQDIALER = new UdpPort((short) 224, "masqdialer");

  /** Direct: 242 */
  public static final UdpPort DIRECT = new UdpPort((short) 242, "Direct");

  /** Survey Measurement: 243 */
  public static final UdpPort SUR_MEAS = new UdpPort((short) 243, "Survey Measurement");

  /** inbusiness: 244 */
  public static final UdpPort INBUSINESS = new UdpPort((short) 244, "inbusiness");

  /** LINK: 245 */
  public static final UdpPort LINK = new UdpPort((short) 245, "LINK");

  /** Display Systems Protocol: 246 */
  public static final UdpPort DSP3270 = new UdpPort((short) 246, "Display Systems Protocol");

  /** SUBNTBCST_TFTP: 247 */
  public static final UdpPort SUBNTBCST_TFTP = new UdpPort((short) 247, "SUBNTBCST_TFTP");

  /** bhfhs: 248 */
  public static final UdpPort BHFHS = new UdpPort((short) 248, "bhfhs");

  /** Secure Electronic Transaction: 257 */
  public static final UdpPort SET = new UdpPort((short) 257, "Secure Electronic Transaction");

  /** Efficient Short Remote Operations: 259 */
  public static final UdpPort ESRO_GEN =
      new UdpPort((short) 259, "Efficient Short Remote Operations");

  /** Openport: 260 */
  public static final UdpPort OPENPORT = new UdpPort((short) 260, "Openport");

  /** IIOP Name Service over TLS/SSL: 261 */
  public static final UdpPort NSIIOPS = new UdpPort((short) 261, "IIOP Name Service over TLS/SSL");

  /** Arcisdms: 262 */
  public static final UdpPort ARCISDMS = new UdpPort((short) 262, "Arcisdms");

  /** HDAP: 263 */
  public static final UdpPort HDAP = new UdpPort((short) 263, "HDAP");

  /** BGMP: 264 */
  public static final UdpPort BGMP = new UdpPort((short) 264, "BGMP");

  /** X-Bone CTL: 265 */
  public static final UdpPort X_BONE_CTL = new UdpPort((short) 265, "X-Bone CTL");

  /** SCSI on ST: 266 */
  public static final UdpPort SST = new UdpPort((short) 266, "SCSI on ST");

  /** Tobit David Service Layer: 267 */
  public static final UdpPort TD_SERVICE = new UdpPort((short) 267, "Tobit David Service Layer");

  /** Tobit David Replica: 268 */
  public static final UdpPort TD_REPLICA = new UdpPort((short) 268, "Tobit David Replica");

  /** MANET Protocols: 269 */
  public static final UdpPort MANET = new UdpPort((short) 269, "MANET Protocols");

  /** Q-mode encapsulation for GIST messages: 270 */
  public static final UdpPort GIST =
      new UdpPort((short) 270, "Q-mode encapsulation for GIST messages");

  /** HTTP-Mgmt: 280 */
  public static final UdpPort HTTP_MGMT = new UdpPort((short) 280, "HTTP-Mgmt");

  /** Personal Link: 281 */
  public static final UdpPort PERSONAL_LINK = new UdpPort((short) 281, "Personal Link");

  /** Cable Port A/X: 282 */
  public static final UdpPort CABLEPORT_AX = new UdpPort((short) 282, "Cable Port A/X");

  /** rescap: 283 */
  public static final UdpPort RESCAP = new UdpPort((short) 283, "rescap");

  /** corerjd: 284 */
  public static final UdpPort CORERJD = new UdpPort((short) 284, "corerjd");

  /** FXP Communication: 286 */
  public static final UdpPort FXP = new UdpPort((short) 286, "FXP Communication");

  /** K-BLOCK: 287 */
  public static final UdpPort K_BLOCK = new UdpPort((short) 287, "K-BLOCK");

  /** Novastor Backup: 308 */
  public static final UdpPort NOVASTORBAKCUP = new UdpPort((short) 308, "Novastor Backup");

  /** EntrustTime: 309 */
  public static final UdpPort ENTRUSTTIME = new UdpPort((short) 309, "EntrustTime");

  /** bhmds: 310 */
  public static final UdpPort BHMDS = new UdpPort((short) 310, "bhmds");

  /** AppleShare IP WebAdmin: 311 */
  public static final UdpPort ASIP_WEBADMIN = new UdpPort((short) 311, "AppleShare IP WebAdmin");

  /** VSLMP: 312 */
  public static final UdpPort VSLMP = new UdpPort((short) 312, "VSLMP");

  /** Magenta Logic: 313 */
  public static final UdpPort MAGENTA_LOGIC = new UdpPort((short) 313, "Magenta Logic");

  /** Opalis Robot: 314 */
  public static final UdpPort OPALIS_ROBOT = new UdpPort((short) 314, "Opalis Robot");

  /** DPSI: 315 */
  public static final UdpPort DPSI = new UdpPort((short) 315, "DPSI");

  /** decAuth: 316 */
  public static final UdpPort DECAUTH = new UdpPort((short) 316, "decAuth");

  /** Zannet: 317 */
  public static final UdpPort ZANNET = new UdpPort((short) 317, "Zannet");

  /** PKIX TimeStamp: 318 */
  public static final UdpPort PKIX_TIMESTAMP = new UdpPort((short) 318, "PKIX TimeStamp");

  /** PTP Event: 319 */
  public static final UdpPort PTP_EVENT = new UdpPort((short) 319, "PTP Event");

  /** PTP General: 320 */
  public static final UdpPort PTP_GENERAL = new UdpPort((short) 320, "PTP General");

  /** PIP: 321 */
  public static final UdpPort PIP = new UdpPort((short) 321, "PIP");

  /** RTSPS: 322 */
  public static final UdpPort RTSPS = new UdpPort((short) 322, "RTSPS");

  /** Texar Security Port: 333 */
  public static final UdpPort TEXAR = new UdpPort((short) 333, "Texar Security Port");

  /** Prospero Data Access Protocol: 344 */
  public static final UdpPort PDAP = new UdpPort((short) 344, "Prospero Data Access Protocol");

  /** Perf Analysis Workbench: 345 */
  public static final UdpPort PAWSERV = new UdpPort((short) 345, "Perf Analysis Workbench");

  /** Zebra server: 346 */
  public static final UdpPort ZSERV = new UdpPort((short) 346, "Zebra server");

  /** Fatmen Server: 347 */
  public static final UdpPort FATSERV = new UdpPort((short) 347, "Fatmen Server");

  /** Cabletron Management Protocol: 348 */
  public static final UdpPort CSI_SGWP = new UdpPort((short) 348, "Cabletron Management Protocol");

  /** mftp: 349 */
  public static final UdpPort MFTP = new UdpPort((short) 349, "mftp");

  /** MATIP Type A: 350 */
  public static final UdpPort MATIP_TYPE_A = new UdpPort((short) 350, "MATIP Type A");

  /** MATIP Type B: 351 */
  public static final UdpPort MATIP_TYPE_B = new UdpPort((short) 351, "MATIP Type B");

  /** DTAG: 352 */
  public static final UdpPort DTAG_STE_SB = new UdpPort((short) 352, "DTAG");

  /** NDSAUTH: 353 */
  public static final UdpPort NDSAUTH = new UdpPort((short) 353, "NDSAUTH");

  /** bh611: 354 */
  public static final UdpPort BH611 = new UdpPort((short) 354, "bh611");

  /** DATEX-ASN: 355 */
  public static final UdpPort DATEX_ASN = new UdpPort((short) 355, "DATEX-ASN");

  /** Cloanto Net 1: 356 */
  public static final UdpPort CLOANTO_NET_1 = new UdpPort((short) 356, "Cloanto Net 1");

  /** bhevent: 357 */
  public static final UdpPort BHEVENT = new UdpPort((short) 357, "bhevent");

  /** Shrinkwrap: 358 */
  public static final UdpPort SHRINKWRAP = new UdpPort((short) 358, "Shrinkwrap");

  /** Network Security Risk Management Protocol: 359 */
  public static final UdpPort NSRMP =
      new UdpPort((short) 359, "Network Security Risk Management Protocol");

  /** scoi2odialog: 360 */
  public static final UdpPort SCOI2ODIALOG = new UdpPort((short) 360, "scoi2odialog");

  /** Semantix: 361 */
  public static final UdpPort SEMANTIX = new UdpPort((short) 361, "Semantix");

  /** SRS Send: 362 */
  public static final UdpPort SRSSEND = new UdpPort((short) 362, "SRS Send");

  /** RSVP Tunnel: 363 */
  public static final UdpPort RSVP_TUNNEL = new UdpPort((short) 363, "RSVP Tunnel");

  /** Aurora CMGR: 364 */
  public static final UdpPort AURORA_CMGR = new UdpPort((short) 364, "Aurora CMGR");

  /** DTK: 365 */
  public static final UdpPort DTK = new UdpPort((short) 365, "DTK");

  /** ODMR: 366 */
  public static final UdpPort ODMR = new UdpPort((short) 366, "ODMR");

  /** MortgageWare: 367 */
  public static final UdpPort MORTGAGEWARE = new UdpPort((short) 367, "MortgageWare");

  /** QbikGDP: 368 */
  public static final UdpPort QBIKGDP = new UdpPort((short) 368, "QbikGDP");

  /** rpc2portmap: 369 */
  public static final UdpPort RPC2PORTMAP = new UdpPort((short) 369, "rpc2portmap");

  /** codaauth2: 370 */
  public static final UdpPort CODAAUTH2 = new UdpPort((short) 370, "codaauth2");

  /** Clearcase: 371 */
  public static final UdpPort CLEARCASE = new UdpPort((short) 371, "Clearcase");

  /** ListProcessor: 372 */
  public static final UdpPort ULISTPROC = new UdpPort((short) 372, "ListProcessor");

  /** Legent Corporation: 373 */
  public static final UdpPort LEGENT_1 = new UdpPort((short) 373, "Legent Corporation");

  /** Legent Corporation: 374 */
  public static final UdpPort LEGENT_2 = new UdpPort((short) 374, "Legent Corporation");

  /** Hassle: 375 */
  public static final UdpPort HASSLE = new UdpPort((short) 375, "Hassle");

  /** Amiga Envoy Network Inquiry Proto: 376 */
  public static final UdpPort NIP = new UdpPort((short) 376, "Amiga Envoy Network Inquiry Proto");

  /** NEC Corporation tnETOS: 377 */
  public static final UdpPort TNETOS = new UdpPort((short) 377, "tnETOS");

  /** NEC Corporation dsETOS: 378 */
  public static final UdpPort DSETOS = new UdpPort((short) 378, "dsETOS");

  /** TIA/EIA/IS-99 modem client: 379 */
  public static final UdpPort IS99C = new UdpPort((short) 379, "TIA/EIA/IS-99 modem client");

  /** TIA/EIA/IS-99 modem server: 380 */
  public static final UdpPort IS99S = new UdpPort((short) 380, "TIA/EIA/IS-99 modem server");

  /** HP performance data collector: 381 */
  public static final UdpPort HP_COLLECTOR =
      new UdpPort((short) 381, "HP performance data collector");

  /** HP performance data managed node: 382 */
  public static final UdpPort HP_MANAGED_NODE =
      new UdpPort((short) 382, "HP performance data managed node");

  /** HP performance data alarm manager: 383 */
  public static final UdpPort HP_ALARM_MGR =
      new UdpPort((short) 383, "HP performance data alarm manager");

  /** A Remote Network Server System: 384 */
  public static final UdpPort ARNS = new UdpPort((short) 384, "A Remote Network Server System");

  /** IBM Application: 385 */
  public static final UdpPort IBM_APP = new UdpPort((short) 385, "IBM Application");

  /** ASA Message Router Object Def.: 386 */
  public static final UdpPort ASA = new UdpPort((short) 386, "ASA Message Router Object Def.");

  /** Appletalk Update-Based Routing Pro.: 387 */
  public static final UdpPort AURP =
      new UdpPort((short) 387, "Appletalk Update-Based Routing Pro.");

  /** Unidata LDM: 388 */
  public static final UdpPort UNIDATA_LDM = new UdpPort((short) 388, "Unidata LDM");

  /** Lightweight Directory Access Protocol: 389 */
  public static final UdpPort LDAP =
      new UdpPort((short) 389, "Lightweight Directory Access Protocol");

  /** UIS: 390 */
  public static final UdpPort UIS = new UdpPort((short) 390, "UIS");

  /** SynOptics SNMP Relay Port: 391 */
  public static final UdpPort SYNOTICS_RELAY =
      new UdpPort((short) 391, "SynOptics SNMP Relay Port");

  /** SynOptics Port Broker Port: 392 */
  public static final UdpPort SYNOTICS_BROKER =
      new UdpPort((short) 392, "SynOptics Port Broker Port");

  /** Meta5: 393 */
  public static final UdpPort META5 = new UdpPort((short) 393, "Meta5");

  /** EMBL Nucleic Data Transfer: 394 */
  public static final UdpPort EMBL_NDT = new UdpPort((short) 394, "EMBL Nucleic Data Transfer");

  /** NetScout Control Protocol: 395 */
  public static final UdpPort NETCP = new UdpPort((short) 395, "NetScout Control Protocol");

  /** Novell Netware over IP: 396 */
  public static final UdpPort NETWARE_IP = new UdpPort((short) 396, "Novell Netware over IP");

  /** Multi Protocol Trans. Net.: 397 */
  public static final UdpPort MPTN = new UdpPort((short) 397, "Multi Protocol Trans. Net.");

  /** Kryptolan: 398 */
  public static final UdpPort KRYPTOLAN = new UdpPort((short) 398, "Kryptolan");

  /** ISO Transport Class 2 Non-Control over UDP: 399 */
  public static final UdpPort ISO_TSAP_C2 =
      new UdpPort((short) 399, "ISO Transport Class 2 Non-Control over UDP");

  /** Oracle Secure Backup: 400 */
  public static final UdpPort OSB_SD = new UdpPort((short) 400, "Oracle Secure Backup");

  /** Uninterruptible Power Supply: 401 */
  public static final UdpPort UPS = new UdpPort((short) 401, "Uninterruptible Power Supply");

  /** Genie Protocol: 402 */
  public static final UdpPort GENIE = new UdpPort((short) 402, "Genie Protocol");

  /** decap: 403 */
  public static final UdpPort DECAP = new UdpPort((short) 403, "decap");

  /** nced: 404 */
  public static final UdpPort NCED = new UdpPort((short) 404, "nced");

  /** ncld: 405 */
  public static final UdpPort NCLD = new UdpPort((short) 405, "ncld");

  /** Interactive Mail Support Protocol: 406 */
  public static final UdpPort IMSP = new UdpPort((short) 406, "Interactive Mail Support Protocol");

  /** Timbuktu: 407 */
  public static final UdpPort TIMBUKTU = new UdpPort((short) 407, "Timbuktu");

  /** Prospero Resource Manager Sys. Man.: 408 */
  public static final UdpPort PRM_SM =
      new UdpPort((short) 408, "Prospero Resource Manager Sys. Man.");

  /** Prospero Resource Manager Node Man.: 409 */
  public static final UdpPort PRM_NM =
      new UdpPort((short) 409, "Prospero Resource Manager Node Man.");

  /** DECLadebug Remote Debug Protocol: 410 */
  public static final UdpPort DECLADEBUG =
      new UdpPort((short) 410, "DECLadebug Remote Debug Protocol");

  /** Remote MT Protocol: 411 */
  public static final UdpPort RMT = new UdpPort((short) 411, "Remote MT Protocol");

  /** Trap Convention Port: 412 */
  public static final UdpPort SYNOPTICS_TRAP = new UdpPort((short) 412, "Trap Convention Port");

  /** Storage Management Services Protocol: 413 */
  public static final UdpPort SMSP =
      new UdpPort((short) 413, "Storage Management Services Protocol");

  /** InfoSeek: 414 */
  public static final UdpPort INFOSEEK = new UdpPort((short) 414, "InfoSeek");

  /** BNet: 415 */
  public static final UdpPort BNET = new UdpPort((short) 415, "BNet");

  /** Silverplatter: 416 */
  public static final UdpPort SILVERPLATTER = new UdpPort((short) 416, "Silverplatter");

  /** Onmux: 417 */
  public static final UdpPort ONMUX = new UdpPort((short) 417, "Onmux");

  /** Hyper-G: 418 */
  public static final UdpPort HYPER_G = new UdpPort((short) 418, "Hyper-G");

  /** Ariel 1: 419 */
  public static final UdpPort ARIEL1 = new UdpPort((short) 419, "Ariel 1");

  /** SMPTE: 420 */
  public static final UdpPort SMPTE = new UdpPort((short) 420, "SMPTE");

  /** Ariel 2: 421 */
  public static final UdpPort ARIEL2 = new UdpPort((short) 421, "Ariel 2");

  /** Ariel 3: 422 */
  public static final UdpPort ARIEL3 = new UdpPort((short) 422, "Ariel 3");

  /** IBM Operations Planning and Control Start: 423 */
  public static final UdpPort OPC_JOB_START =
      new UdpPort((short) 423, "IBM Operations Planning and Control Start");

  /** IBM Operations Planning and Control Track: 424 */
  public static final UdpPort OPC_JOB_TRACK =
      new UdpPort((short) 424, "IBM Operations Planning and Control Track");

  /** ICAD: 425 */
  public static final UdpPort ICAD_EL = new UdpPort((short) 425, "ICAD");

  /** smartsdp: 426 */
  public static final UdpPort SMARTSDP = new UdpPort((short) 426, "smartsdp");

  /** Server Location: 427 */
  public static final UdpPort SVRLOC = new UdpPort((short) 427, "Server Location");

  /** OCS_CMU: 428 */
  public static final UdpPort OCS_CMU = new UdpPort((short) 428, "OCS_CMU");

  /** OCS_AMU: 429 */
  public static final UdpPort OCS_AMU = new UdpPort((short) 429, "OCS_AMU");

  /** UTMPSD: 430 */
  public static final UdpPort UTMPSD = new UdpPort((short) 430, "UTMPSD");

  /** UTMPCD: 431 */
  public static final UdpPort UTMPCD = new UdpPort((short) 431, "UTMPCD");

  /** IASD: 432 */
  public static final UdpPort IASD = new UdpPort((short) 432, "IASD");

  /** NNSP: 433 */
  public static final UdpPort NNSP = new UdpPort((short) 433, "NNSP");

  /** MobileIP-Agent: 434 */
  public static final UdpPort MOBILEIP_AGENT = new UdpPort((short) 434, "MobileIP-Agent");

  /** MobilIP-MN: 435 */
  public static final UdpPort MOBILIP_MN = new UdpPort((short) 435, "MobilIP-MN");

  /** DNA-CML: 436 */
  public static final UdpPort DNA_CML = new UdpPort((short) 436, "DNA-CML");

  /** comscm: 437 */
  public static final UdpPort COMSCM = new UdpPort((short) 437, "comscm");

  /** dsfgw: 438 */
  public static final UdpPort DSFGW = new UdpPort((short) 438, "dsfgw");

  /** dasp: 439 */
  public static final UdpPort DASP = new UdpPort((short) 439, "dasp");

  /** sgcp: 440 */
  public static final UdpPort SGCP = new UdpPort((short) 440, "sgcp");

  /** decvms-sysmgt: 441 */
  public static final UdpPort DECVMS_SYSMGT = new UdpPort((short) 441, "decvms-sysmgt");

  /** cvc_hostd: 442 */
  public static final UdpPort CVC_HOSTD = new UdpPort((short) 442, "cvc_hostd");

  /** HTTPS: 443 */
  public static final UdpPort HTTPS = new UdpPort((short) 443, "HTTPS");

  /** Simple Network Paging Protocol: 444 */
  public static final UdpPort SNPP = new UdpPort((short) 444, "Simple Network Paging Protocol");

  /** Microsoft-DS: 445 */
  public static final UdpPort MICROSOFT_DS = new UdpPort((short) 445, "Microsoft-DS");

  /** DDM-Remote Relational Database Access: 446 */
  public static final UdpPort DDM_RDB =
      new UdpPort((short) 446, "DDM-Remote Relational Database Access");

  /** DDM-Distributed File Management: 447 */
  public static final UdpPort DDM_DFM = new UdpPort((short) 447, "DDM-Distributed File Management");

  /** DDM-Remote DB Access Using Secure Sockets: 448 */
  public static final UdpPort DDM_SSL =
      new UdpPort((short) 448, "DDM-Remote DB Access Using Secure Sockets");

  /** AS Server Mapper: 449 */
  public static final UdpPort AS_SERVERMAP = new UdpPort((short) 449, "AS Server Mapper");

  /** Computer Supported Telecomunication Applications: 450 */
  public static final UdpPort TSERVER =
      new UdpPort((short) 450, "Computer Supported Telecomunication Applications");

  /** Cray Network Semaphore server: 451 */
  public static final UdpPort SFS_SMP_NET =
      new UdpPort((short) 451, "Cray Network Semaphore server");

  /** Cray SFS config server: 452 */
  public static final UdpPort SFS_CONFIG = new UdpPort((short) 452, "Cray SFS config server");

  /** CreativeServer: 453 */
  public static final UdpPort CREATIVESERVER = new UdpPort((short) 453, "CreativeServer");

  /** ContentServer: 454 */
  public static final UdpPort CONTENTSERVER = new UdpPort((short) 454, "ContentServer");

  /** CreativePartnr: 455 */
  public static final UdpPort CREATIVEPARTNR = new UdpPort((short) 455, "CreativePartnr");

  /** macon-udp: 456 */
  public static final UdpPort MACON_UDP = new UdpPort((short) 456, "macon-udp");

  /** scohelp: 457 */
  public static final UdpPort SCOHELP = new UdpPort((short) 457, "scohelp");

  /** apple quick time: 458 */
  public static final UdpPort APPLEQTC = new UdpPort((short) 458, "apple quick time");

  /** ampr-rcmd: 459 */
  public static final UdpPort AMPR_RCMD = new UdpPort((short) 459, "ampr-rcmd");

  /** skronk: 460 */
  public static final UdpPort SKRONK = new UdpPort((short) 460, "skronk");

  /** DataRampSrv: 461 */
  public static final UdpPort DATASURFSRV = new UdpPort((short) 461, "DataRampSrv");

  /** DataRampSrvSec: 462 */
  public static final UdpPort DATASURFSRVSEC = new UdpPort((short) 462, "DataRampSrvSec");

  /** alpes: 463 */
  public static final UdpPort ALPES = new UdpPort((short) 463, "alpes");

  /** kpasswd: 464 */
  public static final UdpPort KPASSWD = new UdpPort((short) 464, "kpasswd");

  /** IGMP over UDP for SSM: 465 */
  public static final UdpPort IGMPV3LITE = new UdpPort((short) 465, "IGMP over UDP for SSM");

  /** digital-vrc: 466 */
  public static final UdpPort DIGITAL_VRC = new UdpPort((short) 466, "digital-vrc");

  /** mylex-mapd: 467 */
  public static final UdpPort MYLEX_MAPD = new UdpPort((short) 467, "mylex-mapd");

  /** proturis: 468 */
  public static final UdpPort PHOTURIS = new UdpPort((short) 468, "proturis");

  /** Radio Control Protocol: 469 */
  public static final UdpPort RCP = new UdpPort((short) 469, "Radio Control Protocol");

  /** scx-proxy: 470 */
  public static final UdpPort SCX_PROXY = new UdpPort((short) 470, "scx-proxy");

  /** Mondex: 471 */
  public static final UdpPort MONDEX = new UdpPort((short) 471, "Mondex");

  /** ljk-login: 472 */
  public static final UdpPort LJK_LOGIN = new UdpPort((short) 472, "ljk-login");

  /** hybrid-pop: 473 */
  public static final UdpPort HYBRID_POP = new UdpPort((short) 473, "hybrid-pop");

  /** tn-tl-w2: 474 */
  public static final UdpPort TN_TL_W2 = new UdpPort((short) 474, "tn-tl-w2");

  /** tcpnethaspsrv: 475 */
  public static final UdpPort TCPNETHASPSRV = new UdpPort((short) 475, "tcpnethaspsrv");

  /** tn-tl-fd1: 476 */
  public static final UdpPort TN_TL_FD1 = new UdpPort((short) 476, "tn-tl-fd1");

  /** ss7ns: 477 */
  public static final UdpPort SS7NS = new UdpPort((short) 477, "ss7ns");

  /** spsc: 478 */
  public static final UdpPort SPSC = new UdpPort((short) 478, "spsc");

  /** iafserver: 479 */
  public static final UdpPort IAFSERVER = new UdpPort((short) 479, "iafserver");

  /** iafdbase: 480 */
  public static final UdpPort IAFDBASE = new UdpPort((short) 480, "iafdbase");

  /** Ph service: 481 */
  public static final UdpPort PH = new UdpPort((short) 481, "Ph service");

  /** bgs-nsi: 482 */
  public static final UdpPort BGS_NSI = new UdpPort((short) 482, "bgs-nsi");

  /** ulpnet: 483 */
  public static final UdpPort ULPNET = new UdpPort((short) 483, "ulpnet");

  /** Integra Software Management Environment: 484 */
  public static final UdpPort INTEGRA_SME =
      new UdpPort((short) 484, "Integra Software Management Environment");

  /** Air Soft Power Burst: 485 */
  public static final UdpPort POWERBURST = new UdpPort((short) 485, "Air Soft Power Burst");

  /** avian: 486 */
  public static final UdpPort AVIAN = new UdpPort((short) 486, "avian");

  /** saft Simple Asynchronous File Transfer: 487 */
  public static final UdpPort SAFT =
      new UdpPort((short) 487, "saft Simple Asynchronous File Transfer");

  /** gss-http: 488 */
  public static final UdpPort GSS_HTTP = new UdpPort((short) 488, "gss-http");

  /** nest-protocol: 489 */
  public static final UdpPort NEST_PROTOCOL = new UdpPort((short) 489, "nest-protocol");

  /** micom-pfs: 490 */
  public static final UdpPort MICOM_PFS = new UdpPort((short) 490, "micom-pfs");

  /** go-login: 491 */
  public static final UdpPort GO_LOGIN = new UdpPort((short) 491, "go-login");

  /** Transport Independent Convergence for FNA: 492 */
  public static final UdpPort TICF_1 =
      new UdpPort((short) 492, "Transport Independent Convergence for FNA");

  /** Transport Independent Convergence for FNA: 493 */
  public static final UdpPort TICF_2 =
      new UdpPort((short) 493, "Transport Independent Convergence for FNA");

  /** POV-Ray: 494 */
  public static final UdpPort POV_RAY = new UdpPort((short) 494, "POV-Ray");

  /** intecourier: 495 */
  public static final UdpPort INTECOURIER = new UdpPort((short) 495, "intecourier");

  /** PIM-RP-DISC: 496 */
  public static final UdpPort PIM_RP_DISC = new UdpPort((short) 496, "PIM-RP-DISC");

  /** Retrospect backup and restore service: 497 */
  public static final UdpPort RETROSPECT =
      new UdpPort((short) 497, "Retrospect backup and restore service");

  /** siam: 498 */
  public static final UdpPort SIAM = new UdpPort((short) 498, "siam");

  /** ISO ILL Protocol: 499 */
  public static final UdpPort ISO_ILL = new UdpPort((short) 499, "ISO ILL Protocol");

  /** isakmp: 500 */
  public static final UdpPort ISAKMP = new UdpPort((short) 500, "isakmp");

  /** STMF: 501 */
  public static final UdpPort STMF = new UdpPort((short) 501, "STMF");

  /** Modbus Application Protocol: 502 */
  public static final UdpPort MBAP = new UdpPort((short) 502, "Modbus Application Protocol");

  /** Intrinsa: 503 */
  public static final UdpPort INTRINSA = new UdpPort((short) 503, "Intrinsa");

  /** citadel: 504 */
  public static final UdpPort CITADEL = new UdpPort((short) 504, "citadel");

  /** mailbox-lm: 505 */
  public static final UdpPort MAILBOX_LM = new UdpPort((short) 505, "mailbox-lm");

  /** ohimsrv: 506 */
  public static final UdpPort OHIMSRV = new UdpPort((short) 506, "ohimsrv");

  /** crs: 507 */
  public static final UdpPort CRS = new UdpPort((short) 507, "crs");

  /** xvttp: 508 */
  public static final UdpPort XVTTP = new UdpPort((short) 508, "xvttp");

  /** snare: 509 */
  public static final UdpPort SNARE = new UdpPort((short) 509, "snare");

  /** FirstClass Protocol: 510 */
  public static final UdpPort FCP = new UdpPort((short) 510, "FirstClass Protocol");

  /** PassGo: 511 */
  public static final UdpPort PASSGO = new UdpPort((short) 511, "PassGo");

  /** biff: 512 */
  public static final UdpPort BIFF = new UdpPort((short) 512, "biff");

  /** who: 513 */
  public static final UdpPort WHO = new UdpPort((short) 513, "who");

  /** syslog: 514 */
  public static final UdpPort SYSLOG = new UdpPort((short) 514, "syslog");

  /** spooler: 515 */
  public static final UdpPort PRINTER = new UdpPort((short) 515, "spooler");

  /** videotex: 516 */
  public static final UdpPort VIDEOTEX = new UdpPort((short) 516, "videotex");

  /** talk: 517 */
  public static final UdpPort TALK = new UdpPort((short) 517, "talk");

  /** ntalk: 518 */
  public static final UdpPort NTALK = new UdpPort((short) 518, "ntalk");

  /** unixtime: 519 */
  public static final UdpPort UTIME = new UdpPort((short) 519, "unixtime");

  /** router: 520 */
  public static final UdpPort ROUTER = new UdpPort((short) 520, "router");

  /** ripng: 521 */
  public static final UdpPort RIPNG = new UdpPort((short) 521, "ripng");

  /** ULP: 522 */
  public static final UdpPort ULP = new UdpPort((short) 522, "ULP");

  /** IBM-DB2: 523 */
  public static final UdpPort IBM_DB2 = new UdpPort((short) 523, "IBM-DB2");

  /** NCP: 524 */
  public static final UdpPort NCP = new UdpPort((short) 524, "NCP");

  /** timeserver: 525 */
  public static final UdpPort TIMED = new UdpPort((short) 525, "timeserver");

  /** newdate: 526 */
  public static final UdpPort TEMPO = new UdpPort((short) 526, "newdate");

  /** Stock IXChange: 527 */
  public static final UdpPort STX = new UdpPort((short) 527, "Stock IXChange");

  /** Customer IXChange: 528 */
  public static final UdpPort CUSTIX = new UdpPort((short) 528, "Customer IXChange");

  /** IRC-SERV: 529 */
  public static final UdpPort IRC_SERV = new UdpPort((short) 529, "IRC-SERV");

  /** courier: 530 */
  public static final UdpPort COURIER = new UdpPort((short) 530, "courier");

  /** conference: 531 */
  public static final UdpPort CONFERENCE = new UdpPort((short) 531, "conference");

  /** readnews: 532 */
  public static final UdpPort NETNEWS = new UdpPort((short) 532, "readnews");

  /** netwall: 533 */
  public static final UdpPort NETWALL = new UdpPort((short) 533, "netwall");

  /** windream Admin: 534 */
  public static final UdpPort WINDREAM = new UdpPort((short) 534, "windream Admin");

  /** iiop: 535 */
  public static final UdpPort IIOP = new UdpPort((short) 535, "iiop");

  /** opalis-rdv: 536 */
  public static final UdpPort OPALIS_RDV = new UdpPort((short) 536, "opalis-rdv");

  /** Networked Media Streaming Protocol: 537 */
  public static final UdpPort NMSP = new UdpPort((short) 537, "Networked Media Streaming Protocol");

  /** gdomap: 538 */
  public static final UdpPort GDOMAP = new UdpPort((short) 538, "gdomap");

  /** Apertus Technologies Load Determination: 539 */
  public static final UdpPort APERTUS_LDP =
      new UdpPort((short) 539, "Apertus Technologies Load Determination");

  /** uucpd: 540 */
  public static final UdpPort UUCP = new UdpPort((short) 540, "uucpd");

  /** uucp-rlogin: 541 */
  public static final UdpPort UUCP_RLOGIN = new UdpPort((short) 541, "uucp-rlogin");

  /** commerce: 542 */
  public static final UdpPort COMMERCE = new UdpPort((short) 542, "commerce");

  /** klogin: 543 */
  public static final UdpPort KLOGIN = new UdpPort((short) 543, "klogin");

  /** krcmd: 544 */
  public static final UdpPort KSHELL = new UdpPort((short) 544, "krcmd");

  /** appleqtcsrvr: 545 */
  public static final UdpPort APPLEQTCSRVR = new UdpPort((short) 545, "appleqtcsrvr");

  /** DHCPv6 Client: 546 */
  public static final UdpPort DHCPV6_CLIENT = new UdpPort((short) 546, "DHCPv6 Client");

  /** DHCPv6 Server: 547 */
  public static final UdpPort DHCPV6_SERVER = new UdpPort((short) 547, "DHCPv6 Server");

  /** AFP over TCP: 548 */
  public static final UdpPort AFPOVERTCP = new UdpPort((short) 548, "AFP over TCP");

  /** IDFP: 549 */
  public static final UdpPort IDFP = new UdpPort((short) 549, "IDFP");

  /** new-who: 550 */
  public static final UdpPort NEW_RWHO = new UdpPort((short) 550, "new-who");

  /** cybercash: 551 */
  public static final UdpPort CYBERCASH = new UdpPort((short) 551, "cybercash");

  /** DeviceShare: 552 */
  public static final UdpPort DEVSHR_NTS = new UdpPort((short) 552, "DeviceShare");

  /** pirp: 553 */
  public static final UdpPort PIRP = new UdpPort((short) 553, "pirp");

  /** Real Time Streaming Protocol (RTSP): 554 */
  public static final UdpPort RTSP =
      new UdpPort((short) 554, "Real Time Streaming Protocol (RTSP)");

  /** dsf: 555 */
  public static final UdpPort DSF = new UdpPort((short) 555, "dsf");

  /** rfs server: 556 */
  public static final UdpPort REMOTEFS = new UdpPort((short) 556, "rfs server");

  /** openvms-sysipc: 557 */
  public static final UdpPort OPENVMS_SYSIPC = new UdpPort((short) 557, "openvms-sysipc");

  /** SDNSKMP: 558 */
  public static final UdpPort SDNSKMP = new UdpPort((short) 558, "SDNSKMP");

  /** TEEDTAP: 559 */
  public static final UdpPort TEEDTAP = new UdpPort((short) 559, "TEEDTAP");

  /** rmonitord: 560 */
  public static final UdpPort RMONITOR = new UdpPort((short) 560, "rmonitord");

  /** monitor: 561 */
  public static final UdpPort MONITOR = new UdpPort((short) 561, "monitor");

  /** chcmd: 562 */
  public static final UdpPort CHSHELL = new UdpPort((short) 562, "chcmd");

  /** nntp protocol over TLS/SSL (was snntp): 563 */
  public static final UdpPort NNTPS = new UdpPort((short) 563, "nntp protocol over TLS/SSL");

  /** plan 9 file service: 564 */
  public static final UdpPort UDP_9PFS = new UdpPort((short) 564, "plan 9 file service");

  /** whoami: 565 */
  public static final UdpPort WHOAMI = new UdpPort((short) 565, "whoami");

  /** streettalk: 566 */
  public static final UdpPort STREETTALK = new UdpPort((short) 566, "streettalk");

  /** banyan-rpc: 567 */
  public static final UdpPort BANYAN_RPC = new UdpPort((short) 567, "banyan-rpc");

  /** microsoft shuttle: 568 */
  public static final UdpPort MS_SHUTTLE = new UdpPort((short) 568, "microsoft shuttle");

  /** microsoft rome: 569 */
  public static final UdpPort MS_ROME = new UdpPort((short) 569, "microsoft rome");

  /** meter demon: 570 */
  public static final UdpPort METER_DEMON = new UdpPort((short) 570, "meter demon");

  /** meter udemon: 571 */
  public static final UdpPort METER_UDEMON = new UdpPort((short) 571, "meter udemon");

  /** sonar: 572 */
  public static final UdpPort SONAR = new UdpPort((short) 572, "sonar");

  /** banyan-vip: 573 */
  public static final UdpPort BANYAN_VIP = new UdpPort((short) 573, "banyan-vip");

  /** FTP Software Agent System: 574 */
  public static final UdpPort FTP_AGENT = new UdpPort((short) 574, "FTP Software Agent System");

  /** VEMMI: 575 */
  public static final UdpPort VEMMI = new UdpPort((short) 575, "VEMMI");

  /** ipcd: 576 */
  public static final UdpPort IPCD = new UdpPort((short) 576, "ipcd");

  /** vnas: 577 */
  public static final UdpPort VNAS = new UdpPort((short) 577, "vnas");

  /** ipdd: 578 */
  public static final UdpPort IPDD = new UdpPort((short) 578, "ipdd");

  /** decbsrv: 579 */
  public static final UdpPort DECBSRV = new UdpPort((short) 579, "decbsrv");

  /** SNTP HEARTBEAT: 580 */
  public static final UdpPort SNTP_HEARTBEAT = new UdpPort((short) 580, "SNTP HEARTBEAT");

  /** Bundle Discovery Protocol: 581 */
  public static final UdpPort BDP = new UdpPort((short) 581, "Bundle Discovery Protocol");

  /** SCC Security: 582 */
  public static final UdpPort SCC_SECURITY = new UdpPort((short) 582, "SCC Security");

  /** Philips Video-Conferencing: 583 */
  public static final UdpPort PHILIPS_VC = new UdpPort((short) 583, "Philips Video-Conferencing");

  /** Key Server: 584 */
  public static final UdpPort KEYSERVER = new UdpPort((short) 584, "Key Server");

  /** Password Change: 586 */
  public static final UdpPort PASSWORD_CHG = new UdpPort((short) 586, "Password Change");

  /** Message Submission: 587 */
  public static final UdpPort SUBMISSION = new UdpPort((short) 587, "Message Submission");

  /** CAL: 588 */
  public static final UdpPort CAL = new UdpPort((short) 588, "CAL");

  /** EyeLink: 589 */
  public static final UdpPort EYELINK = new UdpPort((short) 589, "EyeLink");

  /** TNS CML: 590 */
  public static final UdpPort TNS_CML = new UdpPort((short) 590, "TNS CML");

  /** FileMaker HTTP Alternate: 591 */
  public static final UdpPort HTTP_ALT = new UdpPort((short) 591, "FileMaker HTTP Alternate");

  /** Eudora Set: 592 */
  public static final UdpPort EUDORA_SET = new UdpPort((short) 592, "Eudora Set");

  /** HTTP RPC Ep Map: 593 */
  public static final UdpPort HTTP_RPC_EPMAP = new UdpPort((short) 593, "HTTP RPC Ep Map");

  /** TPIP: 594 */
  public static final UdpPort TPIP = new UdpPort((short) 594, "TPIP");

  /** CAB Protocol: 595 */
  public static final UdpPort CAB_PROTOCOL = new UdpPort((short) 595, "CAB Protocol");

  /** SMSD: 596 */
  public static final UdpPort SMSD = new UdpPort((short) 596, "SMSD");

  /** PTC Name Service: 597 */
  public static final UdpPort PTCNAMESERVICE = new UdpPort((short) 597, "PTC Name Service");

  /** SCO Web Server Manager 3: 598 */
  public static final UdpPort SCO_WEBSRVRMG3 = new UdpPort((short) 598, "SCO Web Server Manager 3");

  /** Aeolon Core Protocol: 599 */
  public static final UdpPort ACP = new UdpPort((short) 599, "Aeolon Core Protocol");

  /** Sun IPC server: 600 */
  public static final UdpPort IPCSERVER = new UdpPort((short) 600, "Sun IPC server");

  /** Reliable Syslog Service: 601 */
  public static final UdpPort SYSLOG_CONN = new UdpPort((short) 601, "Reliable Syslog Service");

  /** XML-RPC over BEEP: 602 */
  public static final UdpPort XMLRPC_BEEP = new UdpPort((short) 602, "XML-RPC over BEEP");

  /** IDXP: 603 */
  public static final UdpPort IDXP = new UdpPort((short) 603, "IDXP");

  /** TUNNEL: 604 */
  public static final UdpPort TUNNEL = new UdpPort((short) 604, "TUNNEL");

  /** SOAP over BEEP: 605 */
  public static final UdpPort SOAP_BEEP = new UdpPort((short) 605, "SOAP over BEEP");

  /** Cray Unified Resource Manager: 606 */
  public static final UdpPort URM = new UdpPort((short) 606, "Cray Unified Resource Manager");

  /** nqs: 607 */
  public static final UdpPort NQS = new UdpPort((short) 607, "nqs");

  /** Sender-Initiated/Unsolicited File Transfer: 608 */
  public static final UdpPort SIFT_UFT =
      new UdpPort((short) 608, "Sender-Initiated/Unsolicited File Transfer");

  /** npmp-trap: 609 */
  public static final UdpPort NPMP_TRAP = new UdpPort((short) 609, "npmp-trap");

  /** npmp-local: 610 */
  public static final UdpPort NPMP_LOCAL = new UdpPort((short) 610, "npmp-local");

  /** npmp-gui: 611 */
  public static final UdpPort NPMP_GUI = new UdpPort((short) 611, "npmp-gui");

  /** HMMP Indication: 612 */
  public static final UdpPort HMMP_IND = new UdpPort((short) 612, "HMMP Indication");

  /** HMMP Operation: 613 */
  public static final UdpPort HMMP_OP = new UdpPort((short) 613, "HMMP Operation");

  /** SSLshell: 614 */
  public static final UdpPort SSHELL = new UdpPort((short) 614, "SSLshell");

  /** SCO Internet Configuration Manager: 615 */
  public static final UdpPort SCO_INETMGR =
      new UdpPort((short) 615, "SCO Internet Configuration Manager");

  /** SCO System Administration Server: 616 */
  public static final UdpPort SCO_SYSMGR =
      new UdpPort((short) 616, "SCO System Administration Server");

  /** SCO Desktop Administration Server: 617 */
  public static final UdpPort SCO_DTMGR =
      new UdpPort((short) 617, "SCO Desktop Administration Server");

  /** DEI-ICDA: 618 */
  public static final UdpPort DEI_ICDA = new UdpPort((short) 618, "DEI-ICDA");

  /** Compaq EVM: 619 */
  public static final UdpPort COMPAQ_EVM = new UdpPort((short) 619, "Compaq EVM");

  /** SCO WebServer Manager: 620 */
  public static final UdpPort SCO_WEBSRVRMGR = new UdpPort((short) 620, "SCO WebServer Manager");

  /** ESCP: 621 */
  public static final UdpPort ESCP_IP = new UdpPort((short) 621, "ESCP");

  /** Collaborator: 622 */
  public static final UdpPort COLLABORATOR = new UdpPort((short) 622, "Collaborator");

  /** ASF Remote Management and Control Protocol: 623 */
  public static final UdpPort ASF_RMCP =
      new UdpPort((short) 623, "ASF Remote Management and Control Protocol");

  /** Crypto Admin: 624 */
  public static final UdpPort CRYPTOADMIN = new UdpPort((short) 624, "Crypto Admin");

  /** DEC DLM: 625 */
  public static final UdpPort DEC_DLM = new UdpPort((short) 625, "DEC DLM");

  /** ASIA: 626 */
  public static final UdpPort ASIA = new UdpPort((short) 626, "ASIA");

  /** PassGo Tivoli: 627 */
  public static final UdpPort PASSGO_TIVOLI = new UdpPort((short) 627, "PassGo Tivoli");

  /** QMQP: 628 */
  public static final UdpPort QMQP = new UdpPort((short) 628, "QMQP");

  /** 3Com AMP3: 629 */
  public static final UdpPort UDP_3COM_AMP3 = new UdpPort((short) 629, "3Com AMP3");

  /** RDA: 630 */
  public static final UdpPort RDA = new UdpPort((short) 630, "RDA");

  /** IPP (Internet Printing Protocol): 631 */
  public static final UdpPort IPP = new UdpPort((short) 631, "Internet Printing Protocol");

  /** bmpp: 632 */
  public static final UdpPort BMPP = new UdpPort((short) 632, "bmpp");

  /** Service Status update (Sterling Software): 633 */
  public static final UdpPort SERVSTAT =
      new UdpPort((short) 633, "Service Status update (Sterling Software)");

  /** ginad: 634 */
  public static final UdpPort GINAD = new UdpPort((short) 634, "ginad");

  /** RLZ DBase: 635 */
  public static final UdpPort RLZDBASE = new UdpPort((short) 635, "RLZ DBase");

  /** ldap protocol over TLS/SSL (was sldap): 636 */
  public static final UdpPort LDAPS = new UdpPort((short) 636, "ldap protocol over TLS/SSL");

  /** lanserver: 637 */
  public static final UdpPort LANSERVER = new UdpPort((short) 637, "lanserver");

  /** mcns-sec: 638 */
  public static final UdpPort MCNS_SEC = new UdpPort((short) 638, "mcns-sec");

  /** MSDP: 639 */
  public static final UdpPort MSDP = new UdpPort((short) 639, "MSDP");

  /** entrust-sps: 640 */
  public static final UdpPort ENTRUST_SPS = new UdpPort((short) 640, "entrust-sps");

  /** repcmd: 641 */
  public static final UdpPort REPCMD = new UdpPort((short) 641, "repcmd");

  /** ESRO-EMSDP V1.3: 642 */
  public static final UdpPort ESRO_EMSDP = new UdpPort((short) 642, "ESRO-EMSDP V1.3");

  /** SANity: 643 */
  public static final UdpPort SANITY = new UdpPort((short) 643, "SANity");

  /** dwr: 644 */
  public static final UdpPort DWR = new UdpPort((short) 644, "dwr");

  /** PSSC: 645 */
  public static final UdpPort PSSC = new UdpPort((short) 645, "PSSC");

  /** LDP: 646 */
  public static final UdpPort LDP = new UdpPort((short) 646, "LDP");

  /** DHCP Failover: 647 */
  public static final UdpPort DHCP_FAILOVER = new UdpPort((short) 647, "DHCP Failover");

  /** Registry Registrar Protocol (RRP): 648 */
  public static final UdpPort RRP = new UdpPort((short) 648, "Registry Registrar Protocol (RRP)");

  /** Cadview-3d - streaming 3d models over the internet: 649 */
  public static final UdpPort CADVIEW_3D =
      new UdpPort((short) 649, "Cadview-3d - streaming 3d models over the internet");

  /** OBEX: 650 */
  public static final UdpPort OBEX = new UdpPort((short) 650, "OBEX");

  /** IEEE MMS: 651 */
  public static final UdpPort IEEE_MMS = new UdpPort((short) 651, "IEEE MMS");

  /** HELLO_PORT: 652 */
  public static final UdpPort HELLO_PORT = new UdpPort((short) 652, "HELLO_PORT");

  /** RepCmd: 653 */
  public static final UdpPort REPSCMD = new UdpPort((short) 653, "RepCmd");

  /** AODV: 654 */
  public static final UdpPort AODV = new UdpPort((short) 654, "AODV");

  /** TINC: 655 */
  public static final UdpPort TINC = new UdpPort((short) 655, "TINC");

  /** SPMP: 656 */
  public static final UdpPort SPMP = new UdpPort((short) 656, "SPMP");

  /** RMC: 657 */
  public static final UdpPort RMC = new UdpPort((short) 657, "RMC");

  /** TenFold: 658 */
  public static final UdpPort TENFOLD = new UdpPort((short) 658, "TenFold");

  /** MacOS Server Admin: 660 */
  public static final UdpPort MAC_SRVR_ADMIN = new UdpPort((short) 660, "MacOS Server Admin");

  /** HAP: 661 */
  public static final UdpPort HAP = new UdpPort((short) 661, "HAP");

  /** PFTP: 662 */
  public static final UdpPort PFTP = new UdpPort((short) 662, "PFTP");

  /** PureNoise: 663 */
  public static final UdpPort PURENOISE = new UdpPort((short) 663, "PureNoise");

  /** ASF Secure Remote Management and Control Protocol: 664 */
  public static final UdpPort ASF_SECURE_RMCP =
      new UdpPort((short) 664, "ASF Secure Remote Management and Control Protocol");

  /** Sun DR: 665 */
  public static final UdpPort SUN_DR = new UdpPort((short) 665, "Sun DR");

  /** doom Id Software: 666 */
  public static final UdpPort DOOM = new UdpPort((short) 666, "doom Id Software");

  /** campaign contribution disclosures - SDR Technologies: 667 */
  public static final UdpPort DISCLOSE =
      new UdpPort((short) 667, "campaign contribution disclosures - SDR Technologies");

  /** MeComm: 668 */
  public static final UdpPort MECOMM = new UdpPort((short) 668, "MeComm");

  /** MeRegister: 669 */
  public static final UdpPort MEREGISTER = new UdpPort((short) 669, "MeRegister");

  /** VACDSM-SWS: 670 */
  public static final UdpPort VACDSM_SWS = new UdpPort((short) 670, "VACDSM-SWS");

  /** VACDSM-APP: 671 */
  public static final UdpPort VACDSM_APP = new UdpPort((short) 671, "VACDSM-APP");

  /** VPPS-QUA: 672 */
  public static final UdpPort VPPS_QUA = new UdpPort((short) 672, "VPPS-QUA");

  /** CIMPLEX: 673 */
  public static final UdpPort CIMPLEX = new UdpPort((short) 673, "CIMPLEX");

  /** ACAP: 674 */
  public static final UdpPort ACAP = new UdpPort((short) 674, "ACAP");

  /** DCTP: 675 */
  public static final UdpPort DCTP = new UdpPort((short) 675, "DCTP");

  /** VPPS Via: 676 */
  public static final UdpPort VPPS_VIA = new UdpPort((short) 676, "VPPS Via");

  /** Virtual Presence Protocol: 677 */
  public static final UdpPort VPP = new UdpPort((short) 677, "Virtual Presence Protocol");

  /** GNU Generation Foundation NCP: 678 */
  public static final UdpPort GGF_NCP = new UdpPort((short) 678, "GNU Generation Foundation NCP");

  /** MRM: 679 */
  public static final UdpPort MRM = new UdpPort((short) 679, "MRM");

  /** entrust-aaas: 680 */
  public static final UdpPort ENTRUST_AAAS = new UdpPort((short) 680, "entrust-aaas");

  /** entrust-aams: 681 */
  public static final UdpPort ENTRUST_AAMS = new UdpPort((short) 681, "entrust-aams");

  /** XFR: 682 */
  public static final UdpPort XFR = new UdpPort((short) 682, "XFR");

  /** CORBA IIOP: 683 */
  public static final UdpPort CORBA_IIOP = new UdpPort((short) 683, "CORBA IIOP");

  /** CORBA IIOP SSL: 684 */
  public static final UdpPort CORBA_IIOP_SSL = new UdpPort((short) 684, "CORBA IIOP SSL");

  /** MDC Port Mapper: 685 */
  public static final UdpPort MDC_PORTMAPPER = new UdpPort((short) 685, "MDC Port Mapper");

  /** Hardware Control Protocol Wismar: 686 */
  public static final UdpPort HCP_WISMAR =
      new UdpPort((short) 686, "Hardware Control Protocol Wismar");

  /** asipregistry: 687 */
  public static final UdpPort ASIPREGISTRY = new UdpPort((short) 687, "asipregistry");

  /** ApplianceWare managment protocol: 688 */
  public static final UdpPort REALM_RUSD =
      new UdpPort((short) 688, "ApplianceWare managment protocol");

  /** NMAP: 689 */
  public static final UdpPort NMAP = new UdpPort((short) 689, "NMAP");

  /** Velneo Application Transfer Protocol: 690 */
  public static final UdpPort VATP =
      new UdpPort((short) 690, "Velneo Application Transfer Protocol");

  /** MS Exchange Routing: 691 */
  public static final UdpPort MSEXCH_ROUTING = new UdpPort((short) 691, "MS Exchange Routing");

  /** Hyperwave-ISP: 692 */
  public static final UdpPort HYPERWAVE_ISP = new UdpPort((short) 692, "Hyperwave-ISP");

  /** almanid Connection Endpoint: 693 */
  public static final UdpPort CONNENDP = new UdpPort((short) 693, "almanid Connection Endpoint");

  /** ha-cluster: 694 */
  public static final UdpPort HA_CLUSTER = new UdpPort((short) 694, "ha-cluster");

  /** IEEE-MMS-SSL: 695 */
  public static final UdpPort IEEE_MMS_SSL = new UdpPort((short) 695, "IEEE-MMS-SSL");

  /** RUSHD: 696 */
  public static final UdpPort RUSHD = new UdpPort((short) 696, "RUSHD");

  /** UUIDGEN: 697 */
  public static final UdpPort UUIDGEN = new UdpPort((short) 697, "UUIDGEN");

  /** OLSR: 698 */
  public static final UdpPort OLSR = new UdpPort((short) 698, "OLSR");

  /** Access Network: 699 */
  public static final UdpPort ACCESSNETWORK = new UdpPort((short) 699, "Access Network");

  /** Extensible Provisioning Protocol: 700 */
  public static final UdpPort EPP = new UdpPort((short) 700, "Extensible Provisioning Protocol");

  /** Link Management Protocol (LMP): 701 */
  public static final UdpPort LMP = new UdpPort((short) 701, "Link Management Protocol (LMP)");

  /** IRIS over BEEP: 702 */
  public static final UdpPort IRIS_BEEP = new UdpPort((short) 702, "IRIS over BEEP");

  /** errlog copy/server daemon: 704 */
  public static final UdpPort ELCSD = new UdpPort((short) 704, "errlog copy/server daemon");

  /** AgentX: 705 */
  public static final UdpPort AGENTX = new UdpPort((short) 705, "AgentX");

  /** SILC: 706 */
  public static final UdpPort SILC = new UdpPort((short) 706, "SILC");

  /** Borland DSJ: 707 */
  public static final UdpPort BORLAND_DSJ = new UdpPort((short) 707, "Borland DSJ");

  /** Entrust Key Management Service Handler: 709 */
  public static final UdpPort ENTRUST_KMSH =
      new UdpPort((short) 709, "Entrust Key Management Service Handler");

  /** Entrust Administration Service Handler: 710 */
  public static final UdpPort ENTRUST_ASH =
      new UdpPort((short) 710, "Entrust Administration Service Handler");

  /** Cisco TDP: 711 */
  public static final UdpPort CISCO_TDP = new UdpPort((short) 711, "Cisco TDP");

  /** TBRPF: 712 */
  public static final UdpPort TBRPF = new UdpPort((short) 712, "TBRPF");

  /** IRIS over XPC: 713 */
  public static final UdpPort IRIS_XPC = new UdpPort((short) 713, "IRIS over XPC");

  /** IRIS over XPCS: 714 */
  public static final UdpPort IRIS_XPCS = new UdpPort((short) 714, "IRIS over XPCS");

  /** IRIS-LWZ: 715 */
  public static final UdpPort IRIS_LWZ = new UdpPort((short) 715, "IRIS-LWZ");

  /** PANA Messages: 716 */
  public static final UdpPort PANA = new UdpPort((short) 716, "PANA Messages");

  /** IBM NetView DM/6000 Server/Client: 729 */
  public static final UdpPort NETVIEWDM1 =
      new UdpPort((short) 729, "IBM NetView DM/6000 Server/Client");

  /** IBM NetView DM/6000 send/tcp: 730 */
  public static final UdpPort NETVIEWDM2 = new UdpPort((short) 730, "IBM NetView DM/6000 send/tcp");

  /** IBM NetView DM/6000 receive/tcp: 731 */
  public static final UdpPort NETVIEWDM3 =
      new UdpPort((short) 731, "IBM NetView DM/6000 receive/tcp");

  /** netGW: 741 */
  public static final UdpPort NETGW = new UdpPort((short) 741, "netGW");

  /** Network based Rev. Cont. Sys.: 742 */
  public static final UdpPort NETRCS = new UdpPort((short) 742, "Network based Rev. Cont. Sys.");

  /** Flexible License Manager: 744 */
  public static final UdpPort FLEXLM = new UdpPort((short) 744, "Flexible License Manager");

  /** Fujitsu Device Control: 747 */
  public static final UdpPort FUJITSU_DEV = new UdpPort((short) 747, "Fujitsu Device Control");

  /** Russell Info Sci Calendar Manager: 748 */
  public static final UdpPort RIS_CM =
      new UdpPort((short) 748, "Russell Info Sci Calendar Manager");

  /** kerberos administration: 749 */
  public static final UdpPort KERBEROS_ADM = new UdpPort((short) 749, "kerberos administration");

  /** kerberos version iv: 750 */
  public static final UdpPort KERBEROS_IV = new UdpPort((short) 750, "kerberos version iv");

  /** pump: 751 */
  public static final UdpPort PUMP = new UdpPort((short) 751, "pump");

  /** qrh: 752 */
  public static final UdpPort QRH = new UdpPort((short) 752, "qrh");

  /** rrh: 753 */
  public static final UdpPort RRH = new UdpPort((short) 753, "rrh");

  /** send: 754 */
  public static final UdpPort TELL = new UdpPort((short) 754, "send");

  /** nlogin: 758 */
  public static final UdpPort NLOGIN = new UdpPort((short) 758, "nlogin");

  /** con: 759 */
  public static final UdpPort CON = new UdpPort((short) 759, "con");

  /** ns: 760 */
  public static final UdpPort NS = new UdpPort((short) 760, "ns");

  /** rxe: 761 */
  public static final UdpPort RXE = new UdpPort((short) 761, "rxe");

  /** quotad: 762 */
  public static final UdpPort QUOTAD = new UdpPort((short) 762, "quotad");

  /** cycleserv: 763 */
  public static final UdpPort CYCLESERV = new UdpPort((short) 763, "cycleserv");

  /** omserv: 764 */
  public static final UdpPort OMSERV = new UdpPort((short) 764, "omserv");

  /** webster: 765 */
  public static final UdpPort WEBSTER = new UdpPort((short) 765, "webster");

  /** phone: 767 */
  public static final UdpPort PHONEBOOK = new UdpPort((short) 767, "phone");

  /** vid: 769 */
  public static final UdpPort VID = new UdpPort((short) 769, "vid");

  /** cadlock: 770 */
  public static final UdpPort CADLOCK = new UdpPort((short) 770, "cadlock");

  /** rtip: 771 */
  public static final UdpPort RTIP = new UdpPort((short) 771, "rtip");

  /** cycleserv2: 772 */
  public static final UdpPort CYCLESERV2 = new UdpPort((short) 772, "cycleserv2");

  /** notify: 773 */
  public static final UdpPort NOTIFY = new UdpPort((short) 773, "notify");

  /** acmaint-dbd: 774 */
  public static final UdpPort ACMAINT_DBD = new UdpPort((short) 774, "acmaint-dbd");

  /** acmaint-transd: 775 */
  public static final UdpPort ACMAINT_TRANSD = new UdpPort((short) 775, "acmaint-transd");

  /** wpages: 776 */
  public static final UdpPort WPAGES = new UdpPort((short) 776, "wpages");

  /** Multiling HTTP: 777 */
  public static final UdpPort MULTILING_HTTP = new UdpPort((short) 777, "Multiling HTTP");

  /** wpgs: 780 */
  public static final UdpPort WPGS = new UdpPort((short) 780, "wpgs");

  /** mdbs-daemon: 800 */
  public static final UdpPort MDBS_DAEMON = new UdpPort((short) 800, "mdbs-daemon");

  /** device: 801 */
  public static final UdpPort DEVICE = new UdpPort((short) 801, "device");

  /** Modbus Application Protocol Secure: 802 */
  public static final UdpPort MBAP_S =
      new UdpPort((short) 802, "Modbus Application Protocol Secure");

  /** FCP Datagram: 810 */
  public static final UdpPort FCP_UDP = new UdpPort((short) 810, "FCP Datagram");

  /** itm-mcell-s: 828 */
  public static final UdpPort ITM_MCELL_S = new UdpPort((short) 828, "itm-mcell-s");

  /** PKIX-3 CA/RA: 829 */
  public static final UdpPort PKIX_3_CA_RA = new UdpPort((short) 829, "PKIX-3 CA/RA");

  /** NETCONF over SSH: 830 */
  public static final UdpPort NETCONF_SSH = new UdpPort((short) 830, "NETCONF over SSH");

  /** NETCONF over BEEP: 831 */
  public static final UdpPort NETCONF_BEEP = new UdpPort((short) 831, "NETCONF over BEEP");

  /** NETCONF for SOAP over HTTPS: 832 */
  public static final UdpPort NETCONFSOAPHTTP =
      new UdpPort((short) 832, "NETCONF for SOAP over HTTPS");

  /** NETCONF for SOAP over BEEP: 833 */
  public static final UdpPort NETCONFSOAPBEEP =
      new UdpPort((short) 833, "NETCONF for SOAP over BEEP");

  /** dhcp-failover 2: 847 */
  public static final UdpPort DHCP_FAILOVER2 = new UdpPort((short) 847, "dhcp-failover 2");

  /** GDOI: 848 */
  public static final UdpPort GDOI = new UdpPort((short) 848, "GDOI");

  /** iSCSI: 860 */
  public static final UdpPort ISCSI = new UdpPort((short) 860, "iSCSI");

  /** OWAMP-Control: 861 */
  public static final UdpPort OWAMP_CONTROL = new UdpPort((short) 861, "OWAMP-Control");

  /** Two-way Active Measurement Protocol (TWAMP) Control: 862 */
  public static final UdpPort TWAMP_CONTROL =
      new UdpPort((short) 862, "Two-way Active Measurement Protocol (TWAMP) Control");

  /** rsync: 873 */
  public static final UdpPort RSYNC = new UdpPort((short) 873, "rsync");

  /** ICL coNETion locate server: 886 */
  public static final UdpPort ICLCNET_LOCATE =
      new UdpPort((short) 886, "ICL coNETion locate server");

  /** ICL coNETion server info: 887 */
  public static final UdpPort ICLCNET_SVINFO = new UdpPort((short) 887, "ICL coNETion server info");

  /** AccessBuilder: 888 */
  public static final UdpPort ACCESSBUILDER = new UdpPort((short) 888, "AccessBuilder");

  /** OMG Initial Refs: 900 */
  public static final UdpPort OMGINITIALREFS = new UdpPort((short) 900, "OMG Initial Refs");

  /** SMPNAMERES: 901 */
  public static final UdpPort SMPNAMERES = new UdpPort((short) 901, "SMPNAMERES");

  /** self documenting Door: send 0x00 for info: 902 */
  public static final UdpPort IDEAFARM_DOOR =
      new UdpPort((short) 902, "self documenting Door: send 0x00 for info");

  /** self documenting Panic Door: send 0x00 for info: 903 */
  public static final UdpPort IDEAFARM_PANIC =
      new UdpPort((short) 903, "self documenting Panic Door: send 0x00 for info");

  /** Kerberized Internet Negotiation of Keys (KINK): 910 */
  public static final UdpPort KINK =
      new UdpPort((short) 910, "Kerberized Internet Negotiation of Keys (KINK)");

  /** xact-backup: 911 */
  public static final UdpPort XACT_BACKUP = new UdpPort((short) 911, "xact-backup");

  /** APEX relay-relay service: 912 */
  public static final UdpPort APEX_MESH = new UdpPort((short) 912, "APEX relay-relay service");

  /** APEX endpoint-relay service: 913 */
  public static final UdpPort APEX_EDGE = new UdpPort((short) 913, "APEX endpoint-relay service");

  /** ftp protocol, data, over TLS/SSL: 989 */
  public static final UdpPort FTPS_DATA =
      new UdpPort((short) 989, "ftp protocol, data, over TLS/SSL");

  /** ftp protocol, control, over TLS/SSL: 990 */
  public static final UdpPort FTPS =
      new UdpPort((short) 990, "ftp protocol, control, over TLS/SSL");

  /** Netnews Administration System: 991 */
  public static final UdpPort NAS = new UdpPort((short) 991, "Netnews Administration System");

  /** telnet protocol over TLS/SSL: 992 */
  public static final UdpPort TELNETS = new UdpPort((short) 992, "telnet protocol over TLS/SSL");

  /** imap4 protocol over TLS/SSL: 993 */
  public static final UdpPort IMAPS = new UdpPort((short) 993, "imap4 protocol over TLS/SSL");

  /** pop3 protocol over TLS/SSL (was spop3): 995 */
  public static final UdpPort POP3S =
      new UdpPort((short) 995, "pop3 protocol over TLS/SSL (was spop3)");

  /** vsinet: 996 */
  public static final UdpPort VSINET = new UdpPort((short) 996, "vsinet");

  /** maitrd: 997 */
  public static final UdpPort MAITRD = new UdpPort((short) 997, "maitrd");

  /** puparp: 998 */
  public static final UdpPort PUPARP = new UdpPort((short) 998, "puparp");

  /** Applix ac: 999 */
  public static final UdpPort APPLIX = new UdpPort((short) 999, "Applix ac");

  /** cadlock2: 1000 */
  public static final UdpPort CADLOCK2 = new UdpPort((short) 1000, "cadlock2");

  /** surf: 1010 */
  public static final UdpPort SURF = new UdpPort((short) 1010, "surf");

  /** GTP-C: 2123 */
  public static final UdpPort GTP_C = new UdpPort((short) 2123, "GTP-C");

  /** GTP-U: 2152 */
  public static final UdpPort GTP_U = new UdpPort((short) 2152, "GTP-U");

  /** GTP': 3386 */
  public static final UdpPort GTP_PRIME = new UdpPort((short) 3386, "GTP'");

  private static final Map<Short, UdpPort> registry = new HashMap<Short, UdpPort>();

  static {
    registry.put(TCPMUX.value(), TCPMUX);
    registry.put(COMPRESSNET_MANAGEMENT_UTILITY.value(), COMPRESSNET_MANAGEMENT_UTILITY);
    registry.put(COMPRESSNET_COMPRESSION_PROCESS.value(), COMPRESSNET_COMPRESSION_PROCESS);
    registry.put(RJE.value(), RJE);
    registry.put(ECHO.value(), ECHO);
    registry.put(DISCARD.value(), DISCARD);
    registry.put(SYSTAT.value(), SYSTAT);
    registry.put(DAYTIME.value(), DAYTIME);
    registry.put(QOTD.value(), QOTD);
    registry.put(MSP.value(), MSP);
    registry.put(CHARGEN.value(), CHARGEN);
    registry.put(FTP_DATA.value(), FTP_DATA);
    registry.put(FTP.value(), FTP);
    registry.put(SSH.value(), SSH);
    registry.put(TELNET.value(), TELNET);
    registry.put(SMTP.value(), SMTP);
    registry.put(NSW_FE.value(), NSW_FE);
    registry.put(MSG_ICP.value(), MSG_ICP);
    registry.put(MSG_AUTH.value(), MSG_AUTH);
    registry.put(DSP.value(), DSP);
    registry.put(TIME.value(), TIME);
    registry.put(RAP.value(), RAP);
    registry.put(RLP.value(), RLP);
    registry.put(GRAPHICS.value(), GRAPHICS);
    registry.put(NAMESERVER.value(), NAMESERVER);
    registry.put(WHOIS.value(), WHOIS);
    registry.put(MPM_FLAGS.value(), MPM_FLAGS);
    registry.put(MPM.value(), MPM);
    registry.put(MPM_SND.value(), MPM_SND);
    registry.put(NI_FTP.value(), NI_FTP);
    registry.put(AUDITD.value(), AUDITD);
    registry.put(TACACS.value(), TACACS);
    registry.put(RE_MAIL_CK.value(), RE_MAIL_CK);
    registry.put(XNS_TIME.value(), XNS_TIME);
    registry.put(DOMAIN.value(), DOMAIN);
    registry.put(XNS_CH.value(), XNS_CH);
    registry.put(ISI_GL.value(), ISI_GL);
    registry.put(XNS_AUTH.value(), XNS_AUTH);
    registry.put(XNS_MAIL.value(), XNS_MAIL);
    registry.put(NI_MAIL.value(), NI_MAIL);
    registry.put(ACAS.value(), ACAS);
    registry.put(WHOIS_PP.value(), WHOIS_PP);
    registry.put(COVIA.value(), COVIA);
    registry.put(TACACS_DS.value(), TACACS_DS);
    registry.put(ORACLE_SQL_NET.value(), ORACLE_SQL_NET);
    registry.put(BOOTPS.value(), BOOTPS);
    registry.put(BOOTPC.value(), BOOTPC);
    registry.put(TFTP.value(), TFTP);
    registry.put(GOPHER.value(), GOPHER);
    registry.put(NETRJS_1.value(), NETRJS_1);
    registry.put(NETRJS_2.value(), NETRJS_2);
    registry.put(NETRJS_3.value(), NETRJS_3);
    registry.put(NETRJS_4.value(), NETRJS_4);
    registry.put(DEOS.value(), DEOS);
    registry.put(VETTCP.value(), VETTCP);
    registry.put(FINGER.value(), FINGER);
    registry.put(HTTP.value(), HTTP);
    registry.put(XFER.value(), XFER);
    registry.put(MIT_ML_DEV_83.value(), MIT_ML_DEV_83);
    registry.put(CTF.value(), CTF);
    registry.put(MIT_ML_DEV_85.value(), MIT_ML_DEV_85);
    registry.put(MFCOBOL.value(), MFCOBOL);
    registry.put(KERBEROS.value(), KERBEROS);
    registry.put(SU_MIT_TG.value(), SU_MIT_TG);
    registry.put(DNSIX.value(), DNSIX);
    registry.put(MIT_DOV.value(), MIT_DOV);
    registry.put(NPP.value(), NPP);
    registry.put(DCP.value(), DCP);
    registry.put(OBJCALL.value(), OBJCALL);
    registry.put(SUPDUP.value(), SUPDUP);
    registry.put(DIXIE.value(), DIXIE);
    registry.put(SWIFT_RVF.value(), SWIFT_RVF);
    registry.put(TACNEWS.value(), TACNEWS);
    registry.put(METAGRAM.value(), METAGRAM);
    registry.put(HOSTNAME.value(), HOSTNAME);
    registry.put(ISO_TSAP.value(), ISO_TSAP);
    registry.put(GPPITNP.value(), GPPITNP);
    registry.put(ACR_NEMA.value(), ACR_NEMA);
    registry.put(CSO.value(), CSO);
    registry.put(UDP_3COM_TSMUX.value(), UDP_3COM_TSMUX);
    registry.put(RTELNET.value(), RTELNET);
    registry.put(SNAGAS.value(), SNAGAS);
    registry.put(POP2.value(), POP2);
    registry.put(POP3.value(), POP3);
    registry.put(SUNRPC.value(), SUNRPC);
    registry.put(MCIDAS.value(), MCIDAS);
    registry.put(AUTH.value(), AUTH);
    registry.put(SFTP.value(), SFTP);
    registry.put(ANSANOTIFY.value(), ANSANOTIFY);
    registry.put(UUCP_PATH.value(), UUCP_PATH);
    registry.put(SQLSERV.value(), SQLSERV);
    registry.put(NNTP.value(), NNTP);
    registry.put(CFDPTKT.value(), CFDPTKT);
    registry.put(ERPC.value(), ERPC);
    registry.put(SMAKYNET.value(), SMAKYNET);
    registry.put(NTP.value(), NTP);
    registry.put(ANSATRADER.value(), ANSATRADER);
    registry.put(LOCUS_MAP.value(), LOCUS_MAP);
    registry.put(NXEDIT.value(), NXEDIT);
    registry.put(LOCUS_CON.value(), LOCUS_CON);
    registry.put(GSS_XLICEN.value(), GSS_XLICEN);
    registry.put(PWDGEN.value(), PWDGEN);
    registry.put(CISCO_FNA.value(), CISCO_FNA);
    registry.put(CISCO_TNA.value(), CISCO_TNA);
    registry.put(CISCO_SYS.value(), CISCO_SYS);
    registry.put(STATSRV.value(), STATSRV);
    registry.put(INGRES_NET.value(), INGRES_NET);
    registry.put(EPMAP.value(), EPMAP);
    registry.put(PROFILE.value(), PROFILE);
    registry.put(NETBIOS_NS.value(), NETBIOS_NS);
    registry.put(NETBIOS_DGM.value(), NETBIOS_DGM);
    registry.put(NETBIOS_SSN.value(), NETBIOS_SSN);
    registry.put(EMFIS_DATA.value(), EMFIS_DATA);
    registry.put(EMFIS_CNTL.value(), EMFIS_CNTL);
    registry.put(BL_IDM.value(), BL_IDM);
    registry.put(IMAP.value(), IMAP);
    registry.put(UMA.value(), UMA);
    registry.put(UAAC.value(), UAAC);
    registry.put(ISO_TP0.value(), ISO_TP0);
    registry.put(ISO_IP.value(), ISO_IP);
    registry.put(JARGON.value(), JARGON);
    registry.put(AED_512.value(), AED_512);
    registry.put(SQL_NET.value(), SQL_NET);
    registry.put(HEMS.value(), HEMS);
    registry.put(BFTP.value(), BFTP);
    registry.put(SGMP.value(), SGMP);
    registry.put(NETSC_PROD.value(), NETSC_PROD);
    registry.put(NETSC_DEV.value(), NETSC_DEV);
    registry.put(SQLSRV.value(), SQLSRV);
    registry.put(KNET_CMP.value(), KNET_CMP);
    registry.put(PCMAIL_SRV.value(), PCMAIL_SRV);
    registry.put(NSS_ROUTING.value(), NSS_ROUTING);
    registry.put(SGMP_TRAPS.value(), SGMP_TRAPS);
    registry.put(SNMP.value(), SNMP);
    registry.put(SNMP_TRAP.value(), SNMP_TRAP);
    registry.put(CMIP_MAN.value(), CMIP_MAN);
    registry.put(CMIP_AGENT.value(), CMIP_AGENT);
    registry.put(XNS_COURIER.value(), XNS_COURIER);
    registry.put(S_NET.value(), S_NET);
    registry.put(NAMP.value(), NAMP);
    registry.put(RSVD.value(), RSVD);
    registry.put(SEND.value(), SEND);
    registry.put(PRINT_SRV.value(), PRINT_SRV);
    registry.put(MULTIPLEX.value(), MULTIPLEX);
    registry.put(CL_1.value(), CL_1);
    registry.put(XYPLEX_MUX.value(), XYPLEX_MUX);
    registry.put(MAILQ.value(), MAILQ);
    registry.put(VMNET.value(), VMNET);
    registry.put(GENRAD_MUX.value(), GENRAD_MUX);
    registry.put(XDMCP.value(), XDMCP);
    registry.put(NEXTSTEP.value(), NEXTSTEP);
    registry.put(BGP.value(), BGP);
    registry.put(RIS.value(), RIS);
    registry.put(UNIFY.value(), UNIFY);
    registry.put(AUDIT.value(), AUDIT);
    registry.put(OCBINDER.value(), OCBINDER);
    registry.put(OCSERVER.value(), OCSERVER);
    registry.put(REMOTE_KIS.value(), REMOTE_KIS);
    registry.put(KIS.value(), KIS);
    registry.put(ACI.value(), ACI);
    registry.put(MUMPS.value(), MUMPS);
    registry.put(QFT.value(), QFT);
    registry.put(GACP.value(), GACP);
    registry.put(PROSPERO.value(), PROSPERO);
    registry.put(OSU_NMS.value(), OSU_NMS);
    registry.put(SRMP.value(), SRMP);
    registry.put(IRC.value(), IRC);
    registry.put(DN6_NLM_AUD.value(), DN6_NLM_AUD);
    registry.put(DN6_SMM_RED.value(), DN6_SMM_RED);
    registry.put(DLS.value(), DLS);
    registry.put(DLS_MON.value(), DLS_MON);
    registry.put(SMUX.value(), SMUX);
    registry.put(SRC.value(), SRC);
    registry.put(AT_RTMP.value(), AT_RTMP);
    registry.put(AT_NBP.value(), AT_NBP);
    registry.put(AT_3.value(), AT_3);
    registry.put(AT_ECHO.value(), AT_ECHO);
    registry.put(AT_5.value(), AT_5);
    registry.put(AT_ZIS.value(), AT_ZIS);
    registry.put(AT_7.value(), AT_7);
    registry.put(AT_8.value(), AT_8);
    registry.put(QMTP.value(), QMTP);
    registry.put(Z39_50.value(), Z39_50);
    registry.put(TEXAS_INSTRUMENTS_914C_G.value(), TEXAS_INSTRUMENTS_914C_G);
    registry.put(ANET.value(), ANET);
    registry.put(IPX.value(), IPX);
    registry.put(VMPWSCS.value(), VMPWSCS);
    registry.put(SOFTPC.value(), SOFTPC);
    registry.put(CAILIC.value(), CAILIC);
    registry.put(DBASE.value(), DBASE);
    registry.put(MPP.value(), MPP);
    registry.put(UARPS.value(), UARPS);
    registry.put(IMAP3.value(), IMAP3);
    registry.put(FLN_SPX.value(), FLN_SPX);
    registry.put(RSH_SPX.value(), RSH_SPX);
    registry.put(CDC.value(), CDC);
    registry.put(MASQDIALER.value(), MASQDIALER);
    registry.put(DIRECT.value(), DIRECT);
    registry.put(SUR_MEAS.value(), SUR_MEAS);
    registry.put(INBUSINESS.value(), INBUSINESS);
    registry.put(LINK.value(), LINK);
    registry.put(DSP3270.value(), DSP3270);
    registry.put(SUBNTBCST_TFTP.value(), SUBNTBCST_TFTP);
    registry.put(BHFHS.value(), BHFHS);
    registry.put(SET.value(), SET);
    registry.put(ESRO_GEN.value(), ESRO_GEN);
    registry.put(OPENPORT.value(), OPENPORT);
    registry.put(NSIIOPS.value(), NSIIOPS);
    registry.put(ARCISDMS.value(), ARCISDMS);
    registry.put(HDAP.value(), HDAP);
    registry.put(BGMP.value(), BGMP);
    registry.put(X_BONE_CTL.value(), X_BONE_CTL);
    registry.put(SST.value(), SST);
    registry.put(TD_SERVICE.value(), TD_SERVICE);
    registry.put(TD_REPLICA.value(), TD_REPLICA);
    registry.put(MANET.value(), MANET);
    registry.put(GIST.value(), GIST);
    registry.put(HTTP_MGMT.value(), HTTP_MGMT);
    registry.put(PERSONAL_LINK.value(), PERSONAL_LINK);
    registry.put(CABLEPORT_AX.value(), CABLEPORT_AX);
    registry.put(RESCAP.value(), RESCAP);
    registry.put(CORERJD.value(), CORERJD);
    registry.put(FXP.value(), FXP);
    registry.put(K_BLOCK.value(), K_BLOCK);
    registry.put(NOVASTORBAKCUP.value(), NOVASTORBAKCUP);
    registry.put(ENTRUSTTIME.value(), ENTRUSTTIME);
    registry.put(BHMDS.value(), BHMDS);
    registry.put(ASIP_WEBADMIN.value(), ASIP_WEBADMIN);
    registry.put(VSLMP.value(), VSLMP);
    registry.put(MAGENTA_LOGIC.value(), MAGENTA_LOGIC);
    registry.put(OPALIS_ROBOT.value(), OPALIS_ROBOT);
    registry.put(DPSI.value(), DPSI);
    registry.put(DECAUTH.value(), DECAUTH);
    registry.put(ZANNET.value(), ZANNET);
    registry.put(PKIX_TIMESTAMP.value(), PKIX_TIMESTAMP);
    registry.put(PTP_EVENT.value(), PTP_EVENT);
    registry.put(PTP_GENERAL.value(), PTP_GENERAL);
    registry.put(PIP.value(), PIP);
    registry.put(RTSPS.value(), RTSPS);
    registry.put(TEXAR.value(), TEXAR);
    registry.put(PDAP.value(), PDAP);
    registry.put(PAWSERV.value(), PAWSERV);
    registry.put(ZSERV.value(), ZSERV);
    registry.put(FATSERV.value(), FATSERV);
    registry.put(CSI_SGWP.value(), CSI_SGWP);
    registry.put(MFTP.value(), MFTP);
    registry.put(MATIP_TYPE_A.value(), MATIP_TYPE_A);
    registry.put(MATIP_TYPE_B.value(), MATIP_TYPE_B);
    registry.put(DTAG_STE_SB.value(), DTAG_STE_SB);
    registry.put(NDSAUTH.value(), NDSAUTH);
    registry.put(BH611.value(), BH611);
    registry.put(DATEX_ASN.value(), DATEX_ASN);
    registry.put(CLOANTO_NET_1.value(), CLOANTO_NET_1);
    registry.put(BHEVENT.value(), BHEVENT);
    registry.put(SHRINKWRAP.value(), SHRINKWRAP);
    registry.put(NSRMP.value(), NSRMP);
    registry.put(SCOI2ODIALOG.value(), SCOI2ODIALOG);
    registry.put(SEMANTIX.value(), SEMANTIX);
    registry.put(SRSSEND.value(), SRSSEND);
    registry.put(RSVP_TUNNEL.value(), RSVP_TUNNEL);
    registry.put(AURORA_CMGR.value(), AURORA_CMGR);
    registry.put(DTK.value(), DTK);
    registry.put(ODMR.value(), ODMR);
    registry.put(MORTGAGEWARE.value(), MORTGAGEWARE);
    registry.put(QBIKGDP.value(), QBIKGDP);
    registry.put(RPC2PORTMAP.value(), RPC2PORTMAP);
    registry.put(CODAAUTH2.value(), CODAAUTH2);
    registry.put(CLEARCASE.value(), CLEARCASE);
    registry.put(ULISTPROC.value(), ULISTPROC);
    registry.put(LEGENT_1.value(), LEGENT_1);
    registry.put(LEGENT_2.value(), LEGENT_2);
    registry.put(HASSLE.value(), HASSLE);
    registry.put(NIP.value(), NIP);
    registry.put(TNETOS.value(), TNETOS);
    registry.put(DSETOS.value(), DSETOS);
    registry.put(IS99C.value(), IS99C);
    registry.put(IS99S.value(), IS99S);
    registry.put(HP_COLLECTOR.value(), HP_COLLECTOR);
    registry.put(HP_MANAGED_NODE.value(), HP_MANAGED_NODE);
    registry.put(HP_ALARM_MGR.value(), HP_ALARM_MGR);
    registry.put(ARNS.value(), ARNS);
    registry.put(IBM_APP.value(), IBM_APP);
    registry.put(ASA.value(), ASA);
    registry.put(AURP.value(), AURP);
    registry.put(UNIDATA_LDM.value(), UNIDATA_LDM);
    registry.put(LDAP.value(), LDAP);
    registry.put(UIS.value(), UIS);
    registry.put(SYNOTICS_RELAY.value(), SYNOTICS_RELAY);
    registry.put(SYNOTICS_BROKER.value(), SYNOTICS_BROKER);
    registry.put(META5.value(), META5);
    registry.put(EMBL_NDT.value(), EMBL_NDT);
    registry.put(NETCP.value(), NETCP);
    registry.put(NETWARE_IP.value(), NETWARE_IP);
    registry.put(MPTN.value(), MPTN);
    registry.put(KRYPTOLAN.value(), KRYPTOLAN);
    registry.put(ISO_TSAP_C2.value(), ISO_TSAP_C2);
    registry.put(OSB_SD.value(), OSB_SD);
    registry.put(UPS.value(), UPS);
    registry.put(GENIE.value(), GENIE);
    registry.put(DECAP.value(), DECAP);
    registry.put(NCED.value(), NCED);
    registry.put(NCLD.value(), NCLD);
    registry.put(IMSP.value(), IMSP);
    registry.put(TIMBUKTU.value(), TIMBUKTU);
    registry.put(PRM_SM.value(), PRM_SM);
    registry.put(PRM_NM.value(), PRM_NM);
    registry.put(DECLADEBUG.value(), DECLADEBUG);
    registry.put(RMT.value(), RMT);
    registry.put(SYNOPTICS_TRAP.value(), SYNOPTICS_TRAP);
    registry.put(SMSP.value(), SMSP);
    registry.put(INFOSEEK.value(), INFOSEEK);
    registry.put(BNET.value(), BNET);
    registry.put(SILVERPLATTER.value(), SILVERPLATTER);
    registry.put(ONMUX.value(), ONMUX);
    registry.put(HYPER_G.value(), HYPER_G);
    registry.put(ARIEL1.value(), ARIEL1);
    registry.put(SMPTE.value(), SMPTE);
    registry.put(ARIEL2.value(), ARIEL2);
    registry.put(ARIEL3.value(), ARIEL3);
    registry.put(OPC_JOB_START.value(), OPC_JOB_START);
    registry.put(OPC_JOB_TRACK.value(), OPC_JOB_TRACK);
    registry.put(ICAD_EL.value(), ICAD_EL);
    registry.put(SMARTSDP.value(), SMARTSDP);
    registry.put(SVRLOC.value(), SVRLOC);
    registry.put(OCS_CMU.value(), OCS_CMU);
    registry.put(OCS_AMU.value(), OCS_AMU);
    registry.put(UTMPSD.value(), UTMPSD);
    registry.put(UTMPCD.value(), UTMPCD);
    registry.put(IASD.value(), IASD);
    registry.put(NNSP.value(), NNSP);
    registry.put(MOBILEIP_AGENT.value(), MOBILEIP_AGENT);
    registry.put(MOBILIP_MN.value(), MOBILIP_MN);
    registry.put(DNA_CML.value(), DNA_CML);
    registry.put(COMSCM.value(), COMSCM);
    registry.put(DSFGW.value(), DSFGW);
    registry.put(DASP.value(), DASP);
    registry.put(SGCP.value(), SGCP);
    registry.put(DECVMS_SYSMGT.value(), DECVMS_SYSMGT);
    registry.put(CVC_HOSTD.value(), CVC_HOSTD);
    registry.put(HTTPS.value(), HTTPS);
    registry.put(SNPP.value(), SNPP);
    registry.put(MICROSOFT_DS.value(), MICROSOFT_DS);
    registry.put(DDM_RDB.value(), DDM_RDB);
    registry.put(DDM_DFM.value(), DDM_DFM);
    registry.put(DDM_SSL.value(), DDM_SSL);
    registry.put(AS_SERVERMAP.value(), AS_SERVERMAP);
    registry.put(TSERVER.value(), TSERVER);
    registry.put(SFS_SMP_NET.value(), SFS_SMP_NET);
    registry.put(SFS_CONFIG.value(), SFS_CONFIG);
    registry.put(CREATIVESERVER.value(), CREATIVESERVER);
    registry.put(CONTENTSERVER.value(), CONTENTSERVER);
    registry.put(CREATIVEPARTNR.value(), CREATIVEPARTNR);
    registry.put(MACON_UDP.value(), MACON_UDP);
    registry.put(SCOHELP.value(), SCOHELP);
    registry.put(APPLEQTC.value(), APPLEQTC);
    registry.put(AMPR_RCMD.value(), AMPR_RCMD);
    registry.put(SKRONK.value(), SKRONK);
    registry.put(DATASURFSRV.value(), DATASURFSRV);
    registry.put(DATASURFSRVSEC.value(), DATASURFSRVSEC);
    registry.put(ALPES.value(), ALPES);
    registry.put(KPASSWD.value(), KPASSWD);
    registry.put(IGMPV3LITE.value(), IGMPV3LITE);
    registry.put(DIGITAL_VRC.value(), DIGITAL_VRC);
    registry.put(MYLEX_MAPD.value(), MYLEX_MAPD);
    registry.put(PHOTURIS.value(), PHOTURIS);
    registry.put(RCP.value(), RCP);
    registry.put(SCX_PROXY.value(), SCX_PROXY);
    registry.put(MONDEX.value(), MONDEX);
    registry.put(LJK_LOGIN.value(), LJK_LOGIN);
    registry.put(HYBRID_POP.value(), HYBRID_POP);
    registry.put(TN_TL_W2.value(), TN_TL_W2);
    registry.put(TCPNETHASPSRV.value(), TCPNETHASPSRV);
    registry.put(TN_TL_FD1.value(), TN_TL_FD1);
    registry.put(SS7NS.value(), SS7NS);
    registry.put(SPSC.value(), SPSC);
    registry.put(IAFSERVER.value(), IAFSERVER);
    registry.put(IAFDBASE.value(), IAFDBASE);
    registry.put(PH.value(), PH);
    registry.put(BGS_NSI.value(), BGS_NSI);
    registry.put(ULPNET.value(), ULPNET);
    registry.put(INTEGRA_SME.value(), INTEGRA_SME);
    registry.put(POWERBURST.value(), POWERBURST);
    registry.put(AVIAN.value(), AVIAN);
    registry.put(SAFT.value(), SAFT);
    registry.put(GSS_HTTP.value(), GSS_HTTP);
    registry.put(NEST_PROTOCOL.value(), NEST_PROTOCOL);
    registry.put(MICOM_PFS.value(), MICOM_PFS);
    registry.put(GO_LOGIN.value(), GO_LOGIN);
    registry.put(TICF_1.value(), TICF_1);
    registry.put(TICF_2.value(), TICF_2);
    registry.put(POV_RAY.value(), POV_RAY);
    registry.put(INTECOURIER.value(), INTECOURIER);
    registry.put(PIM_RP_DISC.value(), PIM_RP_DISC);
    registry.put(RETROSPECT.value(), RETROSPECT);
    registry.put(SIAM.value(), SIAM);
    registry.put(ISO_ILL.value(), ISO_ILL);
    registry.put(ISAKMP.value(), ISAKMP);
    registry.put(STMF.value(), STMF);
    registry.put(MBAP.value(), MBAP);
    registry.put(INTRINSA.value(), INTRINSA);
    registry.put(CITADEL.value(), CITADEL);
    registry.put(MAILBOX_LM.value(), MAILBOX_LM);
    registry.put(OHIMSRV.value(), OHIMSRV);
    registry.put(CRS.value(), CRS);
    registry.put(XVTTP.value(), XVTTP);
    registry.put(SNARE.value(), SNARE);
    registry.put(FCP.value(), FCP);
    registry.put(PASSGO.value(), PASSGO);
    registry.put(BIFF.value(), BIFF);
    registry.put(WHO.value(), WHO);
    registry.put(SYSLOG.value(), SYSLOG);
    registry.put(PRINTER.value(), PRINTER);
    registry.put(VIDEOTEX.value(), VIDEOTEX);
    registry.put(TALK.value(), TALK);
    registry.put(NTALK.value(), NTALK);
    registry.put(UTIME.value(), UTIME);
    registry.put(ROUTER.value(), ROUTER);
    registry.put(RIPNG.value(), RIPNG);
    registry.put(ULP.value(), ULP);
    registry.put(IBM_DB2.value(), IBM_DB2);
    registry.put(NCP.value(), NCP);
    registry.put(TIMED.value(), TIMED);
    registry.put(TEMPO.value(), TEMPO);
    registry.put(STX.value(), STX);
    registry.put(CUSTIX.value(), CUSTIX);
    registry.put(IRC_SERV.value(), IRC_SERV);
    registry.put(COURIER.value(), COURIER);
    registry.put(CONFERENCE.value(), CONFERENCE);
    registry.put(NETNEWS.value(), NETNEWS);
    registry.put(NETWALL.value(), NETWALL);
    registry.put(WINDREAM.value(), WINDREAM);
    registry.put(IIOP.value(), IIOP);
    registry.put(OPALIS_RDV.value(), OPALIS_RDV);
    registry.put(NMSP.value(), NMSP);
    registry.put(GDOMAP.value(), GDOMAP);
    registry.put(APERTUS_LDP.value(), APERTUS_LDP);
    registry.put(UUCP.value(), UUCP);
    registry.put(UUCP_RLOGIN.value(), UUCP_RLOGIN);
    registry.put(COMMERCE.value(), COMMERCE);
    registry.put(KLOGIN.value(), KLOGIN);
    registry.put(KSHELL.value(), KSHELL);
    registry.put(APPLEQTCSRVR.value(), APPLEQTCSRVR);
    registry.put(DHCPV6_CLIENT.value(), DHCPV6_CLIENT);
    registry.put(DHCPV6_SERVER.value(), DHCPV6_SERVER);
    registry.put(AFPOVERTCP.value(), AFPOVERTCP);
    registry.put(IDFP.value(), IDFP);
    registry.put(NEW_RWHO.value(), NEW_RWHO);
    registry.put(CYBERCASH.value(), CYBERCASH);
    registry.put(DEVSHR_NTS.value(), DEVSHR_NTS);
    registry.put(PIRP.value(), PIRP);
    registry.put(RTSP.value(), RTSP);
    registry.put(DSF.value(), DSF);
    registry.put(REMOTEFS.value(), REMOTEFS);
    registry.put(OPENVMS_SYSIPC.value(), OPENVMS_SYSIPC);
    registry.put(SDNSKMP.value(), SDNSKMP);
    registry.put(TEEDTAP.value(), TEEDTAP);
    registry.put(RMONITOR.value(), RMONITOR);
    registry.put(MONITOR.value(), MONITOR);
    registry.put(CHSHELL.value(), CHSHELL);
    registry.put(NNTPS.value(), NNTPS);
    registry.put(UDP_9PFS.value(), UDP_9PFS);
    registry.put(WHOAMI.value(), WHOAMI);
    registry.put(STREETTALK.value(), STREETTALK);
    registry.put(BANYAN_RPC.value(), BANYAN_RPC);
    registry.put(MS_SHUTTLE.value(), MS_SHUTTLE);
    registry.put(MS_ROME.value(), MS_ROME);
    registry.put(METER_DEMON.value(), METER_DEMON);
    registry.put(METER_UDEMON.value(), METER_UDEMON);
    registry.put(SONAR.value(), SONAR);
    registry.put(BANYAN_VIP.value(), BANYAN_VIP);
    registry.put(FTP_AGENT.value(), FTP_AGENT);
    registry.put(VEMMI.value(), VEMMI);
    registry.put(IPCD.value(), IPCD);
    registry.put(VNAS.value(), VNAS);
    registry.put(IPDD.value(), IPDD);
    registry.put(DECBSRV.value(), DECBSRV);
    registry.put(SNTP_HEARTBEAT.value(), SNTP_HEARTBEAT);
    registry.put(BDP.value(), BDP);
    registry.put(SCC_SECURITY.value(), SCC_SECURITY);
    registry.put(PHILIPS_VC.value(), PHILIPS_VC);
    registry.put(KEYSERVER.value(), KEYSERVER);
    registry.put(PASSWORD_CHG.value(), PASSWORD_CHG);
    registry.put(SUBMISSION.value(), SUBMISSION);
    registry.put(CAL.value(), CAL);
    registry.put(EYELINK.value(), EYELINK);
    registry.put(TNS_CML.value(), TNS_CML);
    registry.put(HTTP_ALT.value(), HTTP_ALT);
    registry.put(EUDORA_SET.value(), EUDORA_SET);
    registry.put(HTTP_RPC_EPMAP.value(), HTTP_RPC_EPMAP);
    registry.put(TPIP.value(), TPIP);
    registry.put(CAB_PROTOCOL.value(), CAB_PROTOCOL);
    registry.put(SMSD.value(), SMSD);
    registry.put(PTCNAMESERVICE.value(), PTCNAMESERVICE);
    registry.put(SCO_WEBSRVRMG3.value(), SCO_WEBSRVRMG3);
    registry.put(ACP.value(), ACP);
    registry.put(IPCSERVER.value(), IPCSERVER);
    registry.put(SYSLOG_CONN.value(), SYSLOG_CONN);
    registry.put(XMLRPC_BEEP.value(), XMLRPC_BEEP);
    registry.put(IDXP.value(), IDXP);
    registry.put(TUNNEL.value(), TUNNEL);
    registry.put(SOAP_BEEP.value(), SOAP_BEEP);
    registry.put(URM.value(), URM);
    registry.put(NQS.value(), NQS);
    registry.put(SIFT_UFT.value(), SIFT_UFT);
    registry.put(NPMP_TRAP.value(), NPMP_TRAP);
    registry.put(NPMP_LOCAL.value(), NPMP_LOCAL);
    registry.put(NPMP_GUI.value(), NPMP_GUI);
    registry.put(HMMP_IND.value(), HMMP_IND);
    registry.put(HMMP_OP.value(), HMMP_OP);
    registry.put(SSHELL.value(), SSHELL);
    registry.put(SCO_INETMGR.value(), SCO_INETMGR);
    registry.put(SCO_SYSMGR.value(), SCO_SYSMGR);
    registry.put(SCO_DTMGR.value(), SCO_DTMGR);
    registry.put(DEI_ICDA.value(), DEI_ICDA);
    registry.put(COMPAQ_EVM.value(), COMPAQ_EVM);
    registry.put(SCO_WEBSRVRMGR.value(), SCO_WEBSRVRMGR);
    registry.put(ESCP_IP.value(), ESCP_IP);
    registry.put(COLLABORATOR.value(), COLLABORATOR);
    registry.put(ASF_RMCP.value(), ASF_RMCP);
    registry.put(CRYPTOADMIN.value(), CRYPTOADMIN);
    registry.put(DEC_DLM.value(), DEC_DLM);
    registry.put(ASIA.value(), ASIA);
    registry.put(PASSGO_TIVOLI.value(), PASSGO_TIVOLI);
    registry.put(QMQP.value(), QMQP);
    registry.put(UDP_3COM_AMP3.value(), UDP_3COM_AMP3);
    registry.put(RDA.value(), RDA);
    registry.put(IPP.value(), IPP);
    registry.put(BMPP.value(), BMPP);
    registry.put(SERVSTAT.value(), SERVSTAT);
    registry.put(GINAD.value(), GINAD);
    registry.put(RLZDBASE.value(), RLZDBASE);
    registry.put(LDAPS.value(), LDAPS);
    registry.put(LANSERVER.value(), LANSERVER);
    registry.put(MCNS_SEC.value(), MCNS_SEC);
    registry.put(MSDP.value(), MSDP);
    registry.put(ENTRUST_SPS.value(), ENTRUST_SPS);
    registry.put(REPCMD.value(), REPCMD);
    registry.put(ESRO_EMSDP.value(), ESRO_EMSDP);
    registry.put(SANITY.value(), SANITY);
    registry.put(DWR.value(), DWR);
    registry.put(PSSC.value(), PSSC);
    registry.put(LDP.value(), LDP);
    registry.put(DHCP_FAILOVER.value(), DHCP_FAILOVER);
    registry.put(RRP.value(), RRP);
    registry.put(CADVIEW_3D.value(), CADVIEW_3D);
    registry.put(OBEX.value(), OBEX);
    registry.put(IEEE_MMS.value(), IEEE_MMS);
    registry.put(HELLO_PORT.value(), HELLO_PORT);
    registry.put(REPSCMD.value(), REPSCMD);
    registry.put(AODV.value(), AODV);
    registry.put(TINC.value(), TINC);
    registry.put(SPMP.value(), SPMP);
    registry.put(RMC.value(), RMC);
    registry.put(TENFOLD.value(), TENFOLD);
    registry.put(MAC_SRVR_ADMIN.value(), MAC_SRVR_ADMIN);
    registry.put(HAP.value(), HAP);
    registry.put(PFTP.value(), PFTP);
    registry.put(PURENOISE.value(), PURENOISE);
    registry.put(ASF_SECURE_RMCP.value(), ASF_SECURE_RMCP);
    registry.put(SUN_DR.value(), SUN_DR);
    registry.put(DOOM.value(), DOOM);
    registry.put(DISCLOSE.value(), DISCLOSE);
    registry.put(MECOMM.value(), MECOMM);
    registry.put(MEREGISTER.value(), MEREGISTER);
    registry.put(VACDSM_SWS.value(), VACDSM_SWS);
    registry.put(VACDSM_APP.value(), VACDSM_APP);
    registry.put(VPPS_QUA.value(), VPPS_QUA);
    registry.put(CIMPLEX.value(), CIMPLEX);
    registry.put(ACAP.value(), ACAP);
    registry.put(DCTP.value(), DCTP);
    registry.put(VPPS_VIA.value(), VPPS_VIA);
    registry.put(VPP.value(), VPP);
    registry.put(GGF_NCP.value(), GGF_NCP);
    registry.put(MRM.value(), MRM);
    registry.put(ENTRUST_AAAS.value(), ENTRUST_AAAS);
    registry.put(ENTRUST_AAMS.value(), ENTRUST_AAMS);
    registry.put(XFR.value(), XFR);
    registry.put(CORBA_IIOP.value(), CORBA_IIOP);
    registry.put(CORBA_IIOP_SSL.value(), CORBA_IIOP_SSL);
    registry.put(MDC_PORTMAPPER.value(), MDC_PORTMAPPER);
    registry.put(HCP_WISMAR.value(), HCP_WISMAR);
    registry.put(ASIPREGISTRY.value(), ASIPREGISTRY);
    registry.put(REALM_RUSD.value(), REALM_RUSD);
    registry.put(NMAP.value(), NMAP);
    registry.put(VATP.value(), VATP);
    registry.put(MSEXCH_ROUTING.value(), MSEXCH_ROUTING);
    registry.put(HYPERWAVE_ISP.value(), HYPERWAVE_ISP);
    registry.put(CONNENDP.value(), CONNENDP);
    registry.put(HA_CLUSTER.value(), HA_CLUSTER);
    registry.put(IEEE_MMS_SSL.value(), IEEE_MMS_SSL);
    registry.put(RUSHD.value(), RUSHD);
    registry.put(UUIDGEN.value(), UUIDGEN);
    registry.put(OLSR.value(), OLSR);
    registry.put(ACCESSNETWORK.value(), ACCESSNETWORK);
    registry.put(EPP.value(), EPP);
    registry.put(LMP.value(), LMP);
    registry.put(IRIS_BEEP.value(), IRIS_BEEP);
    registry.put(ELCSD.value(), ELCSD);
    registry.put(AGENTX.value(), AGENTX);
    registry.put(SILC.value(), SILC);
    registry.put(BORLAND_DSJ.value(), BORLAND_DSJ);
    registry.put(ENTRUST_KMSH.value(), ENTRUST_KMSH);
    registry.put(ENTRUST_ASH.value(), ENTRUST_ASH);
    registry.put(CISCO_TDP.value(), CISCO_TDP);
    registry.put(TBRPF.value(), TBRPF);
    registry.put(IRIS_XPC.value(), IRIS_XPC);
    registry.put(IRIS_XPCS.value(), IRIS_XPCS);
    registry.put(IRIS_LWZ.value(), IRIS_LWZ);
    registry.put(PANA.value(), PANA);
    registry.put(NETVIEWDM1.value(), NETVIEWDM1);
    registry.put(NETVIEWDM2.value(), NETVIEWDM2);
    registry.put(NETVIEWDM3.value(), NETVIEWDM3);
    registry.put(NETGW.value(), NETGW);
    registry.put(NETRCS.value(), NETRCS);
    registry.put(FLEXLM.value(), FLEXLM);
    registry.put(FUJITSU_DEV.value(), FUJITSU_DEV);
    registry.put(RIS_CM.value(), RIS_CM);
    registry.put(KERBEROS_ADM.value(), KERBEROS_ADM);
    registry.put(KERBEROS_IV.value(), KERBEROS_IV);
    registry.put(PUMP.value(), PUMP);
    registry.put(QRH.value(), QRH);
    registry.put(RRH.value(), RRH);
    registry.put(TELL.value(), TELL);
    registry.put(NLOGIN.value(), NLOGIN);
    registry.put(CON.value(), CON);
    registry.put(NS.value(), NS);
    registry.put(RXE.value(), RXE);
    registry.put(QUOTAD.value(), QUOTAD);
    registry.put(CYCLESERV.value(), CYCLESERV);
    registry.put(OMSERV.value(), OMSERV);
    registry.put(WEBSTER.value(), WEBSTER);
    registry.put(PHONEBOOK.value(), PHONEBOOK);
    registry.put(VID.value(), VID);
    registry.put(CADLOCK.value(), CADLOCK);
    registry.put(RTIP.value(), RTIP);
    registry.put(CYCLESERV2.value(), CYCLESERV2);
    registry.put(NOTIFY.value(), NOTIFY);
    registry.put(ACMAINT_DBD.value(), ACMAINT_DBD);
    registry.put(ACMAINT_TRANSD.value(), ACMAINT_TRANSD);
    registry.put(WPAGES.value(), WPAGES);
    registry.put(MULTILING_HTTP.value(), MULTILING_HTTP);
    registry.put(WPGS.value(), WPGS);
    registry.put(MDBS_DAEMON.value(), MDBS_DAEMON);
    registry.put(DEVICE.value(), DEVICE);
    registry.put(MBAP_S.value(), MBAP_S);
    registry.put(FCP_UDP.value(), FCP_UDP);
    registry.put(ITM_MCELL_S.value(), ITM_MCELL_S);
    registry.put(PKIX_3_CA_RA.value(), PKIX_3_CA_RA);
    registry.put(NETCONF_SSH.value(), NETCONF_SSH);
    registry.put(NETCONF_BEEP.value(), NETCONF_BEEP);
    registry.put(NETCONFSOAPHTTP.value(), NETCONFSOAPHTTP);
    registry.put(NETCONFSOAPBEEP.value(), NETCONFSOAPBEEP);
    registry.put(DHCP_FAILOVER2.value(), DHCP_FAILOVER2);
    registry.put(GDOI.value(), GDOI);
    registry.put(ISCSI.value(), ISCSI);
    registry.put(OWAMP_CONTROL.value(), OWAMP_CONTROL);
    registry.put(TWAMP_CONTROL.value(), TWAMP_CONTROL);
    registry.put(RSYNC.value(), RSYNC);
    registry.put(ICLCNET_LOCATE.value(), ICLCNET_LOCATE);
    registry.put(ICLCNET_SVINFO.value(), ICLCNET_SVINFO);
    registry.put(ACCESSBUILDER.value(), ACCESSBUILDER);
    registry.put(OMGINITIALREFS.value(), OMGINITIALREFS);
    registry.put(SMPNAMERES.value(), SMPNAMERES);
    registry.put(IDEAFARM_DOOR.value(), IDEAFARM_DOOR);
    registry.put(IDEAFARM_PANIC.value(), IDEAFARM_PANIC);
    registry.put(KINK.value(), KINK);
    registry.put(XACT_BACKUP.value(), XACT_BACKUP);
    registry.put(APEX_MESH.value(), APEX_MESH);
    registry.put(APEX_EDGE.value(), APEX_EDGE);
    registry.put(FTPS_DATA.value(), FTPS_DATA);
    registry.put(FTPS.value(), FTPS);
    registry.put(NAS.value(), NAS);
    registry.put(TELNETS.value(), TELNETS);
    registry.put(IMAPS.value(), IMAPS);
    registry.put(POP3S.value(), POP3S);
    registry.put(VSINET.value(), VSINET);
    registry.put(MAITRD.value(), MAITRD);
    registry.put(PUPARP.value(), PUPARP);
    registry.put(APPLIX.value(), APPLIX);
    registry.put(CADLOCK2.value(), CADLOCK2);
    registry.put(SURF.value(), SURF);
    registry.put(GTP_C.value(), GTP_C);
    registry.put(GTP_U.value(), GTP_U);
    registry.put(GTP_PRIME.value(), GTP_PRIME);
  }

  /**
   * @param value value
   * @param name name
   */
  public UdpPort(Short value, String name) {
    super(value, name);
  }

  /**
   * @param value value
   * @return a UdpPort object.
   */
  public static UdpPort getInstance(Short value) {
    if (registry.containsKey(value)) {
      return registry.get(value);
    } else {
      return new UdpPort(value, "unknown");
    }
  }

  /**
   * @param port port
   * @return a UdpPort object.
   */
  public static UdpPort register(UdpPort port) {
    return registry.put(port.value(), port);
  }
}
