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
 * TCP Port
 *
 * @see <a
 *     href="http://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xml">IANA
 *     Registry</a>
 * @author Kaito Yamada
 * @since pcap4j 0.9.12
 */
public final class TcpPort extends Port {

  /** */
  private static final long serialVersionUID = 3906499626286793530L;

  /** TCP Port Service Multiplexer: 1 */
  public static final TcpPort TCPMUX = new TcpPort((short) 1, "TCP Port Service Multiplexer");

  /** Compressnet Management Utility: 2 */
  public static final TcpPort COMPRESSNET_MANAGEMENT_UTILITY =
      new TcpPort((short) 2, "Compressnet Management Utility");

  /** Compressnet Compression Process: 3 */
  public static final TcpPort COMPRESSNET_COMPRESSION_PROCESS =
      new TcpPort((short) 3, "Compressnet Compression Process");

  /** Remote Job Entry: 5 */
  public static final TcpPort RJE = new TcpPort((short) 5, "Remote Job Entry");

  /** Echo: 7 */
  public static final TcpPort ECHO = new TcpPort((short) 7, "Echo");

  /** Discard: 9 */
  public static final TcpPort DISCARD = new TcpPort((short) 9, "Discard");

  /** systat: 11 */
  public static final TcpPort SYSTAT = new TcpPort((short) 11, "systat");

  /** Daytime: 13 */
  public static final TcpPort DAYTIME = new TcpPort((short) 13, "Daytime");

  /** Quote of the Day: 17 */
  public static final TcpPort QOTD = new TcpPort((short) 17, "Quote of the Day");

  /** Message Send Protocol: 18 */
  public static final TcpPort MSP = new TcpPort((short) 18, "Message Send Protocol");

  /** Character Generator: 19 */
  public static final TcpPort CHARGEN = new TcpPort((short) 19, "Character Generator");

  /** File Transfer [Default Data]: 20 */
  public static final TcpPort FTP_DATA = new TcpPort((short) 20, "File Transfer [Default Data]");

  /** File Transfer [Control]: 21 */
  public static final TcpPort FTP = new TcpPort((short) 21, "File Transfer [Control]");

  /** The Secure Shell (SSH): 22 */
  public static final TcpPort SSH = new TcpPort((short) 22, "SSH");

  /** Telnet: 23 */
  public static final TcpPort TELNET = new TcpPort((short) 23, "Telnet");

  /** Simple Mail Transfer: 25 */
  public static final TcpPort SMTP = new TcpPort((short) 25, "SMTP");

  /** NSW User System FE: 27 */
  public static final TcpPort NSW_FE = new TcpPort((short) 27, "NSW User System FE");

  /** MSG ICP: 29 */
  public static final TcpPort MSG_ICP = new TcpPort((short) 29, "MSG ICP");

  /** MSG Authentication: 31 */
  public static final TcpPort MSG_AUTH = new TcpPort((short) 31, "MSG Authentication");

  /** Display Support Protocol: 33 */
  public static final TcpPort DSP = new TcpPort((short) 33, "Display Support Protocol");

  /** Time: 37 */
  public static final TcpPort TIME = new TcpPort((short) 37, "Time");

  /** Route Access Protocol: 38 */
  public static final TcpPort RAP = new TcpPort((short) 38, "Route Access Protocol");

  /** Resource Location Protocol: 39 */
  public static final TcpPort RLP = new TcpPort((short) 39, "Resource Location Protocol");

  /** Graphics: 41 */
  public static final TcpPort GRAPHICS = new TcpPort((short) 41, "Graphics");

  /** Host Name Server: 42 */
  public static final TcpPort NAMESERVER = new TcpPort((short) 42, "Host Name Server");

  /** Who Is: 43 */
  public static final TcpPort WHOIS = new TcpPort((short) 43, "Who Is");

  /** MPM FLAGS: 44 */
  public static final TcpPort MPM_FLAGS = new TcpPort((short) 44, "MPM FLAGS");

  /** Message Processing Module [recv]: 45 */
  public static final TcpPort MPM = new TcpPort((short) 45, "Message Processing Module [recv]");

  /** Message Processing Module [default send]: 46 */
  public static final TcpPort MPM_SND =
      new TcpPort((short) 46, "Message Processing Module [default send]");

  /** NI FTP: 47 */
  public static final TcpPort NI_FTP = new TcpPort((short) 47, "NI FTP");

  /** Digital Audit Daemon: 48 */
  public static final TcpPort AUDITD = new TcpPort((short) 48, "Digital Audit Daemon");

  /** Login Host Protocol (TACACS): 49 */
  public static final TcpPort TACACS = new TcpPort((short) 49, "Login Host Protocol (TACACS)");

  /** Remote Mail Checking Protocol: 50 */
  public static final TcpPort RE_MAIL_CK = new TcpPort((short) 50, "Remote Mail Checking Protocol");

  /** XNS Time Protocol: 52 */
  public static final TcpPort XNS_TIME = new TcpPort((short) 52, "XNS Time Protocol");

  /** Domain Name Server: 53 */
  public static final TcpPort DOMAIN = new TcpPort((short) 53, "Domain Name Server");

  /** XNS Clearinghouse: 54 */
  public static final TcpPort XNS_CH = new TcpPort((short) 54, "XNS Clearinghouse");

  /** ISI Graphics Language: 55 */
  public static final TcpPort ISI_GL = new TcpPort((short) 55, "ISI Graphics Language");

  /** XNS Authentication: 56 */
  public static final TcpPort XNS_AUTH = new TcpPort((short) 56, "XNS Authentication");

  /** XNS Mail: 58 */
  public static final TcpPort XNS_MAIL = new TcpPort((short) 58, "XNS Mail");

  /** NI MAIL: 61 */
  public static final TcpPort NI_MAIL = new TcpPort((short) 61, "NI MAIL");

  /** ACA Services: 62 */
  public static final TcpPort ACAS = new TcpPort((short) 62, "ACA Services");

  /** whois++: 63 */
  public static final TcpPort WHOIS_PP = new TcpPort((short) 63, "whois++");

  /** Communications Integrator (CI): 64 */
  public static final TcpPort COVIA = new TcpPort((short) 64, "Communications Integrator (CI)");

  /** TACACS-Database Service: 65 */
  public static final TcpPort TACACS_DS = new TcpPort((short) 65, "TACACS-Database Service");

  /** Oracle SQL*NET: 66 */
  public static final TcpPort ORACLE_SQL_NET = new TcpPort((short) 66, "Oracle SQL*NET");

  /** Bootstrap Protocol Server: 67 */
  public static final TcpPort BOOTPS = new TcpPort((short) 67, "Bootstrap Protocol Server");

  /** Bootstrap Protocol Client: 68 */
  public static final TcpPort BOOTPC = new TcpPort((short) 68, "Bootstrap Protocol Client");

  /** Trivial File Transfer: 69 */
  public static final TcpPort TFTP = new TcpPort((short) 69, "Trivial File Transfer");

  /** Gopher: 70 */
  public static final TcpPort GOPHER = new TcpPort((short) 70, "Gopher");

  /** Remote Job Service 1: 71 */
  public static final TcpPort NETRJS_1 = new TcpPort((short) 71, "Remote Job Service 1");

  /** Remote Job Service 2: 72 */
  public static final TcpPort NETRJS_2 = new TcpPort((short) 72, "Remote Job Service 2");

  /** Remote Job Service 3: 73 */
  public static final TcpPort NETRJS_3 = new TcpPort((short) 73, "Remote Job Service 3");

  /** Remote Job Service 4: 74 */
  public static final TcpPort NETRJS_4 = new TcpPort((short) 74, "Remote Job Service 4");

  /** Distributed External Object Store: 76 */
  public static final TcpPort DEOS = new TcpPort((short) 76, "Distributed External Object Store");

  /** vettcp: 78 */
  public static final TcpPort VETTCP = new TcpPort((short) 78, "vettcp");

  /** Finger: 79 */
  public static final TcpPort FINGER = new TcpPort((short) 79, "Finger");

  /** HTTP: 80 */
  public static final TcpPort HTTP = new TcpPort((short) 80, "HTTP");

  /** XFER Utility: 82 */
  public static final TcpPort XFER = new TcpPort((short) 82, "XFER Utility");

  /** MIT ML Device: 83 */
  public static final TcpPort MIT_ML_DEV_83 = new TcpPort((short) 83, "MIT ML Device");

  /** Common Trace Facility: 84 */
  public static final TcpPort CTF = new TcpPort((short) 84, "Common Trace Facility");

  /** MIT ML Device: 85 */
  public static final TcpPort MIT_ML_DEV_85 = new TcpPort((short) 85, "MIT ML Device");

  /** Micro Focus Cobol: 86 */
  public static final TcpPort MFCOBOL = new TcpPort((short) 86, "Micro Focus Cobol");

  /** Kerberos: 88 */
  public static final TcpPort KERBEROS = new TcpPort((short) 88, "Kerberos");

  /** SU/MIT Telnet Gateway: 89 */
  public static final TcpPort SU_MIT_TG = new TcpPort((short) 89, "SU/MIT Telnet Gateway");

  /** DNSIX Securit Attribute Token Map: 90 */
  public static final TcpPort DNSIX = new TcpPort((short) 90, "DNSIX Securit Attribute Token Map");

  /** MIT Dover Spooler: 91 */
  public static final TcpPort MIT_DOV = new TcpPort((short) 91, "MIT Dover Spooler");

  /** Network Printing Protocol: 92 */
  public static final TcpPort NPP = new TcpPort((short) 92, "Network Printing Protocol");

  /** Device Control Protocol: 93 */
  public static final TcpPort DCP = new TcpPort((short) 93, "Device Control Protocol");

  /** Tivoli Object Dispatcher: 94 */
  public static final TcpPort OBJCALL = new TcpPort((short) 94, "Tivoli Object Dispatcher");

  /** SUPDUP: 95 */
  public static final TcpPort SUPDUP = new TcpPort((short) 95, "SUPDUP");

  /** DIXIE Protocol Specification: 96 */
  public static final TcpPort DIXIE = new TcpPort((short) 96, "DIXIE Protocol Specification");

  /** Swift Remote Virtural File Protocol: 97 */
  public static final TcpPort SWIFT_RVF =
      new TcpPort((short) 97, "Swift Remote Virtural File Protocol");

  /** TAC News: 98 */
  public static final TcpPort TACNEWS = new TcpPort((short) 98, "TAC News");

  /** Metagram Relay: 99 */
  public static final TcpPort METAGRAM = new TcpPort((short) 99, "Metagram Relay");

  /** NIC Host Name Server: 101 */
  public static final TcpPort HOSTNAME = new TcpPort((short) 101, "NIC Host Name Server");

  /** ISO-TSAP Class 0: 102 */
  public static final TcpPort ISO_TSAP = new TcpPort((short) 102, "ISO-TSAP Class 0");

  /** Genesis Point-to-Point Trans Net: 103 */
  public static final TcpPort GPPITNP =
      new TcpPort((short) 103, "Genesis Point-to-Point Trans Net");

  /** ACR-NEMA DICOM 300: 104 */
  public static final TcpPort ACR_NEMA = new TcpPort((short) 104, "ACR-NEMA DICOM 300");

  /** CCSO Nameserver Protocol: 105 */
  public static final TcpPort CSO = new TcpPort((short) 105, "CCSO Nameserver Protocol");

  /** 3COM-TSMUX: 106 */
  public static final TcpPort TCP_3COM_TSMUX = new TcpPort((short) 106, "3COM-TSMUX");

  /** Remote Telnet Service: 107 */
  public static final TcpPort RTELNET = new TcpPort((short) 107, "Remote Telnet Service");

  /** SNA Gateway Access Server: 108 */
  public static final TcpPort SNAGAS = new TcpPort((short) 108, "SNA Gateway Access Server");

  /** Post Office Protocol - Version 2: 109 */
  public static final TcpPort POP2 = new TcpPort((short) 109, "Post Office Protocol - Version 2");

  /** Post Office Protocol - Version 3: 110 */
  public static final TcpPort POP3 = new TcpPort((short) 110, "Post Office Protocol - Version 3");

  /** SUN Remote Procedure Call: 111 */
  public static final TcpPort SUNRPC = new TcpPort((short) 111, "SUN Remote Procedure Call");

  /** McIDAS Data Transmission Protocol: 112 */
  public static final TcpPort MCIDAS =
      new TcpPort((short) 112, "McIDAS Data Transmission Protocol");

  /** Authentication Service: 113 */
  public static final TcpPort AUTH = new TcpPort((short) 113, "Authentication Service");

  /** Simple File Transfer Protocol: 115 */
  public static final TcpPort SFTP = new TcpPort((short) 115, "Simple File Transfer Protocol");

  /** ANSA REX Notify: 116 */
  public static final TcpPort ANSANOTIFY = new TcpPort((short) 116, "ANSA REX Notify");

  /** UUCP Path Service: 117 */
  public static final TcpPort UUCP_PATH = new TcpPort((short) 117, "UUCP Path Service");

  /** SQL Services: 118 */
  public static final TcpPort SQLSERV = new TcpPort((short) 118, "SQL Services");

  /** Network News Transfer Protocol: 119 */
  public static final TcpPort NNTP = new TcpPort((short) 119, "Network News Transfer Protocol");

  /** CFDPTKT: 120 */
  public static final TcpPort CFDPTKT = new TcpPort((short) 120, "CFDPTKT");

  /** Encore Expedited Remote Pro.Call: 121 */
  public static final TcpPort ERPC = new TcpPort((short) 121, "Encore Expedited Remote Pro.Call");

  /** SMAKYNET: 122 */
  public static final TcpPort SMAKYNET = new TcpPort((short) 122, "SMAKYNET");

  /** Network Time Protocol: 123 */
  public static final TcpPort NTP = new TcpPort((short) 123, "Network Time Protocol");

  /** ANSA REX Trader: 124 */
  public static final TcpPort ANSATRADER = new TcpPort((short) 124, "ANSA REX Trader");

  /** Locus PC-Interface Net Map Server: 125 */
  public static final TcpPort LOCUS_MAP =
      new TcpPort((short) 125, "Locus PC-Interface Net Map Server");

  /** NXEdit: 126 */
  public static final TcpPort NXEDIT = new TcpPort((short) 126, "NXEdit");

  /** Locus PC-Interface Conn Server: 127 */
  public static final TcpPort LOCUS_CON =
      new TcpPort((short) 127, "Locus PC-Interface Conn Server");

  /** GSS X License Verification: 128 */
  public static final TcpPort GSS_XLICEN = new TcpPort((short) 128, "GSS X License Verification");

  /** Password Generator Protocol: 129 */
  public static final TcpPort PWDGEN = new TcpPort((short) 129, "Password Generator Protocol");

  /** Cisco FNATIVE: 130 */
  public static final TcpPort CISCO_FNA = new TcpPort((short) 130, "Cisco FNATIVE");

  /** Cisco TNATIVE: 131 */
  public static final TcpPort CISCO_TNA = new TcpPort((short) 131, "Cisco TNATIVE");

  /** Cisco SYSMAINT: 132 */
  public static final TcpPort CISCO_SYS = new TcpPort((short) 132, "Cisco SYSMAINT");

  /** Statistics Service: 133 */
  public static final TcpPort STATSRV = new TcpPort((short) 133, "Statistics Service");

  /** INGRES-NET Service: 134 */
  public static final TcpPort INGRES_NET = new TcpPort((short) 134, "INGRES-NET Service");

  /** DCE endpoint resolution: 135 */
  public static final TcpPort EPMAP = new TcpPort((short) 135, "DCE endpoint resolution");

  /** PROFILE Naming System: 136 */
  public static final TcpPort PROFILE = new TcpPort((short) 136, "PROFILE Naming System");

  /** NETBIOS Name Service: 137 */
  public static final TcpPort NETBIOS_NS = new TcpPort((short) 137, "NETBIOS Name Service");

  /** NETBIOS Datagram Service: 138 */
  public static final TcpPort NETBIOS_DGM = new TcpPort((short) 138, "NETBIOS Datagram Service");

  /** NETBIOS Session Service: 139 */
  public static final TcpPort NETBIOS_SSN = new TcpPort((short) 139, "NETBIOS Session Service");

  /** EMFIS Data Service: 140 */
  public static final TcpPort EMFIS_DATA = new TcpPort((short) 140, "EMFIS Data Service");

  /** EMFIS Control Service: 141 */
  public static final TcpPort EMFIS_CNTL = new TcpPort((short) 141, "EMFIS Control Service");

  /** Britton-Lee IDM: 142 */
  public static final TcpPort BL_IDM = new TcpPort((short) 142, "Britton-Lee IDM");

  /** Internet Message Access Protocol: 143 */
  public static final TcpPort IMAP = new TcpPort((short) 143, "Internet Message Access Protocol");

  /** Universal Management Architecture: 144 */
  public static final TcpPort UMA = new TcpPort((short) 144, "Universal Management Architecture");

  /** UAAC Protocol: 145 */
  public static final TcpPort UAAC = new TcpPort((short) 145, "UAAC Protocol");

  /** ISO-IP0: 146 */
  public static final TcpPort ISO_TP0 = new TcpPort((short) 146, "ISO-IP0");

  /** ISO-IP: 147 */
  public static final TcpPort ISO_IP = new TcpPort((short) 147, "ISO-IP");

  /** Jargon: 148 */
  public static final TcpPort JARGON = new TcpPort((short) 148, "Jargon");

  /** AED 512 Emulation Service: 149 */
  public static final TcpPort AED_512 = new TcpPort((short) 149, "AED 512 Emulation Service");

  /** SQL-NET: 150 */
  public static final TcpPort SQL_NET = new TcpPort((short) 150, "SQL-NET");

  /** HEMS: 151 */
  public static final TcpPort HEMS = new TcpPort((short) 151, "HEMS");

  /** Background File Transfer Program: 152 */
  public static final TcpPort BFTP = new TcpPort((short) 152, "Background File Transfer Program");

  /** SGMP: 153 */
  public static final TcpPort SGMP = new TcpPort((short) 153, "SGMP");

  /** NETSC: 154 */
  public static final TcpPort NETSC_PROD = new TcpPort((short) 154, "NETSC");

  /** NETSC: 155 */
  public static final TcpPort NETSC_DEV = new TcpPort((short) 155, "NETSC");

  /** SQL Service: 156 */
  public static final TcpPort SQLSRV = new TcpPort((short) 156, "SQL Service");

  /** KNET/VM Command/Message Protocol: 157 */
  public static final TcpPort KNET_CMP =
      new TcpPort((short) 157, "KNET/VM Command/Message Protocol");

  /** PCMail Server: 158 */
  public static final TcpPort PCMAIL_SRV = new TcpPort((short) 158, "PCMail Server");

  /** NSS-Routing: 159 */
  public static final TcpPort NSS_ROUTING = new TcpPort((short) 159, "NSS-Routing");

  /** SGMP-TRAPS: 160 */
  public static final TcpPort SGMP_TRAPS = new TcpPort((short) 160, "SGMP-TRAPS");

  /** SNMP: 161 */
  public static final TcpPort SNMP = new TcpPort((short) 161, "SNMP");

  /** SNMP Trap: 162 */
  public static final TcpPort SNMP_TRAP = new TcpPort((short) 162, "SNMP Trap");

  /** CMIP/TCP Manager: 163 */
  public static final TcpPort CMIP_MAN = new TcpPort((short) 163, "CMIP/TCP Manager");

  /** CMIP/TCP Agent: 164 */
  public static final TcpPort CMIP_AGENT = new TcpPort((short) 164, "CMIP/TCP Agent");

  /** XNS Courier: 165 */
  public static final TcpPort XNS_COURIER = new TcpPort((short) 165, "XNS Courier");

  /** Sirius Systems: 166 */
  public static final TcpPort S_NET = new TcpPort((short) 166, "Sirius Systems");

  /** NAMP: 167 */
  public static final TcpPort NAMP = new TcpPort((short) 167, "NAMP");

  /** RSVD: 168 */
  public static final TcpPort RSVD = new TcpPort((short) 168, "RSVD");

  /** SEND: 169 */
  public static final TcpPort SEND = new TcpPort((short) 169, "SEND");

  /** Network PostScript: 170 */
  public static final TcpPort PRINT_SRV = new TcpPort((short) 170, "Network PostScript");

  /** Network Innovations Multiplex: 171 */
  public static final TcpPort MULTIPLEX = new TcpPort((short) 171, "Network Innovations Multiplex");

  /** Network Innovations CL/1: 172 */
  public static final TcpPort CL_1 = new TcpPort((short) 172, "Network Innovations CL/1");

  /** Xyplex: 173 */
  public static final TcpPort XYPLEX_MUX = new TcpPort((short) 173, "Xyplex");

  /** MAILQ: 174 */
  public static final TcpPort MAILQ = new TcpPort((short) 174, "MAILQ");

  /** VMNET: 175 */
  public static final TcpPort VMNET = new TcpPort((short) 175, "VMNET");

  /** GENRAD-MUX: 176 */
  public static final TcpPort GENRAD_MUX = new TcpPort((short) 176, "GENRAD-MUX");

  /** X Display Manager Control Protocol: 177 */
  public static final TcpPort XDMCP =
      new TcpPort((short) 177, "X Display Manager Control Protocol");

  /** NextStep Window Server: 178 */
  public static final TcpPort NEXTSTEP = new TcpPort((short) 178, "NextStep Window Server");

  /** Border Gateway Protocol: 179 */
  public static final TcpPort BGP = new TcpPort((short) 179, "Border Gateway Protocol");

  /** Intergraph: 180 */
  public static final TcpPort RIS = new TcpPort((short) 180, "Intergraph");

  /** Unify: 181 */
  public static final TcpPort UNIFY = new TcpPort((short) 181, "Unify");

  /** Unisys Audit SITP: 182 */
  public static final TcpPort AUDIT = new TcpPort((short) 182, "Unisys Audit SITP");

  /** OCBinder: 183 */
  public static final TcpPort OCBINDER = new TcpPort((short) 183, "OCBinder");

  /** OCServer: 184 */
  public static final TcpPort OCSERVER = new TcpPort((short) 184, "OCServer");

  /** Remote-KIS: 185 */
  public static final TcpPort REMOTE_KIS = new TcpPort((short) 185, "Remote-KIS");

  /** KIS Protocol: 186 */
  public static final TcpPort KIS = new TcpPort((short) 186, "KIS Protocol");

  /** Application Communication Interface: 187 */
  public static final TcpPort ACI = new TcpPort((short) 187, "Application Communication Interface");

  /** Plus Five's MUMPS: 188 */
  public static final TcpPort MUMPS = new TcpPort((short) 188, "Plus Five's MUMPS");

  /** Queued File Transport: 189 */
  public static final TcpPort QFT = new TcpPort((short) 189, "Queued File Transport");

  /** Gateway Access Control Protocol: 190 */
  public static final TcpPort GACP = new TcpPort((short) 190, "Gateway Access Control Protocol");

  /** Prospero Directory Service: 191 */
  public static final TcpPort PROSPERO = new TcpPort((short) 191, "Prospero Directory Service");

  /** OSU Network Monitoring System: 192 */
  public static final TcpPort OSU_NMS = new TcpPort((short) 192, "OSU Network Monitoring System");

  /** Spider Remote Monitoring Protocol: 193 */
  public static final TcpPort SRMP = new TcpPort((short) 193, "Spider Remote Monitoring Protocol");

  /** Internet Relay Chat Protocol: 194 */
  public static final TcpPort IRC = new TcpPort((short) 194, "Internet Relay Chat Protocol");

  /** DNSIX Network Level Module Audit: 195 */
  public static final TcpPort DN6_NLM_AUD =
      new TcpPort((short) 195, "DNSIX Network Level Module Audit");

  /** DNSIX Session Mgt Module Audit Redir: 196 */
  public static final TcpPort DN6_SMM_RED =
      new TcpPort((short) 196, "DNSIX Session Mgt Module Audit Redir");

  /** Directory Location Service: 197 */
  public static final TcpPort DLS = new TcpPort((short) 197, "Directory Location Service");

  /** Directory Location Service Monitor: 198 */
  public static final TcpPort DLS_MON =
      new TcpPort((short) 198, "Directory Location Service Monitor");

  /** SMUX: 199 */
  public static final TcpPort SMUX = new TcpPort((short) 199, "SMUX");

  /** IBM System Resource Controller: 200 */
  public static final TcpPort SRC = new TcpPort((short) 200, "IBM System Resource Controller");

  /** AppleTalk Routing Maintenance: 201 */
  public static final TcpPort AT_RTMP = new TcpPort((short) 201, "AppleTalk Routing Maintenance");

  /** AppleTalk Name Binding: 202 */
  public static final TcpPort AT_NBP = new TcpPort((short) 202, "AppleTalk Name Binding");

  /** AppleTalk Unused: 203 */
  public static final TcpPort AT_3 = new TcpPort((short) 203, "AppleTalk Unused");

  /** AppleTalk Echo: 204 */
  public static final TcpPort AT_ECHO = new TcpPort((short) 204, "AppleTalk Echo");

  /** AppleTalk Unused: 205 */
  public static final TcpPort AT_5 = new TcpPort((short) 205, "AppleTalk Unused");

  /** AppleTalk Zone Information: 206 */
  public static final TcpPort AT_ZIS = new TcpPort((short) 206, "AppleTalk Zone Information");

  /** AppleTalk Unused: 207 */
  public static final TcpPort AT_7 = new TcpPort((short) 207, "AppleTalk Unused");

  /** AppleTalk Unused: 208 */
  public static final TcpPort AT_8 = new TcpPort((short) 208, "AppleTalk Unused");

  /** The Quick Mail Transfer Protocol: 209 */
  public static final TcpPort QMTP = new TcpPort((short) 209, "The Quick Mail Transfer Protocol");

  /** ANSI Z39.50: 210 */
  public static final TcpPort Z39_50 = new TcpPort((short) 210, "ANSI Z39.50");

  /** Texas Instruments 914C/G Terminal: 211 */
  public static final TcpPort TEXAS_INSTRUMENTS_914C_G =
      new TcpPort((short) 211, "Texas Instruments 914C/G Terminal");

  /** ATEXSSTR: 212 */
  public static final TcpPort ANET = new TcpPort((short) 212, "ATEXSSTR");

  /** IPX: 213 */
  public static final TcpPort IPX = new TcpPort((short) 213, "IPX");

  /** VM PWSCS: 214 */
  public static final TcpPort VMPWSCS = new TcpPort((short) 214, "VM PWSCS");

  /** Insignia Solutions SoftPC: 215 */
  public static final TcpPort SOFTPC = new TcpPort((short) 215, "Insignia Solutions SoftPC");

  /** Computer Associates Int'l License Server: 216 */
  public static final TcpPort CAILIC =
      new TcpPort((short) 216, "Computer Associates Int'l License Server");

  /** dBASE Unix: 217 */
  public static final TcpPort DBASE = new TcpPort((short) 217, "dBASE Unix");

  /** Netix Message Posting Protocol: 218 */
  public static final TcpPort MPP = new TcpPort((short) 218, "Netix Message Posting Protocol");

  /** Unisys ARPs: 219 */
  public static final TcpPort UARPS = new TcpPort((short) 219, "Unisys ARPs");

  /** Interactive Mail Access Protocol v3: 220 */
  public static final TcpPort IMAP3 =
      new TcpPort((short) 220, "Interactive Mail Access Protocol v3");

  /** Berkeley rlogind with SPX auth: 221 */
  public static final TcpPort FLN_SPX = new TcpPort((short) 221, "Berkeley rlogind with SPX auth");

  /** Berkeley rshd with SPX auth: 222 */
  public static final TcpPort RSH_SPX = new TcpPort((short) 222, "Berkeley rshd with SPX auth");

  /** Certificate Distribution Center: 223 */
  public static final TcpPort CDC = new TcpPort((short) 223, "Certificate Distribution Center");

  /** masqdialer: 224 */
  public static final TcpPort MASQDIALER = new TcpPort((short) 224, "masqdialer");

  /** Direct: 242 */
  public static final TcpPort DIRECT = new TcpPort((short) 242, "Direct");

  /** Survey Measurement: 243 */
  public static final TcpPort SUR_MEAS = new TcpPort((short) 243, "Survey Measurement");

  /** inbusiness: 244 */
  public static final TcpPort INBUSINESS = new TcpPort((short) 244, "inbusiness");

  /** LINK: 245 */
  public static final TcpPort LINK = new TcpPort((short) 245, "LINK");

  /** Display Systems Protocol: 246 */
  public static final TcpPort DSP3270 = new TcpPort((short) 246, "Display Systems Protocol");

  /** SUBNTBCST_TFTP: 247 */
  public static final TcpPort SUBNTBCST_TFTP = new TcpPort((short) 247, "SUBNTBCST_TFTP");

  /** bhfhs: 248 */
  public static final TcpPort BHFHS = new TcpPort((short) 248, "bhfhs");

  /** Secure Electronic Transaction: 257 */
  public static final TcpPort SET = new TcpPort((short) 257, "Secure Electronic Transaction");

  /** Efficient Short Remote Operations: 259 */
  public static final TcpPort ESRO_GEN =
      new TcpPort((short) 259, "Efficient Short Remote Operations");

  /** Openport: 260 */
  public static final TcpPort OPENPORT = new TcpPort((short) 260, "Openport");

  /** IIOP Name Service over TLS/SSL: 261 */
  public static final TcpPort NSIIOPS = new TcpPort((short) 261, "IIOP Name Service over TLS/SSL");

  /** Arcisdms: 262 */
  public static final TcpPort ARCISDMS = new TcpPort((short) 262, "Arcisdms");

  /** HDAP: 263 */
  public static final TcpPort HDAP = new TcpPort((short) 263, "HDAP");

  /** BGMP: 264 */
  public static final TcpPort BGMP = new TcpPort((short) 264, "BGMP");

  /** X-Bone CTL: 265 */
  public static final TcpPort X_BONE_CTL = new TcpPort((short) 265, "X-Bone CTL");

  /** SCSI on ST: 266 */
  public static final TcpPort SST = new TcpPort((short) 266, "SCSI on ST");

  /** Tobit David Service Layer: 267 */
  public static final TcpPort TD_SERVICE = new TcpPort((short) 267, "Tobit David Service Layer");

  /** Tobit David Replica: 268 */
  public static final TcpPort TD_REPLICA = new TcpPort((short) 268, "Tobit David Replica");

  /** MANET Protocols: 269 */
  public static final TcpPort MANET = new TcpPort((short) 269, "MANET Protocols");

  /** IETF Network Endpoint Assessment (NEA) Posture Transport Protocol over TLS (PT-TLS): 271 */
  public static final TcpPort PT_TLS = new TcpPort((short) 271, "PT-TLS");

  /** HTTP-Mgmt: 280 */
  public static final TcpPort HTTP_MGMT = new TcpPort((short) 280, "HTTP-Mgmt");

  /** Personal Link: 281 */
  public static final TcpPort PERSONAL_LINK = new TcpPort((short) 281, "Personal Link");

  /** Cable Port A/X: 282 */
  public static final TcpPort CABLEPORT_AX = new TcpPort((short) 282, "Cable Port A/X");

  /** rescap: 283 */
  public static final TcpPort RESCAP = new TcpPort((short) 283, "rescap");

  /** corerjd: 284 */
  public static final TcpPort CORERJD = new TcpPort((short) 284, "corerjd");

  /** FXP Communication: 286 */
  public static final TcpPort FXP = new TcpPort((short) 286, "FXP Communication");

  /** K-BLOCK: 287 */
  public static final TcpPort K_BLOCK = new TcpPort((short) 287, "K-BLOCK");

  /** Novastor Backup: 308 */
  public static final TcpPort NOVASTORBAKCUP = new TcpPort((short) 308, "Novastor Backup");

  /** EntrustTime: 309 */
  public static final TcpPort ENTRUSTTIME = new TcpPort((short) 309, "EntrustTime");

  /** bhmds: 310 */
  public static final TcpPort BHMDS = new TcpPort((short) 310, "bhmds");

  /** AppleShare IP WebAdmin: 311 */
  public static final TcpPort ASIP_WEBADMIN = new TcpPort((short) 311, "AppleShare IP WebAdmin");

  /** VSLMP: 312 */
  public static final TcpPort VSLMP = new TcpPort((short) 312, "VSLMP");

  /** Magenta Logic: 313 */
  public static final TcpPort MAGENTA_LOGIC = new TcpPort((short) 313, "Magenta Logic");

  /** Opalis Robot: 314 */
  public static final TcpPort OPALIS_ROBOT = new TcpPort((short) 314, "Opalis Robot");

  /** DPSI: 315 */
  public static final TcpPort DPSI = new TcpPort((short) 315, "DPSI");

  /** decAuth: 316 */
  public static final TcpPort DECAUTH = new TcpPort((short) 316, "decAuth");

  /** Zannet: 317 */
  public static final TcpPort ZANNET = new TcpPort((short) 317, "Zannet");

  /** PKIX TimeStamp: 318 */
  public static final TcpPort PKIX_TIMESTAMP = new TcpPort((short) 318, "PKIX TimeStamp");

  /** PTP Event: 319 */
  public static final TcpPort PTP_EVENT = new TcpPort((short) 319, "PTP Event");

  /** PTP General: 320 */
  public static final TcpPort PTP_GENERAL = new TcpPort((short) 320, "PTP General");

  /** PIP: 321 */
  public static final TcpPort PIP = new TcpPort((short) 321, "PIP");

  /** RTSPS: 322 */
  public static final TcpPort RTSPS = new TcpPort((short) 322, "RTSPS");

  /** Resource PKI to Router Protocol: 323 */
  public static final TcpPort RPKI_RTR =
      new TcpPort((short) 323, "Resource PKI to Router Protocol");

  /** Resource PKI to Router Protocol over TLS: 324 */
  public static final TcpPort RPKI_RTR_TLS =
      new TcpPort((short) 324, "Resource PKI to Router Protocol over TLS");

  /** Texar Security Port: 333 */
  public static final TcpPort TEXAR = new TcpPort((short) 333, "Texar Security Port");

  /** Prospero Data Access Protocol: 344 */
  public static final TcpPort PDAP = new TcpPort((short) 344, "Prospero Data Access Protocol");

  /** Perf Analysis Workbench: 345 */
  public static final TcpPort PAWSERV = new TcpPort((short) 345, "Perf Analysis Workbench");

  /** Zebra server: 346 */
  public static final TcpPort ZSERV = new TcpPort((short) 346, "Zebra server");

  /** Fatmen Server: 347 */
  public static final TcpPort FATSERV = new TcpPort((short) 347, "Fatmen Server");

  /** Cabletron Management Protocol: 348 */
  public static final TcpPort CSI_SGWP = new TcpPort((short) 348, "Cabletron Management Protocol");

  /** MFTP: 349 */
  public static final TcpPort MFTP = new TcpPort((short) 349, "MFTP");

  /** MATIP Type A: 350 */
  public static final TcpPort MATIP_TYPE_A = new TcpPort((short) 350, "MATIP Type A");

  /** MATIP Type B: 351 */
  public static final TcpPort MATIP_TYPE_B = new TcpPort((short) 351, "MATIP Type B");

  /** DTAG: 352 */
  public static final TcpPort DTAG_STE_SB = new TcpPort((short) 352, "DTAG");

  /** NDSAUTH: 353 */
  public static final TcpPort NDSAUTH = new TcpPort((short) 353, "NDSAUTH");

  /** bh611: 354 */
  public static final TcpPort BH611 = new TcpPort((short) 354, "bh611");

  /** DATEX-ASN: 355 */
  public static final TcpPort DATEX_ASN = new TcpPort((short) 355, "DATEX-ASN");

  /** Cloanto Net 1: 356 */
  public static final TcpPort CLOANTO_NET_1 = new TcpPort((short) 356, "Cloanto Net 1");

  /** bhevent: 357 */
  public static final TcpPort BHEVENT = new TcpPort((short) 357, "bhevent");

  /** Shrinkwrap: 358 */
  public static final TcpPort SHRINKWRAP = new TcpPort((short) 358, "Shrinkwrap");

  /** Network Security Risk Management Protocol: 359 */
  public static final TcpPort NSRMP =
      new TcpPort((short) 359, "Network Security Risk Management Protocol");

  /** scoi2odialog: 360 */
  public static final TcpPort SCOI2ODIALOG = new TcpPort((short) 360, "scoi2odialog");

  /** Semantix: 361 */
  public static final TcpPort SEMANTIX = new TcpPort((short) 361, "Semantix");

  /** SRS Send: 362 */
  public static final TcpPort SRSSEND = new TcpPort((short) 362, "SRS Send");

  /** RSVP Tunnel: 363 */
  public static final TcpPort RSVP_TUNNEL = new TcpPort((short) 363, "RSVP Tunnel");

  /** Aurora CMGR: 364 */
  public static final TcpPort AURORA_CMGR = new TcpPort((short) 364, "Aurora CMGR");

  /** DTK: 365 */
  public static final TcpPort DTK = new TcpPort((short) 365, "DTK");

  /** ODMR: 366 */
  public static final TcpPort ODMR = new TcpPort((short) 366, "ODMR");

  /** MortgageWare: 367 */
  public static final TcpPort MORTGAGEWARE = new TcpPort((short) 367, "MortgageWare");

  /** QbikGDP: 368 */
  public static final TcpPort QBIKGDP = new TcpPort((short) 368, "QbikGDP");

  /** rpc2portmap: 369 */
  public static final TcpPort RPC2PORTMAP = new TcpPort((short) 369, "rpc2portmap");

  /** codaauth2: 370 */
  public static final TcpPort CODAAUTH2 = new TcpPort((short) 370, "codaauth2");

  /** Clearcase: 371 */
  public static final TcpPort CLEARCASE = new TcpPort((short) 371, "Clearcase");

  /** ListProcessor: 372 */
  public static final TcpPort ULISTPROC = new TcpPort((short) 372, "ListProcessor");

  /** Legent Corporation: 373 */
  public static final TcpPort LEGENT_1 = new TcpPort((short) 373, "Legent Corporation");

  /** Legent Corporation: 374 */
  public static final TcpPort LEGENT_2 = new TcpPort((short) 374, "Legent Corporation");

  /** Hassle: 375 */
  public static final TcpPort HASSLE = new TcpPort((short) 375, "Hassle");

  /** Amiga Envoy Network Inquiry Proto: 376 */
  public static final TcpPort NIP = new TcpPort((short) 376, "Amiga Envoy Network Inquiry Proto");

  /** NEC Corporation tnETOS: 377 */
  public static final TcpPort TNETOS = new TcpPort((short) 377, "tnETOS");

  /** NEC Corporation dsETOS: 378 */
  public static final TcpPort DSETOS = new TcpPort((short) 378, "dsETOS");

  /** TIA/EIA/IS-99 modem client: 379 */
  public static final TcpPort IS99C = new TcpPort((short) 379, "TIA/EIA/IS-99 modem client");

  /** TIA/EIA/IS-99 modem server: 380 */
  public static final TcpPort IS99S = new TcpPort((short) 380, "TIA/EIA/IS-99 modem server");

  /** HP performance data collector: 381 */
  public static final TcpPort HP_COLLECTOR =
      new TcpPort((short) 381, "HP performance data collector");

  /** HP performance data managed node: 382 */
  public static final TcpPort HP_MANAGED_NODE =
      new TcpPort((short) 382, "HP performance data managed node");

  /** HP performance data alarm manager: 383 */
  public static final TcpPort HP_ALARM_MGR =
      new TcpPort((short) 383, "HP performance data alarm manager");

  /** A Remote Network Server System: 384 */
  public static final TcpPort ARNS = new TcpPort((short) 384, "A Remote Network Server System");

  /** IBM Application: 385 */
  public static final TcpPort IBM_APP = new TcpPort((short) 385, "IBM Application");

  /** ASA Message Router Object Def.: 386 */
  public static final TcpPort ASA = new TcpPort((short) 386, "ASA Message Router Object Def.");

  /** Appletalk Update-Based Routing Pro.: 387 */
  public static final TcpPort AURP =
      new TcpPort((short) 387, "Appletalk Update-Based Routing Pro.");

  /** Unidata LDM: 388 */
  public static final TcpPort UNIDATA_LDM = new TcpPort((short) 388, "Unidata LDM");

  /** Lightweight Directory Access Protocol: 389 */
  public static final TcpPort LDAP =
      new TcpPort((short) 389, "Lightweight Directory Access Protocol");

  /** UIS: 390 */
  public static final TcpPort UIS = new TcpPort((short) 390, "UIS");

  /** SynOptics SNMP Relay Port: 391 */
  public static final TcpPort SYNOTICS_RELAY =
      new TcpPort((short) 391, "SynOptics SNMP Relay Port");

  /** SynOptics Port Broker Port: 392 */
  public static final TcpPort SYNOTICS_BROKER =
      new TcpPort((short) 392, "SynOptics Port Broker Port");

  /** Meta5: 393 */
  public static final TcpPort META5 = new TcpPort((short) 393, "Meta5");

  /** EMBL Nucleic Data Transfer: 394 */
  public static final TcpPort EMBL_NDT = new TcpPort((short) 394, "EMBL Nucleic Data Transfer");

  /** NetScout Control Protocol: 395 */
  public static final TcpPort NETCP = new TcpPort((short) 395, "NetScout Control Protocol");

  /** Novell Netware over IP: 396 */
  public static final TcpPort NETWARE_IP = new TcpPort((short) 396, "Novell Netware over IP");

  /** Multi Protocol Trans. Net.: 397 */
  public static final TcpPort MPTN = new TcpPort((short) 397, "Multi Protocol Trans. Net.");

  /** Kryptolan: 398 */
  public static final TcpPort KRYPTOLAN = new TcpPort((short) 398, "Kryptolan");

  /** ISO Transport Class 2 Non-Control over TCP: 399 */
  public static final TcpPort ISO_TSAP_C2 =
      new TcpPort((short) 399, "ISO Transport Class 2 Non-Control over TCP");

  /** Oracle Secure Backup: 400 */
  public static final TcpPort OSB_SD = new TcpPort((short) 400, "Oracle Secure Backup");

  /** Uninterruptible Power Supply: 401 */
  public static final TcpPort UPS = new TcpPort((short) 401, "Uninterruptible Power Supply");

  /** Genie Protocol: 402 */
  public static final TcpPort GENIE = new TcpPort((short) 402, "Genie Protocol");

  /** decap: 403 */
  public static final TcpPort DECAP = new TcpPort((short) 403, "decap");

  /** nced: 404 */
  public static final TcpPort NCED = new TcpPort((short) 404, "nced");

  /** ncld: 405 */
  public static final TcpPort NCLD = new TcpPort((short) 405, "ncld");

  /** Interactive Mail Support Protocol: 406 */
  public static final TcpPort IMSP = new TcpPort((short) 406, "Interactive Mail Support Protocol");

  /** Timbuktu: 407 */
  public static final TcpPort TIMBUKTU = new TcpPort((short) 407, "Timbuktu");

  /** Prospero Resource Manager Sys. Man.: 408 */
  public static final TcpPort PRM_SM =
      new TcpPort((short) 408, "Prospero Resource Manager Sys. Man.");

  /** Prospero Resource Manager Node Man.: 409 */
  public static final TcpPort PRM_NM =
      new TcpPort((short) 409, "Prospero Resource Manager Node Man.");

  /** DECLadebug Remote Debug Protocol: 410 */
  public static final TcpPort DECLADEBUG =
      new TcpPort((short) 410, "DECLadebug Remote Debug Protocol");

  /** Remote MT Protocol: 411 */
  public static final TcpPort RMT = new TcpPort((short) 411, "Remote MT Protocol");

  /** Trap Convention Port: 412 */
  public static final TcpPort SYNOPTICS_TRAP = new TcpPort((short) 412, "Trap Convention Port");

  /** Storage Management Services Protocol: 413 */
  public static final TcpPort SMSP =
      new TcpPort((short) 413, "Storage Management Services Protocol");

  /** InfoSeek: 414 */
  public static final TcpPort INFOSEEK = new TcpPort((short) 414, "InfoSeek");

  /** BNet: 415 */
  public static final TcpPort BNET = new TcpPort((short) 415, "BNet");

  /** Silverplatter: 416 */
  public static final TcpPort SILVERPLATTER = new TcpPort((short) 416, "Silverplatter");

  /** Onmux: 417 */
  public static final TcpPort ONMUX = new TcpPort((short) 417, "Onmux");

  /** Hyper-G: 418 */
  public static final TcpPort HYPER_G = new TcpPort((short) 418, "Hyper-G");

  /** Ariel 1: 419 */
  public static final TcpPort ARIEL1 = new TcpPort((short) 419, "Ariel 1");

  /** SMPTE: 420 */
  public static final TcpPort SMPTE = new TcpPort((short) 420, "SMPTE");

  /** Ariel 2: 421 */
  public static final TcpPort ARIEL2 = new TcpPort((short) 421, "Ariel 2");

  /** Ariel 3: 422 */
  public static final TcpPort ARIEL3 = new TcpPort((short) 422, "Ariel 3");

  /** IBM Operations Planning and Control Start: 423 */
  public static final TcpPort OPC_JOB_START =
      new TcpPort((short) 423, "IBM Operations Planning and Control Start");

  /** IBM Operations Planning and Control Track: 424 */
  public static final TcpPort OPC_JOB_TRACK =
      new TcpPort((short) 424, "IBM Operations Planning and Control Track");

  /** ICAD: 425 */
  public static final TcpPort ICAD_EL = new TcpPort((short) 425, "ICAD");

  /** smartsdp: 426 */
  public static final TcpPort SMARTSDP = new TcpPort((short) 426, "smartsdp");

  /** Server Location: 427 */
  public static final TcpPort SVRLOC = new TcpPort((short) 427, "Server Location");

  /** OCS_CMU: 428 */
  public static final TcpPort OCS_CMU = new TcpPort((short) 428, "OCS_CMU");

  /** OCS_AMU: 429 */
  public static final TcpPort OCS_AMU = new TcpPort((short) 429, "OCS_AMU");

  /** UTMPSD: 430 */
  public static final TcpPort UTMPSD = new TcpPort((short) 430, "UTMPSD");

  /** UTMPCD: 431 */
  public static final TcpPort UTMPCD = new TcpPort((short) 431, "UTMPCD");

  /** IASD: 432 */
  public static final TcpPort IASD = new TcpPort((short) 432, "IASD");

  /** NNSP: 433 */
  public static final TcpPort NNSP = new TcpPort((short) 433, "NNSP");

  /** MobileIP-Agent: 434 */
  public static final TcpPort MOBILEIP_AGENT = new TcpPort((short) 434, "MobileIP-Agent");

  /** MobilIP-MN: 435 */
  public static final TcpPort MOBILIP_MN = new TcpPort((short) 435, "MobilIP-MN");

  /** DNA-CML: 436 */
  public static final TcpPort DNA_CML = new TcpPort((short) 436, "DNA-CML");

  /** comscm: 437 */
  public static final TcpPort COMSCM = new TcpPort((short) 437, "comscm");

  /** dsfgw: 438 */
  public static final TcpPort DSFGW = new TcpPort((short) 438, "dsfgw");

  /** dasp: 439 */
  public static final TcpPort DASP = new TcpPort((short) 439, "dasp");

  /** sgcp: 440 */
  public static final TcpPort SGCP = new TcpPort((short) 440, "sgcp");

  /** decvms-sysmgt: 441 */
  public static final TcpPort DECVMS_SYSMGT = new TcpPort((short) 441, "decvms-sysmgt");

  /** cvc_hostd: 442 */
  public static final TcpPort CVC_HOSTD = new TcpPort((short) 442, "cvc_hostd");

  /** HTTPS: 443 */
  public static final TcpPort HTTPS = new TcpPort((short) 443, "HTTPS");

  /** Simple Network Paging Protocol: 444 */
  public static final TcpPort SNPP = new TcpPort((short) 444, "Simple Network Paging Protocol");

  /** Microsoft-DS: 445 */
  public static final TcpPort MICROSOFT_DS = new TcpPort((short) 445, "Microsoft-DS");

  /** DDM-Remote Relational Database Access: 446 */
  public static final TcpPort DDM_RDB =
      new TcpPort((short) 446, "DDM-Remote Relational Database Access");

  /** DDM-Distributed File Management: 447 */
  public static final TcpPort DDM_DFM = new TcpPort((short) 447, "DDM-Distributed File Management");

  /** DDM-Remote DB Access Using Secure Sockets: 448 */
  public static final TcpPort DDM_SSL =
      new TcpPort((short) 448, "DDM-Remote DB Access Using Secure Sockets");

  /** AS Server Mapper: 449 */
  public static final TcpPort AS_SERVERMAP = new TcpPort((short) 449, "AS Server Mapper");

  /** Computer Supported Telecomunication Applications: 450 */
  public static final TcpPort TSERVER =
      new TcpPort((short) 450, "Computer Supported Telecomunication Applications");

  /** Cray Network Semaphore server: 451 */
  public static final TcpPort SFS_SMP_NET =
      new TcpPort((short) 451, "Cray Network Semaphore server");

  /** Cray SFS config server: 452 */
  public static final TcpPort SFS_CONFIG = new TcpPort((short) 452, "Cray SFS config server");

  /** CreativeServer: 453 */
  public static final TcpPort CREATIVESERVER = new TcpPort((short) 453, "CreativeServer");

  /** ContentServer: 454 */
  public static final TcpPort CONTENTSERVER = new TcpPort((short) 454, "ContentServer");

  /** CreativePartnr: 455 */
  public static final TcpPort CREATIVEPARTNR = new TcpPort((short) 455, "CreativePartnr");

  /** macon-tcp: 456 */
  public static final TcpPort MACON_TCP = new TcpPort((short) 456, "macon-tcp");

  /** scohelp: 457 */
  public static final TcpPort SCOHELP = new TcpPort((short) 457, "scohelp");

  /** apple quick time: 458 */
  public static final TcpPort APPLEQTC = new TcpPort((short) 458, "apple quick time");

  /** ampr-rcmd: 459 */
  public static final TcpPort AMPR_RCMD = new TcpPort((short) 459, "ampr-rcmd");

  /** skronk: 460 */
  public static final TcpPort SKRONK = new TcpPort((short) 460, "skronk");

  /** DataRampSrv: 461 */
  public static final TcpPort DATASURFSRV = new TcpPort((short) 461, "DataRampSrv");

  /** DataRampSrvSec: 462 */
  public static final TcpPort DATASURFSRVSEC = new TcpPort((short) 462, "DataRampSrvSec");

  /** alpes: 463 */
  public static final TcpPort ALPES = new TcpPort((short) 463, "alpes");

  /** kpasswd: 464 */
  public static final TcpPort KPASSWD = new TcpPort((short) 464, "kpasswd");

  /** URL Rendesvous Directory for SSM: 465 */
  public static final TcpPort URD = new TcpPort((short) 465, "URL Rendesvous Directory for SSM");

  /** digital-vrc: 466 */
  public static final TcpPort DIGITAL_VRC = new TcpPort((short) 466, "digital-vrc");

  /** mylex-mapd: 467 */
  public static final TcpPort MYLEX_MAPD = new TcpPort((short) 467, "mylex-mapd");

  /** proturis: 468 */
  public static final TcpPort PHOTURIS = new TcpPort((short) 468, "proturis");

  /** Radio Control Protocol: 469 */
  public static final TcpPort RCP = new TcpPort((short) 469, "Radio Control Protocol");

  /** scx-proxy: 470 */
  public static final TcpPort SCX_PROXY = new TcpPort((short) 470, "scx-proxy");

  /** Mondex: 471 */
  public static final TcpPort MONDEX = new TcpPort((short) 471, "Mondex");

  /** ljk-login: 472 */
  public static final TcpPort LJK_LOGIN = new TcpPort((short) 472, "ljk-login");

  /** hybrid-pop: 473 */
  public static final TcpPort HYBRID_POP = new TcpPort((short) 473, "hybrid-pop");

  /** tn-tl-w1: 474 */
  public static final TcpPort TN_TL_W1 = new TcpPort((short) 474, "tn-tl-w1");

  /** tcpnethaspsrv: 475 */
  public static final TcpPort TCPNETHASPSRV = new TcpPort((short) 475, "tcpnethaspsrv");

  /** tn-tl-fd1: 476 */
  public static final TcpPort TN_TL_FD1 = new TcpPort((short) 476, "tn-tl-fd1");

  /** ss7ns: 477 */
  public static final TcpPort SS7NS = new TcpPort((short) 477, "ss7ns");

  /** spsc: 478 */
  public static final TcpPort SPSC = new TcpPort((short) 478, "spsc");

  /** iafserver: 479 */
  public static final TcpPort IAFSERVER = new TcpPort((short) 479, "iafserver");

  /** iafdbase: 480 */
  public static final TcpPort IAFDBASE = new TcpPort((short) 480, "iafdbase");

  /** Ph service: 481 */
  public static final TcpPort PH = new TcpPort((short) 481, "Ph service");

  /** bgs-nsi: 482 */
  public static final TcpPort BGS_NSI = new TcpPort((short) 482, "bgs-nsi");

  /** ulpnet: 483 */
  public static final TcpPort ULPNET = new TcpPort((short) 483, "ulpnet");

  /** Integra Software Management Environment: 484 */
  public static final TcpPort INTEGRA_SME =
      new TcpPort((short) 484, "Integra Software Management Environment");

  /** Air Soft Power Burst: 485 */
  public static final TcpPort POWERBURST = new TcpPort((short) 485, "Air Soft Power Burst");

  /** avian: 486 */
  public static final TcpPort AVIAN = new TcpPort((short) 486, "avian");

  /** Simple Asynchronous File Transfer: 487 */
  public static final TcpPort SAFT = new TcpPort((short) 487, "Simple Asynchronous File Transfer");

  /** GSS-HTTP: 488 */
  public static final TcpPort GSS_HTTP = new TcpPort((short) 488, "GSS-HTTP");

  /** nest-protocol: 489 */
  public static final TcpPort NEST_PROTOCOL = new TcpPort((short) 489, "nest-protocol");

  /** micom-pfs: 490 */
  public static final TcpPort MICOM_PFS = new TcpPort((short) 490, "micom-pfs");

  /** go-login: 491 */
  public static final TcpPort GO_LOGIN = new TcpPort((short) 491, "go-login");

  /** Transport Independent Convergence for FNA: 492 */
  public static final TcpPort TICF_1 =
      new TcpPort((short) 492, "Transport Independent Convergence for FNA");

  /** Transport Independent Convergence for FNA: 493 */
  public static final TcpPort TICF_2 =
      new TcpPort((short) 493, "Transport Independent Convergence for FNA");

  /** POV-Ray: 494 */
  public static final TcpPort POV_RAY = new TcpPort((short) 494, "POV-Ray");

  /** intecourier: 495 */
  public static final TcpPort INTECOURIER = new TcpPort((short) 495, "intecourier");

  /** PIM-RP-DISC: 496 */
  public static final TcpPort PIM_RP_DISC = new TcpPort((short) 496, "PIM-RP-DISC");

  /** Retrospect backup and restore service: 497 */
  public static final TcpPort RETROSPECT =
      new TcpPort((short) 497, "Retrospect backup and restore service");

  /** siam: 498 */
  public static final TcpPort SIAM = new TcpPort((short) 498, "siam");

  /** ISO ILL Protocol: 499 */
  public static final TcpPort ISO_ILL = new TcpPort((short) 499, "ISO ILL Protocol");

  /** isakmp: 500 */
  public static final TcpPort ISAKMP = new TcpPort((short) 500, "isakmp");

  /** STMF: 501 */
  public static final TcpPort STMF = new TcpPort((short) 501, "STMF");

  /** Modbus Application Protocol: 502 */
  public static final TcpPort MBAP = new TcpPort((short) 502, "Modbus Application Protocol");

  /** Intrinsa: 503 */
  public static final TcpPort INTRINSA = new TcpPort((short) 503, "Intrinsa");

  /** citadel: 504 */
  public static final TcpPort CITADEL = new TcpPort((short) 504, "citadel");

  /** mailbox-lm: 505 */
  public static final TcpPort MAILBOX_LM = new TcpPort((short) 505, "mailbox-lm");

  /** ohimsrv: 506 */
  public static final TcpPort OHIMSRV = new TcpPort((short) 506, "ohimsrv");

  /** crs: 507 */
  public static final TcpPort CRS = new TcpPort((short) 507, "crs");

  /** xvttp: 508 */
  public static final TcpPort XVTTP = new TcpPort((short) 508, "xvttp");

  /** snare: 509 */
  public static final TcpPort SNARE = new TcpPort((short) 509, "snare");

  /** FirstClass Protocol: 510 */
  public static final TcpPort FCP = new TcpPort((short) 510, "FirstClass Protocol");

  /** PassGo: 511 */
  public static final TcpPort PASSGO = new TcpPort((short) 511, "PassGo");

  /** exec: 512 */
  public static final TcpPort EXEC = new TcpPort((short) 512, "exec");

  /** login: 513 */
  public static final TcpPort LOGIN = new TcpPort((short) 513, "login");

  /** shell: 514 */
  public static final TcpPort SHELL = new TcpPort((short) 514, "shell");

  /** spooler: 515 */
  public static final TcpPort PRINTER = new TcpPort((short) 515, "spooler");

  /** videotex: 516 */
  public static final TcpPort VIDEOTEX = new TcpPort((short) 516, "videotex");

  /** TALK: 517 */
  public static final TcpPort TALK = new TcpPort((short) 517, "TALK");

  /** ntalk: 518 */
  public static final TcpPort NTALK = new TcpPort((short) 518, "ntalk");

  /** unixtime: 519 */
  public static final TcpPort UTIME = new TcpPort((short) 519, "unixtime");

  /** extended file name server: 520 */
  public static final TcpPort EFS = new TcpPort((short) 520, "extended file name server");

  /** ripng: 521 */
  public static final TcpPort RIPNG = new TcpPort((short) 521, "ripng");

  /** ULP: 522 */
  public static final TcpPort ULP = new TcpPort((short) 522, "ULP");

  /** IBM-DB2: 523 */
  public static final TcpPort IBM_DB2 = new TcpPort((short) 523, "IBM-DB2");

  /** NCP: 524 */
  public static final TcpPort NCP = new TcpPort((short) 524, "NCP");

  /** timeserver: 525 */
  public static final TcpPort TIMED = new TcpPort((short) 525, "timeserver");

  /** newdate: 526 */
  public static final TcpPort TEMPO = new TcpPort((short) 526, "newdate");

  /** Stock IXChange: 527 */
  public static final TcpPort STX = new TcpPort((short) 527, "Stock IXChange");

  /** Customer IXChange: 528 */
  public static final TcpPort CUSTIX = new TcpPort((short) 528, "Customer IXChange");

  /** IRC-SERV: 529 */
  public static final TcpPort IRC_SERV = new TcpPort((short) 529, "IRC-SERV");

  /** courier: 530 */
  public static final TcpPort COURIER = new TcpPort((short) 530, "courier");

  /** conference: 531 */
  public static final TcpPort CONFERENCE = new TcpPort((short) 531, "conference");

  /** readnews: 532 */
  public static final TcpPort NETNEWS = new TcpPort((short) 532, "readnews");

  /** netwall: 533 */
  public static final TcpPort NETWALL = new TcpPort((short) 533, "netwall");

  /** windream Admin: 534 */
  public static final TcpPort WINDREAM = new TcpPort((short) 534, "windream Admin");

  /** iiop: 535 */
  public static final TcpPort IIOP = new TcpPort((short) 535, "iiop");

  /** opalis-rdv: 536 */
  public static final TcpPort OPALIS_RDV = new TcpPort((short) 536, "opalis-rdv");

  /** Networked Media Streaming Protocol: 537 */
  public static final TcpPort NMSP = new TcpPort((short) 537, "Networked Media Streaming Protocol");

  /** gdomap: 538 */
  public static final TcpPort GDOMAP = new TcpPort((short) 538, "gdomap");

  /** Apertus Technologies Load Determination: 539 */
  public static final TcpPort APERTUS_LDP =
      new TcpPort((short) 539, "Apertus Technologies Load Determination");

  /** uucpd: 540 */
  public static final TcpPort UUCP = new TcpPort((short) 540, "uucpd");

  /** uucp-rlogin: 541 */
  public static final TcpPort UUCP_RLOGIN = new TcpPort((short) 541, "uucp-rlogin");

  /** commerce: 542 */
  public static final TcpPort COMMERCE = new TcpPort((short) 542, "commerce");

  /** klogin: 543 */
  public static final TcpPort KLOGIN = new TcpPort((short) 543, "klogin");

  /** krcmd: 544 */
  public static final TcpPort KSHELL = new TcpPort((short) 544, "krcmd");

  /** appleqtcsrvr: 545 */
  public static final TcpPort APPLEQTCSRVR = new TcpPort((short) 545, "appleqtcsrvr");

  /** DHCPv6 Client: 546 */
  public static final TcpPort DHCPV6_CLIENT = new TcpPort((short) 546, "DHCPv6 Client");

  /** DHCPv6 Server: 547 */
  public static final TcpPort DHCPV6_SERVER = new TcpPort((short) 547, "DHCPv6 Server");

  /** AFP over TCP: 548 */
  public static final TcpPort AFPOVERTCP = new TcpPort((short) 548, "AFP over TCP");

  /** IDFP: 549 */
  public static final TcpPort IDFP = new TcpPort((short) 549, "IDFP");

  /** new-who: 550 */
  public static final TcpPort NEW_RWHO = new TcpPort((short) 550, "new-who");

  /** cybercash: 551 */
  public static final TcpPort CYBERCASH = new TcpPort((short) 551, "cybercash");

  /** DeviceShare: 552 */
  public static final TcpPort DEVSHR_NTS = new TcpPort((short) 552, "DeviceShare");

  /** pirp: 553 */
  public static final TcpPort PIRP = new TcpPort((short) 553, "pirp");

  /** Real Time Streaming Protocol (RTSP): 554 */
  public static final TcpPort RTSP =
      new TcpPort((short) 554, "Real Time Streaming Protocol (RTSP)");

  /** dsf: 555 */
  public static final TcpPort DSF = new TcpPort((short) 555, "dsf");

  /** rfs server: 556 */
  public static final TcpPort REMOTEFS = new TcpPort((short) 556, "rfs server");

  /** openvms-sysipc: 557 */
  public static final TcpPort OPENVMS_SYSIPC = new TcpPort((short) 557, "openvms-sysipc");

  /** SDNSKMP: 558 */
  public static final TcpPort SDNSKMP = new TcpPort((short) 558, "SDNSKMP");

  /** TEEDTAP: 559 */
  public static final TcpPort TEEDTAP = new TcpPort((short) 559, "TEEDTAP");

  /** rmonitord: 560 */
  public static final TcpPort RMONITOR = new TcpPort((short) 560, "rmonitord");

  /** monitor: 561 */
  public static final TcpPort MONITOR = new TcpPort((short) 561, "monitor");

  /** chcmd: 562 */
  public static final TcpPort CHSHELL = new TcpPort((short) 562, "chcmd");

  /** nntp protocol over TLS/SSL (was snntp): 563 */
  public static final TcpPort NNTPS = new TcpPort((short) 563, "nntp protocol over TLS/SSL");

  /** plan 9 file service: 564 */
  public static final TcpPort TCP_9PFS = new TcpPort((short) 564, "plan 9 file service");

  /** whoami: 565 */
  public static final TcpPort WHOAMI = new TcpPort((short) 565, "whoami");

  /** streettalk: 566 */
  public static final TcpPort STREETTALK = new TcpPort((short) 566, "streettalk");

  /** banyan-rpc: 567 */
  public static final TcpPort BANYAN_RPC = new TcpPort((short) 567, "banyan-rpc");

  /** microsoft shuttle: 568 */
  public static final TcpPort MS_SHUTTLE = new TcpPort((short) 568, "microsoft shuttle");

  /** microsoft rome: 569 */
  public static final TcpPort MS_ROME = new TcpPort((short) 569, "microsoft rome");

  /** meter demon: 570 */
  public static final TcpPort METER_DEMON = new TcpPort((short) 570, "meter demon");

  /** meter udemon: 571 */
  public static final TcpPort METER_UDEMON = new TcpPort((short) 571, "meter udemon");

  /** sonar: 572 */
  public static final TcpPort SONAR = new TcpPort((short) 572, "sonar");

  /** banyan-vip: 573 */
  public static final TcpPort BANYAN_VIP = new TcpPort((short) 573, "banyan-vip");

  /** FTP Software Agent System: 574 */
  public static final TcpPort FTP_AGENT = new TcpPort((short) 574, "FTP Software Agent System");

  /** VEMMI: 575 */
  public static final TcpPort VEMMI = new TcpPort((short) 575, "VEMMI");

  /** ipcd: 576 */
  public static final TcpPort IPCD = new TcpPort((short) 576, "ipcd");

  /** vnas: 577 */
  public static final TcpPort VNAS = new TcpPort((short) 577, "vnas");

  /** ipdd: 578 */
  public static final TcpPort IPDD = new TcpPort((short) 578, "ipdd");

  /** decbsrv: 579 */
  public static final TcpPort DECBSRV = new TcpPort((short) 579, "decbsrv");

  /** SNTP HEARTBEAT: 580 */
  public static final TcpPort SNTP_HEARTBEAT = new TcpPort((short) 580, "SNTP HEARTBEAT");

  /** Bundle Discovery Protocol: 581 */
  public static final TcpPort BDP = new TcpPort((short) 581, "Bundle Discovery Protocol");

  /** SCC Security: 582 */
  public static final TcpPort SCC_SECURITY = new TcpPort((short) 582, "SCC Security");

  /** Philips Video-Conferencing: 583 */
  public static final TcpPort PHILIPS_VC = new TcpPort((short) 583, "Philips Video-Conferencing");

  /** Key Server: 584 */
  public static final TcpPort KEYSERVER = new TcpPort((short) 584, "Key Server");

  /** Password Change: 586 */
  public static final TcpPort PASSWORD_CHG = new TcpPort((short) 586, "Password Change");

  /** Message Submission: 587 */
  public static final TcpPort SUBMISSION = new TcpPort((short) 587, "Message Submission");

  /** CAL: 588 */
  public static final TcpPort CAL = new TcpPort((short) 588, "CAL");

  /** EyeLink: 589 */
  public static final TcpPort EYELINK = new TcpPort((short) 589, "EyeLink");

  /** TNS CML: 590 */
  public static final TcpPort TNS_CML = new TcpPort((short) 590, "TNS CML");

  /** FileMaker HTTP Alternate : 591 */
  public static final TcpPort HTTP_ALT = new TcpPort((short) 591, "FileMaker HTTP Alternate");

  /** Eudora Set: 592 */
  public static final TcpPort EUDORA_SET = new TcpPort((short) 592, "Eudora Set");

  /** HTTP RPC Ep Map: 593 */
  public static final TcpPort HTTP_RPC_EPMAP = new TcpPort((short) 593, "HTTP RPC Ep Map");

  /** TPIP: 594 */
  public static final TcpPort TPIP = new TcpPort((short) 594, "TPIP");

  /** CAB Protocol: 595 */
  public static final TcpPort CAB_PROTOCOL = new TcpPort((short) 595, "CAB Protocol");

  /** SMSD: 596 */
  public static final TcpPort SMSD = new TcpPort((short) 596, "SMSD");

  /** PTC Name Service: 597 */
  public static final TcpPort PTCNAMESERVICE = new TcpPort((short) 597, "PTC Name Service");

  /** SCO Web Server Manager 3: 598 */
  public static final TcpPort SCO_WEBSRVRMG3 = new TcpPort((short) 598, "SCO Web Server Manager 3");

  /** Aeolon Core Protocol: 599 */
  public static final TcpPort ACP = new TcpPort((short) 599, "Aeolon Core Protocol");

  /** Sun IPC server: 600 */
  public static final TcpPort IPCSERVER = new TcpPort((short) 600, "Sun IPC server");

  /** Reliable Syslog Service: 601 */
  public static final TcpPort SYSLOG_CONN = new TcpPort((short) 601, "Reliable Syslog Service");

  /** XML-RPC over BEEP: 602 */
  public static final TcpPort XMLRPC_BEEP = new TcpPort((short) 602, "XML-RPC over BEEP");

  /** IDXP: 603 */
  public static final TcpPort IDXP = new TcpPort((short) 603, "IDXP");

  /** TUNNEL: 604 */
  public static final TcpPort TUNNEL = new TcpPort((short) 604, "TUNNEL");

  /** SOAP over BEEP: 605 */
  public static final TcpPort SOAP_BEEP = new TcpPort((short) 605, "SOAP over BEEP");

  /** Cray Unified Resource Manager: 606 */
  public static final TcpPort URM = new TcpPort((short) 606, "Cray Unified Resource Manager");

  /** nqs: 607 */
  public static final TcpPort NQS = new TcpPort((short) 607, "nqs");

  /** Sender-Initiated/Unsolicited File Transfer: 608 */
  public static final TcpPort SIFT_UFT =
      new TcpPort((short) 608, "Sender-Initiated/Unsolicited File Transfer");

  /** npmp-trap: 609 */
  public static final TcpPort NPMP_TRAP = new TcpPort((short) 609, "npmp-trap");

  /** npmp-local: 610 */
  public static final TcpPort NPMP_LOCAL = new TcpPort((short) 610, "npmp-local");

  /** npmp-gui: 611 */
  public static final TcpPort NPMP_GUI = new TcpPort((short) 611, "npmp-gui");

  /** HMMP Indication: 612 */
  public static final TcpPort HMMP_IND = new TcpPort((short) 612, "HMMP Indication");

  /** HMMP Operation: 613 */
  public static final TcpPort HMMP_OP = new TcpPort((short) 613, "HMMP Operation");

  /** SSLshell: 614 */
  public static final TcpPort SSHELL = new TcpPort((short) 614, "SSLshell");

  /** SCO Internet Configuration Manager: 615 */
  public static final TcpPort SCO_INETMGR =
      new TcpPort((short) 615, "SCO Internet Configuration Manager");

  /** SCO System Administration Server: 616 */
  public static final TcpPort SCO_SYSMGR =
      new TcpPort((short) 616, "SCO System Administration Server");

  /** SCO Desktop Administration Server: 617 */
  public static final TcpPort SCO_DTMGR =
      new TcpPort((short) 617, "SCO Desktop Administration Server");

  /** DEI-ICDA: 618 */
  public static final TcpPort DEI_ICDA = new TcpPort((short) 618, "DEI-ICDA");

  /** Compaq EVM: 619 */
  public static final TcpPort COMPAQ_EVM = new TcpPort((short) 619, "Compaq EVM");

  /** SCO WebServer Manager: 620 */
  public static final TcpPort SCO_WEBSRVRMGR = new TcpPort((short) 620, "SCO WebServer Manager");

  /** ESCP: 621 */
  public static final TcpPort ESCP_IP = new TcpPort((short) 621, "ESCP");

  /** Collaborator: 622 */
  public static final TcpPort COLLABORATOR = new TcpPort((short) 622, "Collaborator");

  /** DMTF out-of-band web services management protocol: 623 */
  public static final TcpPort OOB_WS_HTTP =
      new TcpPort((short) 623, "DMTF out-of-band web services management protocol");

  /** Crypto Admin: 624 */
  public static final TcpPort CRYPTOADMIN = new TcpPort((short) 624, "Crypto Admin");

  /** DEC DLM: 625 */
  public static final TcpPort DEC_DLM = new TcpPort((short) 625, "DEC DLM");

  /** ASIA: 626 */
  public static final TcpPort ASIA = new TcpPort((short) 626, "ASIA");

  /** PassGo Tivoli: 627 */
  public static final TcpPort PASSGO_TIVOLI = new TcpPort((short) 627, "PassGo Tivoli");

  /** QMQP: 628 */
  public static final TcpPort QMQP = new TcpPort((short) 628, "QMQP");

  /** 3Com AMP3: 629 */
  public static final TcpPort TCP_3COM_AMP3 = new TcpPort((short) 629, "3Com AMP3");

  /** RDA: 630 */
  public static final TcpPort RDA = new TcpPort((short) 630, "RDA");

  /** IPP (Internet Printing Protocol): 631 */
  public static final TcpPort IPP = new TcpPort((short) 631, "Internet Printing Protocol");

  /** bmpp: 632 */
  public static final TcpPort BMPP = new TcpPort((short) 632, "bmpp");

  /** Service Status update (Sterling Software): 633 */
  public static final TcpPort SERVSTAT =
      new TcpPort((short) 633, "Service Status update (Sterling Software)");

  /** ginad: 634 */
  public static final TcpPort GINAD = new TcpPort((short) 634, "ginad");

  /** RLZ DBase: 635 */
  public static final TcpPort RLZDBASE = new TcpPort((short) 635, "RLZ DBase");

  /** ldap protocol over TLS/SSL (was sldap): 636 */
  public static final TcpPort LDAPS = new TcpPort((short) 636, "ldap protocol over TLS/SSL");

  /** lanserver: 637 */
  public static final TcpPort LANSERVER = new TcpPort((short) 637, "lanserver");

  /** mcns-sec: 638 */
  public static final TcpPort MCNS_SEC = new TcpPort((short) 638, "mcns-sec");

  /** MSDP: 639 */
  public static final TcpPort MSDP = new TcpPort((short) 639, "MSDP");

  /** entrust-sps: 640 */
  public static final TcpPort ENTRUST_SPS = new TcpPort((short) 640, "entrust-sps");

  /** repcmd: 641 */
  public static final TcpPort REPCMD = new TcpPort((short) 641, "repcmd");

  /** ESRO-EMSDP V1.3: 642 */
  public static final TcpPort ESRO_EMSDP = new TcpPort((short) 642, "ESRO-EMSDP V1.3");

  /** SANity: 643 */
  public static final TcpPort SANITY = new TcpPort((short) 643, "SANity");

  /** dwr: 644 */
  public static final TcpPort DWR = new TcpPort((short) 644, "dwr");

  /** PSSC: 645 */
  public static final TcpPort PSSC = new TcpPort((short) 645, "PSSC");

  /** LDP: 646 */
  public static final TcpPort LDP = new TcpPort((short) 646, "LDP");

  /** DHCP Failover: 647 */
  public static final TcpPort DHCP_FAILOVER = new TcpPort((short) 647, "DHCP Failover");

  /** Registry Registrar Protocol (RRP): 648 */
  public static final TcpPort RRP = new TcpPort((short) 648, "Registry Registrar Protocol");

  /** Cadview-3d: 649 */
  public static final TcpPort CADVIEW_3D = new TcpPort((short) 649, "Cadview-3d");

  /** OBEX: 650 */
  public static final TcpPort OBEX = new TcpPort((short) 650, "OBEX");

  /** IEEE MMS: 651 */
  public static final TcpPort IEEE_MMS = new TcpPort((short) 651, "IEEE MMS");

  /** HELLO_PORT: 652 */
  public static final TcpPort HELLO_PORT = new TcpPort((short) 652, "HELLO_PORT");

  /** RepCmd: 653 */
  public static final TcpPort REPSCMD = new TcpPort((short) 653, "RepCmd");

  /** AODV: 654 */
  public static final TcpPort AODV = new TcpPort((short) 654, "AODV");

  /** TINC: 655 */
  public static final TcpPort TINC = new TcpPort((short) 655, "TINC");

  /** SPMP: 656 */
  public static final TcpPort SPMP = new TcpPort((short) 656, "SPMP");

  /** RMC: 657 */
  public static final TcpPort RMC = new TcpPort((short) 657, "RMC");

  /** TenFold: 658 */
  public static final TcpPort TENFOLD = new TcpPort((short) 658, "TenFold");

  /** MacOS Server Admin: 660 */
  public static final TcpPort MAC_SRVR_ADMIN = new TcpPort((short) 660, "MacOS Server Admin");

  /** HAP: 661 */
  public static final TcpPort HAP = new TcpPort((short) 661, "HAP");

  /** PFTP: 662 */
  public static final TcpPort PFTP = new TcpPort((short) 662, "PFTP");

  /** PureNoise: 663 */
  public static final TcpPort PURENOISE = new TcpPort((short) 663, "PureNoise");

  /** DMTF out-of-band secure web services management protocol: 664 */
  public static final TcpPort OOB_WS_HTTPS =
      new TcpPort((short) 664, "DMTF out-of-band secure web services management protocol");

  /** Sun DR: 665 */
  public static final TcpPort SUN_DR = new TcpPort((short) 665, "Sun DR");

  /** doom Id Software: 666 */
  public static final TcpPort DOOM = new TcpPort((short) 666, "doom Id Software");

  /** campaign contribution disclosures: 667 */
  public static final TcpPort DISCLOSE =
      new TcpPort((short) 667, "campaign contribution disclosures");

  /** MeComm: 668 */
  public static final TcpPort MECOMM = new TcpPort((short) 668, "MeComm");

  /** MeRegister: 669 */
  public static final TcpPort MEREGISTER = new TcpPort((short) 669, "MeRegister");

  /** VACDSM-SWS: 670 */
  public static final TcpPort VACDSM_SWS = new TcpPort((short) 670, "VACDSM-SWS");

  /** VACDSM-APP: 671 */
  public static final TcpPort VACDSM_APP = new TcpPort((short) 671, "VACDSM-APP");

  /** VPPS-QUA: 672 */
  public static final TcpPort VPPS_QUA = new TcpPort((short) 672, "VPPS-QUA");

  /** CIMPLEX: 673 */
  public static final TcpPort CIMPLEX = new TcpPort((short) 673, "CIMPLEX");

  /** ACAP: 674 */
  public static final TcpPort ACAP = new TcpPort((short) 674, "ACAP");

  /** DCTP: 675 */
  public static final TcpPort DCTP = new TcpPort((short) 675, "DCTP");

  /** VPPS Via: 676 */
  public static final TcpPort VPPS_VIA = new TcpPort((short) 676, "VPPS Via");

  /** Virtual Presence Protocol: 677 */
  public static final TcpPort VPP = new TcpPort((short) 677, "Virtual Presence Protocol");

  /** GNU Generation Foundation NCP: 678 */
  public static final TcpPort GGF_NCP = new TcpPort((short) 678, "GNU Generation Foundation NCP");

  /** MRM: 679 */
  public static final TcpPort MRM = new TcpPort((short) 679, "MRM");

  /** entrust-aaas: 680 */
  public static final TcpPort ENTRUST_AAAS = new TcpPort((short) 680, "entrust-aaas");

  /** entrust-aams: 681 */
  public static final TcpPort ENTRUST_AAMS = new TcpPort((short) 681, "entrust-aams");

  /** XFR: 682 */
  public static final TcpPort XFR = new TcpPort((short) 682, "XFR");

  /** CORBA IIOP: 683 */
  public static final TcpPort CORBA_IIOP = new TcpPort((short) 683, "CORBA IIOP");

  /** CORBA IIOP SSL: 684 */
  public static final TcpPort CORBA_IIOP_SSL = new TcpPort((short) 684, "CORBA IIOP SSL");

  /** MDC Port Mapper: 685 */
  public static final TcpPort MDC_PORTMAPPER = new TcpPort((short) 685, "MDC Port Mapper");

  /** Hardware Control Protocol Wismar: 686 */
  public static final TcpPort HCP_WISMAR =
      new TcpPort((short) 686, "Hardware Control Protocol Wismar");

  /** asipregistry: 687 */
  public static final TcpPort ASIPREGISTRY = new TcpPort((short) 687, "asipregistry");

  /** ApplianceWare managment protocol: 688 */
  public static final TcpPort REALM_RUSD =
      new TcpPort((short) 688, "ApplianceWare managment protocol");

  /** NMAP: 689 */
  public static final TcpPort NMAP = new TcpPort((short) 689, "NMAP");

  /** Velneo Application Transfer Protocol: 690 */
  public static final TcpPort VATP =
      new TcpPort((short) 690, "Velneo Application Transfer Protocol");

  /** MS Exchange Routing: 691 */
  public static final TcpPort MSEXCH_ROUTING = new TcpPort((short) 691, "MS Exchange Routing");

  /** Hyperwave-ISP: 692 */
  public static final TcpPort HYPERWAVE_ISP = new TcpPort((short) 692, "Hyperwave-ISP");

  /** almanid Connection Endpoint: 693 */
  public static final TcpPort CONNENDP = new TcpPort((short) 693, "almanid Connection Endpoint");

  /** ha-cluster: 694 */
  public static final TcpPort HA_CLUSTER = new TcpPort((short) 694, "ha-cluster");

  /** IEEE-MMS-SSL: 695 */
  public static final TcpPort IEEE_MMS_SSL = new TcpPort((short) 695, "IEEE-MMS-SSL");

  /** RUSHD: 696 */
  public static final TcpPort RUSHD = new TcpPort((short) 696, "RUSHD");

  /** UUIDGEN: 697 */
  public static final TcpPort UUIDGEN = new TcpPort((short) 697, "UUIDGEN");

  /** OLSR: 698 */
  public static final TcpPort OLSR = new TcpPort((short) 698, "OLSR");

  /** Access Network: 699 */
  public static final TcpPort ACCESSNETWORK = new TcpPort((short) 699, "Access Network");

  /** Extensible Provisioning Protocol: 700 */
  public static final TcpPort EPP = new TcpPort((short) 700, "Extensible Provisioning Protocol");

  /** Link Management Protocol (LMP): 701 */
  public static final TcpPort LMP = new TcpPort((short) 701, "Link Management Protocol (LMP)");

  /** IRIS over BEEP: 702 */
  public static final TcpPort IRIS_BEEP = new TcpPort((short) 702, "IRIS over BEEP");

  /** errlog copy/server daemon: 704 */
  public static final TcpPort ELCSD = new TcpPort((short) 704, "errlog copy/server daemon");

  /** AgentX: 705 */
  public static final TcpPort AGENTX = new TcpPort((short) 705, "AgentX");

  /** SILC: 706 */
  public static final TcpPort SILC = new TcpPort((short) 706, "SILC");

  /** Borland DSJ: 707 */
  public static final TcpPort BORLAND_DSJ = new TcpPort((short) 707, "Borland DSJ");

  /** Entrust Key Management Service Handler: 709 */
  public static final TcpPort ENTRUST_KMSH =
      new TcpPort((short) 709, "Entrust Key Management Service Handler");

  /** Entrust Administration Service Handler: 710 */
  public static final TcpPort ENTRUST_ASH =
      new TcpPort((short) 710, "Entrust Administration Service Handler");

  /** Cisco TDP: 711 */
  public static final TcpPort CISCO_TDP = new TcpPort((short) 711, "Cisco TDP");

  /** TBRPF: 712 */
  public static final TcpPort TBRPF = new TcpPort((short) 712, "TBRPF");

  /** IRIS over XPC: 713 */
  public static final TcpPort IRIS_XPC = new TcpPort((short) 713, "IRIS over XPC");

  /** IRIS over XPCS: 714 */
  public static final TcpPort IRIS_XPCS = new TcpPort((short) 714, "IRIS over XPCS");

  /** IRIS-LWZ: 715 */
  public static final TcpPort IRIS_LWZ = new TcpPort((short) 715, "IRIS-LWZ");

  /** IBM NetView DM/6000 Server/Client: 729 */
  public static final TcpPort NETVIEWDM1 =
      new TcpPort((short) 729, "IBM NetView DM/6000 Server/Client");

  /** IBM NetView DM/6000 send/tcp: 730 */
  public static final TcpPort NETVIEWDM2 = new TcpPort((short) 730, "IBM NetView DM/6000 send/tcp");

  /** IBM NetView DM/6000 receive/tcp: 731 */
  public static final TcpPort NETVIEWDM3 =
      new TcpPort((short) 731, "IBM NetView DM/6000 receive/tcp");

  /** netGW: 741 */
  public static final TcpPort NETGW = new TcpPort((short) 741, "netGW");

  /** Network based Rev. Cont. Sys.: 742 */
  public static final TcpPort NETRCS = new TcpPort((short) 742, "Network based Rev. Cont. Sys.");

  /** Flexible License Manager: 744 */
  public static final TcpPort FLEXLM = new TcpPort((short) 744, "Flexible License Manager");

  /** Fujitsu Device Control: 747 */
  public static final TcpPort FUJITSU_DEV = new TcpPort((short) 747, "Fujitsu Device Control");

  /** Russell Info Sci Calendar Manager: 748 */
  public static final TcpPort RIS_CM =
      new TcpPort((short) 748, "Russell Info Sci Calendar Manager");

  /** kerberos administration: 749 */
  public static final TcpPort KERBEROS_ADM = new TcpPort((short) 749, "kerberos administration");

  /** rfile: 750 */
  public static final TcpPort RFILE = new TcpPort((short) 750, "rfile");

  /** pump: 751 */
  public static final TcpPort PUMP = new TcpPort((short) 751, "pump");

  /** qrh: 752 */
  public static final TcpPort QRH = new TcpPort((short) 752, "qrh");

  /** rrh: 753 */
  public static final TcpPort RRH = new TcpPort((short) 753, "rrh");

  /** send: 754 */
  public static final TcpPort TELL = new TcpPort((short) 754, "send");

  /** nlogin: 758 */
  public static final TcpPort NLOGIN = new TcpPort((short) 758, "nlogin");

  /** con: 759 */
  public static final TcpPort CON = new TcpPort((short) 759, "con");

  /** ns: 760 */
  public static final TcpPort NS = new TcpPort((short) 760, "ns");

  /** rxe: 761 */
  public static final TcpPort RXE = new TcpPort((short) 761, "rxe");

  /** quotad: 762 */
  public static final TcpPort QUOTAD = new TcpPort((short) 762, "quotad");

  /** cycleserv: 763 */
  public static final TcpPort CYCLESERV = new TcpPort((short) 763, "cycleserv");

  /** omserv: 764 */
  public static final TcpPort OMSERV = new TcpPort((short) 764, "omserv");

  /** webster: 765 */
  public static final TcpPort WEBSTER = new TcpPort((short) 765, "webster");

  /** phone: 767 */
  public static final TcpPort PHONEBOOK = new TcpPort((short) 767, "phone");

  /** vid: 769 */
  public static final TcpPort VID = new TcpPort((short) 769, "vid");

  /** cadlock: 770 */
  public static final TcpPort CADLOCK = new TcpPort((short) 770, "cadlock");

  /** rtip: 771 */
  public static final TcpPort RTIP = new TcpPort((short) 771, "rtip");

  /** cycleserv2: 772 */
  public static final TcpPort CYCLESERV2 = new TcpPort((short) 772, "cycleserv2");

  /** submit: 773 */
  public static final TcpPort SUBMIT = new TcpPort((short) 773, "submit");

  /** rpasswd: 774 */
  public static final TcpPort RPASSWD = new TcpPort((short) 774, "rpasswd");

  /** entomb: 775 */
  public static final TcpPort ENTOMB = new TcpPort((short) 775, "entomb");

  /** wpages: 776 */
  public static final TcpPort WPAGES = new TcpPort((short) 776, "wpages");

  /** Multiling HTTP: 777 */
  public static final TcpPort MULTILING_HTTP = new TcpPort((short) 777, "Multiling HTTP");

  /** wpgs: 780 */
  public static final TcpPort WPGS = new TcpPort((short) 780, "wpgs");

  /** mdbs-daemon: 800 */
  public static final TcpPort MDBS_DAEMON = new TcpPort((short) 800, "mdbs-daemon");

  /** device: 801 */
  public static final TcpPort DEVICE = new TcpPort((short) 801, "device");

  /** Modbus Application Protocol Secure: 802 */
  public static final TcpPort MBAP_S =
      new TcpPort((short) 802, "Modbus Application Protocol Secure");

  /** FCP: 810 */
  public static final TcpPort FCP_UDP = new TcpPort((short) 810, "FCP");

  /** itm-mcell-s: 828 */
  public static final TcpPort ITM_MCELL_S = new TcpPort((short) 828, "itm-mcell-s");

  /** PKIX-3 CA/RA: 829 */
  public static final TcpPort PKIX_3_CA_RA = new TcpPort((short) 829, "PKIX-3 CA/RA");

  /** NETCONF over SSH: 830 */
  public static final TcpPort NETCONF_SSH = new TcpPort((short) 830, "NETCONF over SSH");

  /** NETCONF over BEEP: 831 */
  public static final TcpPort NETCONF_BEEP = new TcpPort((short) 831, "NETCONF over BEEP");

  /** NETCONF for SOAP over HTTPS: 832 */
  public static final TcpPort NETCONFSOAPHTTP =
      new TcpPort((short) 832, "NETCONF for SOAP over HTTPS");

  /** NETCONF for SOAP over BEEP: 833 */
  public static final TcpPort NETCONFSOAPBEEP =
      new TcpPort((short) 833, "NETCONF for SOAP over BEEP");

  /** dhcp-failover 2: 847 */
  public static final TcpPort DHCP_FAILOVER2 = new TcpPort((short) 847, "dhcp-failover 2");

  /** GDOI: 848 */
  public static final TcpPort GDOI = new TcpPort((short) 848, "GDOI");

  /** iSCSI: 860 */
  public static final TcpPort ISCSI = new TcpPort((short) 860, "iSCSI");

  /** OWAMP-Control: 861 */
  public static final TcpPort OWAMP_CONTROL = new TcpPort((short) 861, "OWAMP-Control");

  /** Two-way Active Measurement Protocol (TWAMP) Control: 862 */
  public static final TcpPort TWAMP_CONTROL =
      new TcpPort((short) 862, "Two-way Active Measurement Protocol (TWAMP) Control");

  /** rsync: 873 */
  public static final TcpPort RSYNC = new TcpPort((short) 873, "rsync");

  /** ICL coNETion locate server: 886 */
  public static final TcpPort ICLCNET_LOCATE =
      new TcpPort((short) 886, "ICL coNETion locate server");

  /** ICL coNETion server info: 887 */
  public static final TcpPort ICLCNET_SVINFO = new TcpPort((short) 887, "ICL coNETion server info");

  /** AccessBuilder: 888 */
  public static final TcpPort ACCESSBUILDER = new TcpPort((short) 888, "AccessBuilder");

  /** OMG Initial Refs: 900 */
  public static final TcpPort OMGINITIALREFS = new TcpPort((short) 900, "OMG Initial Refs");

  /** SMPNAMERES: 901 */
  public static final TcpPort SMPNAMERES = new TcpPort((short) 901, "SMPNAMERES");

  /** self documenting Telnet Door: 902 */
  public static final TcpPort IDEAFARM_DOOR =
      new TcpPort((short) 902, "self documenting Telnet Door");

  /** self documenting Telnet Panic Door: 903 */
  public static final TcpPort IDEAFARM_PANIC =
      new TcpPort((short) 903, "self documenting Telnet Panic Door");

  /** Kerberized Internet Negotiation of Keys (KINK): 910 */
  public static final TcpPort KINK =
      new TcpPort((short) 910, "Kerberized Internet Negotiation of Keys (KINK)");

  /** xact-backup: 911 */
  public static final TcpPort XACT_BACKUP = new TcpPort((short) 911, "xact-backup");

  /** APEX relay-relay service: 912 */
  public static final TcpPort APEX_MESH = new TcpPort((short) 912, "APEX relay-relay service");

  /** APEX endpoint-relay service: 913 */
  public static final TcpPort APEX_EDGE = new TcpPort((short) 913, "APEX endpoint-relay service");

  /** ftp protocol, data, over TLS/SSL: 989 */
  public static final TcpPort FTPS_DATA =
      new TcpPort((short) 989, "ftp protocol, data, over TLS/SSL");

  /** ftp protocol, control, over TLS/SSL: 990 */
  public static final TcpPort FTPS =
      new TcpPort((short) 990, "ftp protocol, control, over TLS/SSL");

  /** Netnews Administration System: 991 */
  public static final TcpPort NAS = new TcpPort((short) 991, "Netnews Administration System");

  /** telnet protocol over TLS/SSL: 992 */
  public static final TcpPort TELNETS = new TcpPort((short) 992, "telnet protocol over TLS/SSL");

  /** imap4 protocol over TLS/SSL: 993 */
  public static final TcpPort IMAPS = new TcpPort((short) 993, "imap4 protocol over TLS/SSL");

  /** pop3 protocol over TLS/SSL (was spop3): 995 */
  public static final TcpPort POP3S =
      new TcpPort((short) 995, "pop3 protocol over TLS/SSL (was spop3)");

  /** vsinet: 996 */
  public static final TcpPort VSINET = new TcpPort((short) 996, "vsinet");

  /** maitrd: 997 */
  public static final TcpPort MAITRD = new TcpPort((short) 997, "maitrd");

  /** busboy: 998 */
  public static final TcpPort BUSBOY = new TcpPort((short) 998, "busboy");

  /** puprouter: 999 */
  public static final TcpPort PUPROUTER = new TcpPort((short) 999, "puprouter");

  /** cadlock2: 1000 */
  public static final TcpPort CADLOCK2 = new TcpPort((short) 1000, "cadlock2");

  /** surf: 1010 */
  public static final TcpPort SURF = new TcpPort((short) 1010, "surf");

  private static final Map<Short, TcpPort> registry = new HashMap<Short, TcpPort>();

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
    registry.put(TCP_3COM_TSMUX.value(), TCP_3COM_TSMUX);
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
    registry.put(PT_TLS.value(), PT_TLS);
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
    registry.put(RPKI_RTR.value(), RPKI_RTR);
    registry.put(RPKI_RTR_TLS.value(), RPKI_RTR_TLS);
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
    registry.put(MACON_TCP.value(), MACON_TCP);
    registry.put(SCOHELP.value(), SCOHELP);
    registry.put(APPLEQTC.value(), APPLEQTC);
    registry.put(AMPR_RCMD.value(), AMPR_RCMD);
    registry.put(SKRONK.value(), SKRONK);
    registry.put(DATASURFSRV.value(), DATASURFSRV);
    registry.put(DATASURFSRVSEC.value(), DATASURFSRVSEC);
    registry.put(ALPES.value(), ALPES);
    registry.put(KPASSWD.value(), KPASSWD);
    registry.put(URD.value(), URD);
    registry.put(DIGITAL_VRC.value(), DIGITAL_VRC);
    registry.put(MYLEX_MAPD.value(), MYLEX_MAPD);
    registry.put(PHOTURIS.value(), PHOTURIS);
    registry.put(RCP.value(), RCP);
    registry.put(SCX_PROXY.value(), SCX_PROXY);
    registry.put(MONDEX.value(), MONDEX);
    registry.put(LJK_LOGIN.value(), LJK_LOGIN);
    registry.put(HYBRID_POP.value(), HYBRID_POP);
    registry.put(TN_TL_W1.value(), TN_TL_W1);
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
    registry.put(EXEC.value(), EXEC);
    registry.put(LOGIN.value(), LOGIN);
    registry.put(SHELL.value(), SHELL);
    registry.put(PRINTER.value(), PRINTER);
    registry.put(VIDEOTEX.value(), VIDEOTEX);
    registry.put(TALK.value(), TALK);
    registry.put(NTALK.value(), NTALK);
    registry.put(UTIME.value(), UTIME);
    registry.put(EFS.value(), EFS);
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
    registry.put(TCP_9PFS.value(), TCP_9PFS);
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
    registry.put(OOB_WS_HTTP.value(), OOB_WS_HTTP);
    registry.put(CRYPTOADMIN.value(), CRYPTOADMIN);
    registry.put(DEC_DLM.value(), DEC_DLM);
    registry.put(ASIA.value(), ASIA);
    registry.put(PASSGO_TIVOLI.value(), PASSGO_TIVOLI);
    registry.put(QMQP.value(), QMQP);
    registry.put(TCP_3COM_AMP3.value(), TCP_3COM_AMP3);
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
    registry.put(OOB_WS_HTTPS.value(), OOB_WS_HTTPS);
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
    registry.put(NETVIEWDM1.value(), NETVIEWDM1);
    registry.put(NETVIEWDM2.value(), NETVIEWDM2);
    registry.put(NETVIEWDM3.value(), NETVIEWDM3);
    registry.put(NETGW.value(), NETGW);
    registry.put(NETRCS.value(), NETRCS);
    registry.put(FLEXLM.value(), FLEXLM);
    registry.put(FUJITSU_DEV.value(), FUJITSU_DEV);
    registry.put(RIS_CM.value(), RIS_CM);
    registry.put(KERBEROS_ADM.value(), KERBEROS_ADM);
    registry.put(RFILE.value(), RFILE);
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
    registry.put(SUBMIT.value(), SUBMIT);
    registry.put(RPASSWD.value(), RPASSWD);
    registry.put(ENTOMB.value(), ENTOMB);
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
    registry.put(BUSBOY.value(), BUSBOY);
    registry.put(PUPROUTER.value(), PUPROUTER);
    registry.put(CADLOCK2.value(), CADLOCK2);
    registry.put(SURF.value(), SURF);
  }

  /**
   * @param value value
   * @param name name
   */
  public TcpPort(Short value, String name) {
    super(value, name);
  }

  /**
   * @param value value
   * @return a TcpPort object.
   */
  public static TcpPort getInstance(Short value) {
    if (registry.containsKey(value)) {
      return registry.get(value);
    } else {
      return new TcpPort(value, "unknown");
    }
  }

  /**
   * @param port port
   * @return a TcpPort object.
   */
  public static TcpPort register(TcpPort port) {
    return registry.put(port.value(), port);
  }
}
