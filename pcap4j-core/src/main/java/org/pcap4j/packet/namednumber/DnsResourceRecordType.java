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
 * DNS Resource Record (RR) TYPE
 *
 * @see <a
 *     href="http://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4">IANA
 *     Registry</a>
 * @author Kaito Yamada
 * @since pcap4j 1.7.1
 */
public final class DnsResourceRecordType extends NamedNumber<Short, DnsResourceRecordType> {

  /** */
  private static final long serialVersionUID = 513163065994381046L;

  /** Host address: 1 */
  public static final DnsResourceRecordType A =
      new DnsResourceRecordType((short) 1, "A (Host address)");

  /** Authoritative name server: 2 */
  public static final DnsResourceRecordType NS =
      new DnsResourceRecordType((short) 2, "NS (Authoritative name server)");

  /** Mail destination: 3 */
  public static final DnsResourceRecordType MD =
      new DnsResourceRecordType((short) 3, "MD (Mail destination)");

  /** Mail forwarder: 4 */
  public static final DnsResourceRecordType MF =
      new DnsResourceRecordType((short) 4, "MF (Mail forwarder)");

  /** Canonical name for an alias: 5 */
  public static final DnsResourceRecordType CNAME =
      new DnsResourceRecordType((short) 5, "CNAME (Canonical name for an alias)");

  /** Start of a zone of authority: 6 */
  public static final DnsResourceRecordType SOA =
      new DnsResourceRecordType((short) 6, "SOA (Start of a zone of authority)");

  /** Mailbox domain name: 7 */
  public static final DnsResourceRecordType MB =
      new DnsResourceRecordType((short) 7, "MB (Mailbox domain name)");

  /** Mail group member: 8 */
  public static final DnsResourceRecordType MG =
      new DnsResourceRecordType((short) 8, "MG (Mail group member)");

  /** Mail rename domain name: 9 */
  public static final DnsResourceRecordType MR =
      new DnsResourceRecordType((short) 9, "MR (Mail rename domain name)");

  /** Null RR: 10 */
  public static final DnsResourceRecordType NULL =
      new DnsResourceRecordType((short) 10, "NULL (Null RR)");

  /** Well known service description: 11 */
  public static final DnsResourceRecordType WKS =
      new DnsResourceRecordType((short) 11, "WKS (Well known service description)");

  /** Domain name pointer: 12 */
  public static final DnsResourceRecordType PTR =
      new DnsResourceRecordType((short) 12, "PTR (Domain name pointer)");

  /** Host information: 13 */
  public static final DnsResourceRecordType HINFO =
      new DnsResourceRecordType((short) 13, "HINFO (Host information)");

  /** Mailbox or mail list information: 14 */
  public static final DnsResourceRecordType MINFO =
      new DnsResourceRecordType((short) 14, "MINFO (Mailbox or mail list information)");

  /** Mail exchange: 15 */
  public static final DnsResourceRecordType MX =
      new DnsResourceRecordType((short) 15, "MX (Mail exchange)");

  /** Text strings: 16 */
  public static final DnsResourceRecordType TXT =
      new DnsResourceRecordType((short) 16, "TXT (Text strings)");

  /** Responsible Person: 17 */
  public static final DnsResourceRecordType RP =
      new DnsResourceRecordType((short) 17, "RP (Responsible Person)");

  /** AFS Data Base location: 18 */
  public static final DnsResourceRecordType AFSDB =
      new DnsResourceRecordType((short) 18, "AFSDB (AFS Data Base location)");

  /** X.25 PSDN address: 19 */
  public static final DnsResourceRecordType X25 =
      new DnsResourceRecordType((short) 19, "X25 (X.25 PSDN address)");

  /** ISDN address: 20 */
  public static final DnsResourceRecordType ISDN =
      new DnsResourceRecordType((short) 20, "ISDN (ISDN address)");

  /** Route Through: 21 */
  public static final DnsResourceRecordType RT =
      new DnsResourceRecordType((short) 21, "RT (Route Through)");

  /** NSAP address: 22 */
  public static final DnsResourceRecordType NSAP =
      new DnsResourceRecordType((short) 22, "NSAP (NSAP address)");

  /** NSAP style domain name pointer: 23 */
  public static final DnsResourceRecordType NSAP_PTR =
      new DnsResourceRecordType((short) 23, "NSAP-PTR (NSAP style domain name pointer)");

  /** Security signature: 24 */
  public static final DnsResourceRecordType SIG =
      new DnsResourceRecordType((short) 24, "SIG (Security signature)");

  /** Security key: 25 */
  public static final DnsResourceRecordType KEY =
      new DnsResourceRecordType((short) 25, "KEY (Security key)");

  /** X.400 mail mapping information: 26 */
  public static final DnsResourceRecordType PX =
      new DnsResourceRecordType((short) 26, "PX (X.400 mail mapping information)");

  /** Geographical Position: 27 */
  public static final DnsResourceRecordType GPOS =
      new DnsResourceRecordType((short) 27, "GPOS (Geographical Position)");

  /** IP6 Address: 28 */
  public static final DnsResourceRecordType AAAA =
      new DnsResourceRecordType((short) 28, "AAAA (IP6 Address)");

  /** Location Information: 29 */
  public static final DnsResourceRecordType LOC =
      new DnsResourceRecordType((short) 29, "LOC (Location Information)");

  /** Next Domain: 30 */
  public static final DnsResourceRecordType NXT =
      new DnsResourceRecordType((short) 30, "NXT (Next Domain)");

  /** Endpoint Identifier: 31 */
  public static final DnsResourceRecordType EID =
      new DnsResourceRecordType((short) 31, "EID (Endpoint Identifier)");

  /** Nimrod Locator: 32 */
  public static final DnsResourceRecordType NIMLOC =
      new DnsResourceRecordType((short) 32, "NIMLOC (Nimrod Locator)");

  /** Server Selection: 33 */
  public static final DnsResourceRecordType SRV =
      new DnsResourceRecordType((short) 33, "SRV (Server Selection)");

  /** ATM Address: 34 */
  public static final DnsResourceRecordType ATMA =
      new DnsResourceRecordType((short) 34, "ATMA (ATM Address)");

  /** Naming Authority Pointer: 35 */
  public static final DnsResourceRecordType NAPTR =
      new DnsResourceRecordType((short) 35, "NAPTR (Naming Authority Pointer)");

  /** Key Exchanger: 36 */
  public static final DnsResourceRecordType KX =
      new DnsResourceRecordType((short) 36, "KX (Key Exchanger)");

  /** CERT: 37 */
  public static final DnsResourceRecordType CERT = new DnsResourceRecordType((short) 37, "CERT");

  /** A6: 38 */
  public static final DnsResourceRecordType A6 = new DnsResourceRecordType((short) 38, "A6");

  /** DNAME: 39 */
  public static final DnsResourceRecordType DNAME = new DnsResourceRecordType((short) 39, "DNAME");

  /** SINK: 40 */
  public static final DnsResourceRecordType SINK = new DnsResourceRecordType((short) 40, "SINK");

  /** OPT: 41 */
  public static final DnsResourceRecordType OPT = new DnsResourceRecordType((short) 41, "OPT");

  /** APL: 42 */
  public static final DnsResourceRecordType APL = new DnsResourceRecordType((short) 42, "APL");

  /** Delegation Signer: 43 */
  public static final DnsResourceRecordType DS =
      new DnsResourceRecordType((short) 43, "DS (Delegation Signer)");

  /** SSH Key Fingerprint: 44 */
  public static final DnsResourceRecordType SSHFP =
      new DnsResourceRecordType((short) 44, "SSHFP (SSH Key Fingerprint)");

  /** IPSECKEY: 45 */
  public static final DnsResourceRecordType IPSECKEY =
      new DnsResourceRecordType((short) 45, "IPSECKEY");

  /** RRSIG: 46 */
  public static final DnsResourceRecordType RRSIG = new DnsResourceRecordType((short) 46, "RRSIG");

  /** NSEC: 47 */
  public static final DnsResourceRecordType NSEC = new DnsResourceRecordType((short) 47, "NSEC");

  /** DNSKEY: 48 */
  public static final DnsResourceRecordType DNSKEY =
      new DnsResourceRecordType((short) 48, "DNSKEY");

  /** DHCID: 49 */
  public static final DnsResourceRecordType DHCID = new DnsResourceRecordType((short) 49, "DHCID");

  /** NSEC3: 50 */
  public static final DnsResourceRecordType NSEC3 = new DnsResourceRecordType((short) 50, "NSEC3");

  /** NSEC3PARAM: 51 */
  public static final DnsResourceRecordType NSEC3PARAM =
      new DnsResourceRecordType((short) 51, "NSEC3PARAM");

  /** TLSA: 52 */
  public static final DnsResourceRecordType TLSA = new DnsResourceRecordType((short) 52, "TLSA");

  /** S/MIME cert association: 53 */
  public static final DnsResourceRecordType SMIMEA =
      new DnsResourceRecordType((short) 53, "SMIMEA (S/MIME cert association)");

  /** Host Identity Protocol: 55 */
  public static final DnsResourceRecordType HIP =
      new DnsResourceRecordType((short) 55, "HIP (Host Identity Protocol)");

  /** NINFO: 56 */
  public static final DnsResourceRecordType NINFO = new DnsResourceRecordType((short) 56, "NINFO");

  /** RKEY: 57 */
  public static final DnsResourceRecordType RKEY = new DnsResourceRecordType((short) 57, "RKEY");

  /** Trust Anchor LINK: 58 */
  public static final DnsResourceRecordType TALINK =
      new DnsResourceRecordType((short) 58, "TALINK (Trust Anchor LINK)");

  /** Child DS: 59 */
  public static final DnsResourceRecordType CDS =
      new DnsResourceRecordType((short) 59, "CDS (Child DS)");

  /** DNSKEY(s) the Child wants reflected in DS: 60 */
  public static final DnsResourceRecordType CDNSKEY =
      new DnsResourceRecordType((short) 60, "CDNSKEY (DNSKEY(s) the Child wants reflected in DS)");

  /** OpenPGP Key: 61 */
  public static final DnsResourceRecordType OPENPGPKEY =
      new DnsResourceRecordType((short) 61, "OPENPGPKEY (OpenPGP Key)");

  /** Child-To-Parent Synchronization: 62 */
  public static final DnsResourceRecordType CSYNC =
      new DnsResourceRecordType((short) 62, "CSYNC (Child-To-Parent Synchronization)");

  /** SPF: 99 */
  public static final DnsResourceRecordType SPF = new DnsResourceRecordType((short) 99, "SPF");

  /** UINFO: 100 */
  public static final DnsResourceRecordType UINFO = new DnsResourceRecordType((short) 100, "UINFO");

  /** UID: 101 */
  public static final DnsResourceRecordType UID = new DnsResourceRecordType((short) 101, "UID");

  /** GID: 102 */
  public static final DnsResourceRecordType GID = new DnsResourceRecordType((short) 102, "GID");

  /** UNSPEC: 103 */
  public static final DnsResourceRecordType UNSPEC =
      new DnsResourceRecordType((short) 103, "UNSPEC");

  /** NID: 104 */
  public static final DnsResourceRecordType NID = new DnsResourceRecordType((short) 104, "NID");

  /** L32: 105 */
  public static final DnsResourceRecordType L32 = new DnsResourceRecordType((short) 105, "L32");

  /** L64: 106 */
  public static final DnsResourceRecordType L64 = new DnsResourceRecordType((short) 106, "L64");

  /** LP: 107 */
  public static final DnsResourceRecordType LP = new DnsResourceRecordType((short) 107, "LP");

  /** EUI-48 address: 108 */
  public static final DnsResourceRecordType EUI48 =
      new DnsResourceRecordType((short) 108, "EUI48 (EUI-48 address)");

  /** EUI-64 address: 109 */
  public static final DnsResourceRecordType EUI64 =
      new DnsResourceRecordType((short) 109, "EUI64 (EUI-64 address)");

  /** Transaction Key: 249 */
  public static final DnsResourceRecordType TKEY =
      new DnsResourceRecordType((short) 249, "TKEY (Transaction Key)");

  /** Transaction Signature: 250 */
  public static final DnsResourceRecordType TSIG =
      new DnsResourceRecordType((short) 250, "TSIG (Transaction Signature)");

  /** Incremental transfer: 251 */
  public static final DnsResourceRecordType IXFR =
      new DnsResourceRecordType((short) 251, "IXFR (Incremental transfer)");

  /** Transfer of an entire zone: 252 */
  public static final DnsResourceRecordType AXFR =
      new DnsResourceRecordType((short) 252, "AXFR (Transfer of an entire zone)");

  /** Mailbox-related RRs (MB, MG or MR): 253 */
  public static final DnsResourceRecordType MAILB =
      new DnsResourceRecordType((short) 253, "MAILB (Mailbox-related RRs (MB, MG or MR))");

  /** Mail agent RRs: 254 */
  public static final DnsResourceRecordType MAILA =
      new DnsResourceRecordType((short) 254, "MAILA (Mail agent RRs)");

  /** All records: 255 */
  public static final DnsResourceRecordType ALL_RECORDS =
      new DnsResourceRecordType((short) 255, "* (All records)");

  /** URI: 256 */
  public static final DnsResourceRecordType URI = new DnsResourceRecordType((short) 256, "URI");

  /** Certification Authority Restriction: 257 */
  public static final DnsResourceRecordType CAA =
      new DnsResourceRecordType((short) 257, "CAA (Certification Authority Restriction)");

  /** Application Visibility and Control: 258 */
  public static final DnsResourceRecordType AVC =
      new DnsResourceRecordType((short) 258, "AVC (Application Visibility and Control)");

  /** DNSSEC Trust Authorities: 32768 */
  public static final DnsResourceRecordType TA =
      new DnsResourceRecordType((short) 32768, "TA (DNSSEC Trust Authorities)");

  /** DNSSEC Lookaside Validation: 32769 */
  public static final DnsResourceRecordType DLV =
      new DnsResourceRecordType((short) 32769, "DLV (DNSSEC Lookaside Validation)");

  private static final Map<Short, DnsResourceRecordType> registry =
      new HashMap<Short, DnsResourceRecordType>();

  static {
    registry.put(A.value(), A);
    registry.put(NS.value(), NS);
    registry.put(MD.value(), MD);
    registry.put(MF.value(), MF);
    registry.put(CNAME.value(), CNAME);
    registry.put(SOA.value(), SOA);
    registry.put(MB.value(), MB);
    registry.put(MG.value(), MG);
    registry.put(MR.value(), MR);
    registry.put(NULL.value(), NULL);
    registry.put(WKS.value(), WKS);
    registry.put(PTR.value(), PTR);
    registry.put(HINFO.value(), HINFO);
    registry.put(MINFO.value(), MINFO);
    registry.put(MX.value(), MX);
    registry.put(TXT.value(), TXT);
    registry.put(RP.value(), RP);
    registry.put(AFSDB.value(), AFSDB);
    registry.put(X25.value(), X25);
    registry.put(ISDN.value(), ISDN);
    registry.put(RT.value(), RT);
    registry.put(NSAP.value(), NSAP);
    registry.put(NSAP_PTR.value(), NSAP_PTR);
    registry.put(SIG.value(), SIG);
    registry.put(KEY.value(), KEY);
    registry.put(PX.value(), PX);
    registry.put(GPOS.value(), GPOS);
    registry.put(AAAA.value(), AAAA);
    registry.put(LOC.value(), LOC);
    registry.put(NXT.value(), NXT);
    registry.put(EID.value(), EID);
    registry.put(NIMLOC.value(), NIMLOC);
    registry.put(SRV.value(), SRV);
    registry.put(ATMA.value(), ATMA);
    registry.put(NAPTR.value(), NAPTR);
    registry.put(KX.value(), KX);
    registry.put(CERT.value(), CERT);
    registry.put(A6.value(), A6);
    registry.put(DNAME.value(), DNAME);
    registry.put(SINK.value(), SINK);
    registry.put(OPT.value(), OPT);
    registry.put(APL.value(), APL);
    registry.put(DS.value(), DS);
    registry.put(SSHFP.value(), SSHFP);
    registry.put(IPSECKEY.value(), IPSECKEY);
    registry.put(RRSIG.value(), RRSIG);
    registry.put(NSEC.value(), NSEC);
    registry.put(DNSKEY.value(), DNSKEY);
    registry.put(DHCID.value(), DHCID);
    registry.put(NSEC3.value(), NSEC3);
    registry.put(NSEC3PARAM.value(), NSEC3PARAM);
    registry.put(TLSA.value(), TLSA);
    registry.put(SMIMEA.value(), SMIMEA);
    registry.put(HIP.value(), HIP);
    registry.put(NINFO.value(), NINFO);
    registry.put(RKEY.value(), RKEY);
    registry.put(TALINK.value(), TALINK);
    registry.put(CDS.value(), CDS);
    registry.put(CDNSKEY.value(), CDNSKEY);
    registry.put(OPENPGPKEY.value(), OPENPGPKEY);
    registry.put(CSYNC.value(), CSYNC);
    registry.put(SPF.value(), SPF);
    registry.put(UINFO.value(), UINFO);
    registry.put(UID.value(), UID);
    registry.put(GID.value(), GID);
    registry.put(UNSPEC.value(), UNSPEC);
    registry.put(NID.value(), NID);
    registry.put(L32.value(), L32);
    registry.put(L64.value(), L64);
    registry.put(LP.value(), LP);
    registry.put(EUI48.value(), EUI48);
    registry.put(EUI64.value(), EUI64);
    registry.put(TKEY.value(), TKEY);
    registry.put(TSIG.value(), TSIG);
    registry.put(IXFR.value(), IXFR);
    registry.put(AXFR.value(), AXFR);
    registry.put(MAILB.value(), MAILB);
    registry.put(MAILA.value(), MAILA);
    registry.put(ALL_RECORDS.value(), ALL_RECORDS);
    registry.put(URI.value(), URI);
    registry.put(CAA.value(), CAA);
    registry.put(AVC.value(), AVC);
    registry.put(TA.value(), TA);
    registry.put(DLV.value(), DLV);
  }

  /**
   * @param value value
   * @param name name
   */
  public DnsResourceRecordType(Short value, String name) {
    super(value, name);
  }

  /**
   * @param value value
   * @return a DnsResourceRecordType object.
   */
  public static DnsResourceRecordType getInstance(Short value) {
    if (registry.containsKey(value)) {
      return registry.get(value);
    } else {
      return new DnsResourceRecordType(value, "unknown");
    }
  }

  /**
   * @param type type
   * @return a DnsResourceRecordType object.
   */
  public static DnsResourceRecordType register(DnsResourceRecordType type) {
    return registry.put(type.value(), type);
  }

  @Override
  public String valueAsString() {
    return String.valueOf(value() & 0xFFFF);
  }

  @Override
  public int compareTo(DnsResourceRecordType o) {
    return value().compareTo(o.value());
  }
}
