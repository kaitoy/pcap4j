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
 * DNS RCODE
 *
 * @see <a
 *     href="http://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-6">IANA
 *     Registry</a>
 * @author Kaito Yamada
 * @since pcap4j 1.7.1
 */
public final class DnsRCode extends NamedNumber<Byte, DnsRCode> {

  /** */
  private static final long serialVersionUID = -1275148349508319228L;

  /** No Error: 0 */
  public static final DnsRCode NO_ERROR = new DnsRCode((byte) 0, "No Error");

  /** Format Error: 1 */
  public static final DnsRCode FORM_ERR = new DnsRCode((byte) 1, "Format Error");

  /** Server Failure: 2 */
  public static final DnsRCode SERV_FAIL = new DnsRCode((byte) 2, "Server Failure");

  /** Non-Existent Domain: 3 */
  public static final DnsRCode NX_DOMAIN = new DnsRCode((byte) 3, "Non-Existent Domain");

  /** Not Implemented: 4 */
  public static final DnsRCode NOT_IMP = new DnsRCode((byte) 4, "Not Implemented");

  /** Query Refused: 5 */
  public static final DnsRCode REFUSED = new DnsRCode((byte) 5, "Query Refused");

  /** Name Exists when it should not: 6 */
  public static final DnsRCode YX_DOMAIN = new DnsRCode((byte) 6, "Name Exists when it should not");

  /** RR Set Exists when it should not: 7 */
  public static final DnsRCode YX_RR_SET =
      new DnsRCode((byte) 7, "RR Set Exists when it should not");

  /** RR Set that should exist does not: 8 */
  public static final DnsRCode NX_RR_SET =
      new DnsRCode((byte) 8, "RR Set that should exist does not");

  /** Not Authorized: 9 */
  public static final DnsRCode NOT_AUTH = new DnsRCode((byte) 9, "Not Authorized");

  /** Name not contained in zone: 10 */
  public static final DnsRCode NOT_ZONE = new DnsRCode((byte) 10, "Name not contained in zone");

  private static final Map<Byte, DnsRCode> registry = new HashMap<Byte, DnsRCode>();

  static {
    registry.put(NO_ERROR.value(), NO_ERROR);
    registry.put(FORM_ERR.value(), FORM_ERR);
    registry.put(SERV_FAIL.value(), SERV_FAIL);
    registry.put(NX_DOMAIN.value(), NX_DOMAIN);
    registry.put(NOT_IMP.value(), NOT_IMP);
    registry.put(REFUSED.value(), REFUSED);
    registry.put(YX_DOMAIN.value(), YX_DOMAIN);
    registry.put(YX_RR_SET.value(), YX_RR_SET);
    registry.put(NX_RR_SET.value(), NX_RR_SET);
    registry.put(NOT_AUTH.value(), NOT_AUTH);
    registry.put(NOT_ZONE.value(), NOT_ZONE);
  }

  /**
   * @param value value
   * @param name name
   */
  public DnsRCode(Byte value, String name) {
    super(value, name);
    if ((value & 0xF0) != 0) {
      throw new IllegalArgumentException(
          value + " is invalid value. " + "DNS RCODE must be between 0 and 15");
    }
  }

  /**
   * @param value value
   * @return a DnsRCode object.
   */
  public static DnsRCode getInstance(Byte value) {
    if (registry.containsKey(value)) {
      return registry.get(value);
    } else {
      return new DnsRCode(value, "unknown");
    }
  }

  /**
   * @param code code
   * @return a DnsRCode object.
   */
  public static DnsRCode register(DnsRCode code) {
    return registry.put(code.value(), code);
  }

  @Override
  public int compareTo(DnsRCode o) {
    return value().compareTo(o.value());
  }
}
