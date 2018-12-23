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
 * DNS OpCode
 *
 * @see <a
 *     href="http://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-5">IANA
 *     Registry</a>
 * @author Kaito Yamada
 * @since pcap4j 1.7.1
 */
public final class DnsOpCode extends NamedNumber<Byte, DnsOpCode> {

  /** */
  private static final long serialVersionUID = -7397483318208343692L;

  /** Query: 0 */
  public static final DnsOpCode QUERY = new DnsOpCode((byte) 0, "Query");

  /** IQuery: 1 */
  public static final DnsOpCode IQUERY = new DnsOpCode((byte) 1, "IQuery");

  /** Status: 2 */
  public static final DnsOpCode STATUS = new DnsOpCode((byte) 2, "Status");

  /** Notify: 4 */
  public static final DnsOpCode NOTIFY = new DnsOpCode((byte) 4, "Notify");

  /** Update: 5 */
  public static final DnsOpCode UPDATE = new DnsOpCode((byte) 5, "Update");

  private static final Map<Byte, DnsOpCode> registry = new HashMap<Byte, DnsOpCode>();

  static {
    registry.put(QUERY.value(), QUERY);
    registry.put(IQUERY.value(), IQUERY);
    registry.put(STATUS.value(), STATUS);
    registry.put(NOTIFY.value(), NOTIFY);
    registry.put(UPDATE.value(), UPDATE);
  }

  /**
   * @param value value
   * @param name name
   */
  public DnsOpCode(Byte value, String name) {
    super(value, name);
    if ((value & 0xF0) != 0) {
      throw new IllegalArgumentException(
          value + " is invalid value. " + "DNS OpCode must be between 0 and 15");
    }
  }

  /**
   * @param value value
   * @return a DnsOpCode object.
   */
  public static DnsOpCode getInstance(Byte value) {
    if (registry.containsKey(value)) {
      return registry.get(value);
    } else {
      return new DnsOpCode(value, "unknown");
    }
  }

  /**
   * @param code code
   * @return a DnsOpCode object.
   */
  public static DnsOpCode register(DnsOpCode code) {
    return registry.put(code.value(), code);
  }

  @Override
  public int compareTo(DnsOpCode o) {
    return value().compareTo(o.value());
  }
}
