/*_##########################################################################
  _##
  _##  Copyright (C) 2016-2019  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.namednumber;

import java.util.HashMap;
import java.util.Map;

/**
 * SCTP Port
 *
 * @see <a
 *     href="http://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xml">IANA
 *     Registry</a>
 * @author Jeff Myers (myersj@gmail.com)
 * @since pcap4j 1.6.6
 */
public final class SctpPort extends Port {

  /** */
  private static final long serialVersionUID = 8265462534894583620L;

  /** Discard: 9 */
  public static final SctpPort DISCARD = new SctpPort((short) 9, "Discard");

  /** File Transfer [Default Data]: 20 */
  public static final SctpPort FTP_DATA = new SctpPort((short) 20, "File Transfer [Default Data]");

  /** File Transfer [Control]: 21 */
  public static final SctpPort FTP = new SctpPort((short) 21, "File Transfer [Control]");

  /** The Secure Shell (SSH): 22 */
  public static final SctpPort SSH = new SctpPort((short) 22, "SSH");

  /** HTTP: 80 */
  public static final SctpPort HTTP = new SctpPort((short) 80, "HTTP");

  /** Border Gateway Protocol: 179 */
  public static final SctpPort BGP = new SctpPort((short) 179, "Border Gateway Protocol");

  /** HTTPS: 443 */
  public static final SctpPort HTTPS = new SctpPort((short) 443, "HTTPS");

  private static final Map<Short, SctpPort> registry = new HashMap<Short, SctpPort>();

  static {
    registry.put(DISCARD.value(), DISCARD);
    registry.put(FTP_DATA.value(), FTP_DATA);
    registry.put(FTP.value(), FTP);
    registry.put(SSH.value(), SSH);
    registry.put(HTTP.value(), HTTP);
    registry.put(BGP.value(), BGP);
    registry.put(HTTPS.value(), HTTPS);
  }

  /**
   * @param value value
   * @param name name
   */
  public SctpPort(Short value, String name) {
    super(value, name);
  }

  /**
   * @param value value
   * @return a SctpPort object.
   */
  public static SctpPort getInstance(Short value) {
    if (registry.containsKey(value)) {
      return registry.get(value);
    } else {
      return new SctpPort(value, "unknown");
    }
  }

  /**
   * @param port port
   * @return a SctpPort object.
   */
  public static SctpPort register(SctpPort port) {
    return registry.put(port.value(), port);
  }
}
