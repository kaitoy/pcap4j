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
 * Logical Link Control (LLC) Number
 *
 * @see <a
 *     href="http://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml#ieee-802-numbers-3">IANA
 *     Registry</a>
 * @author Kaito Yamada
 * @since pcap4j 1.6.5
 */
public final class LlcNumber extends NamedNumber<Byte, LlcNumber> {

  /** */
  private static final long serialVersionUID = -8810011448282399402L;

  /** NULL LSAP: 0 */
  public static final LlcNumber NULL_LSAP = new LlcNumber((byte) 0, "NULL LSAP");

  /** LLC Sublayer Mgt (individual): 2 */
  public static final LlcNumber LLC_SUBLAYER_MGT_INDIVIDUAL =
      new LlcNumber((byte) 2, "LLC Sublayer Mgt (individual)");

  /** LLC Sublayer Mgt (group): 3 */
  public static final LlcNumber LLC_SUBLAYER_MGT_GROUP =
      new LlcNumber((byte) 3, "LLC Sublayer Mgt (group)");

  /** SNA Path Control (individual): 4 */
  public static final LlcNumber SNA_PATH_CONTROL_INDIVIDUAL =
      new LlcNumber((byte) 4, "SNA Path Control (individual)");

  /** SNA Path Control (group): 5 */
  public static final LlcNumber SNA_PATH_CONTROL_GROUP =
      new LlcNumber((byte) 5, "SNA Path Control (group)");

  /** DOD IP: 6 */
  public static final LlcNumber DOD_IP = new LlcNumber((byte) 6, "DOD IP");

  /** ProWay-LAN: 14 */
  public static final LlcNumber PROWAY_LAN = new LlcNumber((byte) 14, "ProWay-LAN");

  /** EIA-RS 511: 78 */
  public static final LlcNumber EIA_RS_511 = new LlcNumber((byte) 78, "EIA-RS 511");

  /** ISI IP: 94 */
  public static final LlcNumber ISI_IP = new LlcNumber((byte) 94, "ISI IP");

  /** ProWay-LAN (IEC 955): 142 */
  public static final LlcNumber PROWAY_LAN_IEC_955 =
      new LlcNumber((byte) 142, "ProWay-LAN (IEC 955)");

  /** ARP: 152 */
  public static final LlcNumber ARP = new LlcNumber((byte) 152, "ARP");

  /** SNAP: 170 */
  public static final LlcNumber SNAP = new LlcNumber((byte) 170, "SNAP");

  /** NetBIOS: 240 */
  public static final LlcNumber NETBIOS = new LlcNumber((byte) 240, "NetBIOS");

  /** ISO CLNS IS 8473: 254 */
  public static final LlcNumber ISO_CLNS_IS_8473 = new LlcNumber((byte) 254, "ISO CLNS IS 8473");

  /** Global DSAP: 255 */
  public static final LlcNumber GLOBAL_DSAP = new LlcNumber((byte) 255, "Global DSAP");

  private static final Map<Byte, LlcNumber> registry = new HashMap<Byte, LlcNumber>();

  static {
    registry.put(NULL_LSAP.value(), NULL_LSAP);
    registry.put(LLC_SUBLAYER_MGT_INDIVIDUAL.value(), LLC_SUBLAYER_MGT_INDIVIDUAL);
    registry.put(LLC_SUBLAYER_MGT_GROUP.value(), LLC_SUBLAYER_MGT_GROUP);
    registry.put(SNA_PATH_CONTROL_INDIVIDUAL.value(), SNA_PATH_CONTROL_INDIVIDUAL);
    registry.put(SNA_PATH_CONTROL_GROUP.value(), SNA_PATH_CONTROL_GROUP);
    registry.put(DOD_IP.value(), DOD_IP);
    registry.put(PROWAY_LAN.value(), PROWAY_LAN);
    registry.put(EIA_RS_511.value(), EIA_RS_511);
    registry.put(ISI_IP.value(), ISI_IP);
    registry.put(PROWAY_LAN_IEC_955.value(), PROWAY_LAN_IEC_955);
    registry.put(ARP.value(), ARP);
    registry.put(SNAP.value(), SNAP);
    registry.put(NETBIOS.value(), NETBIOS);
    registry.put(ISO_CLNS_IS_8473.value(), ISO_CLNS_IS_8473);
    registry.put(GLOBAL_DSAP.value(), GLOBAL_DSAP);
  }

  /**
   * @param value value
   * @param name name
   */
  public LlcNumber(Byte value, String name) {
    super(value, name);
  }

  /**
   * @param value value
   * @return a LlcNumber object.
   */
  public static LlcNumber getInstance(Byte value) {
    if (registry.containsKey(value)) {
      return registry.get(value);
    } else {
      return new LlcNumber(value, "unknown");
    }
  }

  /**
   * @param number number
   * @return a LlcNumber object.
   */
  public static LlcNumber register(LlcNumber number) {
    return registry.put(number.value(), number);
  }

  @Override
  public int compareTo(LlcNumber o) {
    return value().compareTo(o.value());
  }

  /** */
  @Override
  public String valueAsString() {
    return String.valueOf(value() & 0xFF);
  }
}
