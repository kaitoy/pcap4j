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
 * LLC Control Modifier Function
 *
 * @see <a href="http://standards.ieee.org/about/get/802/802.2.html">IEEE 802.2</a>
 * @author Kaito Yamada
 * @since pcap4j 1.6.5
 */
public final class LlcControlModifierFunction
    extends NamedNumber<Byte, LlcControlModifierFunction> {

  /** */
  private static final long serialVersionUID = 468392162004904375L;

  /** Unnumbered information (UI): 0 */
  public static final LlcControlModifierFunction UI =
      new LlcControlModifierFunction((byte) 0, "UI");

  /** Disconnect mode (DM): 3 */
  public static final LlcControlModifierFunction DM =
      new LlcControlModifierFunction((byte) 3, "DM");

  /** Disconnect (DISC): 16 */
  public static final LlcControlModifierFunction DISC =
      new LlcControlModifierFunction((byte) 16, "DISC");

  /** Unnumbered acknowledgment (UA): 24 */
  public static final LlcControlModifierFunction UA =
      new LlcControlModifierFunction((byte) 24, "UA");

  /** Acknowledged connectionless information/acknowledgment 0 (AC0): 25 */
  public static final LlcControlModifierFunction AC0 =
      new LlcControlModifierFunction((byte) 25, "AC0");

  /** Set asynchronous balanced mode extended (SABME): 16 */
  public static final LlcControlModifierFunction SABME =
      new LlcControlModifierFunction((byte) 27, "SABME");

  /** Frame reject (FRMR): 33 */
  public static final LlcControlModifierFunction FRMR =
      new LlcControlModifierFunction((byte) 33, "FRMR");

  /** Exchange identification (XID): 43 */
  public static final LlcControlModifierFunction XID =
      new LlcControlModifierFunction((byte) 43, "XID");

  /** Test (TEST): 56 */
  public static final LlcControlModifierFunction TEST =
      new LlcControlModifierFunction((byte) 56, "TEST");

  /** Acknowledged connectionless information/acknowledgment 1 (AC1): 57 */
  public static final LlcControlModifierFunction AC1 =
      new LlcControlModifierFunction((byte) 57, "AC1");

  private static final Map<Byte, LlcControlModifierFunction> registry =
      new HashMap<Byte, LlcControlModifierFunction>();

  static {
    registry.put(UI.value(), UI);
    registry.put(DM.value(), DM);
    registry.put(DISC.value(), DISC);
    registry.put(UA.value(), UA);
    registry.put(AC0.value(), AC0);
    registry.put(SABME.value(), SABME);
    registry.put(FRMR.value(), FRMR);
    registry.put(XID.value(), XID);
    registry.put(TEST.value(), TEST);
    registry.put(AC1.value(), AC1);
  }

  /**
   * @param value value
   * @param name name
   */
  public LlcControlModifierFunction(Byte value, String name) {
    super(value, name);
    if (value < 0 || value > 59 || (value & 0x04) != 0) {
      throw new IllegalArgumentException(
          "value must be (value >= 0 || value <= 55 || (value & 0x04) == 0). value: " + value);
    }
  }

  /**
   * @param value value
   * @return a LlcControlModifierFunction object.
   */
  public static LlcControlModifierFunction getInstance(Byte value) {
    if (registry.containsKey(value)) {
      return registry.get(value);
    } else {
      return new LlcControlModifierFunction(value, "unknown");
    }
  }

  /**
   * @param number number
   * @return a LlcControlModifierFunction object.
   */
  public static LlcControlModifierFunction register(LlcControlModifierFunction number) {
    return registry.put(number.value(), number);
  }

  @Override
  public int compareTo(LlcControlModifierFunction o) {
    return value().compareTo(o.value());
  }
}
