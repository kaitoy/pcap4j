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
 * LLC Control Supervisory Function
 *
 * @see <a href="http://standards.ieee.org/about/get/802/802.2.html">IEEE 802.2</a>
 * @author Kaito Yamada
 * @since pcap4j 1.6.5
 */
public final class LlcControlSupervisoryFunction
    extends NamedNumber<Byte, LlcControlSupervisoryFunction> {

  /** */
  private static final long serialVersionUID = 6818202103839595038L;

  /** Receive ready (RR): 0 */
  public static final LlcControlSupervisoryFunction RR =
      new LlcControlSupervisoryFunction((byte) 0, "Receive ready");

  /** Receive not ready: 1 */
  public static final LlcControlSupervisoryFunction RNR =
      new LlcControlSupervisoryFunction((byte) 1, "Receive not ready");

  /** Reject: 2 */
  public static final LlcControlSupervisoryFunction REJ =
      new LlcControlSupervisoryFunction((byte) 2, "Reject");

  private static final Map<Byte, LlcControlSupervisoryFunction> registry =
      new HashMap<Byte, LlcControlSupervisoryFunction>();

  static {
    registry.put(RR.value(), RR);
    registry.put(RNR.value(), RNR);
    registry.put(REJ.value(), REJ);
  }

  /**
   * @param value value
   * @param name name
   */
  public LlcControlSupervisoryFunction(Byte value, String name) {
    super(value, name);
    if ((value & 0xFC) != 0) {
      throw new IllegalArgumentException(value + " is invalid value. It must be between 0 and 3");
    }
  }

  /**
   * @param value value
   * @return a LlcSupervisoryFunction object.
   */
  public static LlcControlSupervisoryFunction getInstance(Byte value) {
    if (registry.containsKey(value)) {
      return registry.get(value);
    } else {
      return new LlcControlSupervisoryFunction(value, "unknown");
    }
  }

  /**
   * @param number number
   * @return a LlcSupervisoryFunction object.
   */
  public static LlcControlSupervisoryFunction register(LlcControlSupervisoryFunction number) {
    return registry.put(number.value(), number);
  }

  @Override
  public int compareTo(LlcControlSupervisoryFunction o) {
    return value().compareTo(o.value());
  }
}
