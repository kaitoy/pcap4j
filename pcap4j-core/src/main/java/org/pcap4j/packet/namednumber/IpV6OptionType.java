/*_##########################################################################
  _##
  _##  Copyright (C) 2012-2015  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.namednumber;

import java.util.HashMap;
import java.util.Map;
import org.pcap4j.util.ByteArrays;

/**
 * IpV6 Option Type
 *
 * @see <a
 *     href="http://www.iana.org/assignments/ipv6-parameters/ipv6-parameters.xml#ipv6-parameters-2">IANA
 *     Registry</a>
 * @see <a href="http://tools.ietf.org/html/rfc2460#section-4.2">RFC 2460 section 4.2</a>
 * @author Kaito Yamada
 * @since pcap4j 0.9.10
 */
public final class IpV6OptionType extends NamedNumber<Byte, IpV6OptionType> {

  /** */
  private static final long serialVersionUID = 2460312908857953021L;

  /** Pad1: 0x00 */
  public static final IpV6OptionType PAD1 = new IpV6OptionType((byte) 0x00, "Pad1");

  /** PadN: 0x01 */
  public static final IpV6OptionType PADN = new IpV6OptionType((byte) 0x01, "PadN");

  /** Jumbo Payload: 0xC2 */
  public static final IpV6OptionType JUMBO_PAYLOAD =
      new IpV6OptionType((byte) 0xC2, "Jumbo Payload");

  /** RPL: 0x63 */
  public static final IpV6OptionType RPL = new IpV6OptionType((byte) 0x63, "RPL");

  /** Tunnel Encapsulation Limit: 0x04 */
  public static final IpV6OptionType TUNNEL_ENCAPSULATION_LIMIT =
      new IpV6OptionType((byte) 0x04, "Tunnel Encapsulation Limit");

  /** Router Alert: 0x05 */
  public static final IpV6OptionType ROUTER_ALERT = new IpV6OptionType((byte) 0x05, "Router Alert");

  /** Quick-Start: 0x26 */
  public static final IpV6OptionType QUICK_START = new IpV6OptionType((byte) 0x26, "Quick-Start");

  /** CALIPSO: 0x07 */
  public static final IpV6OptionType CALIPSO = new IpV6OptionType((byte) 0x07, "CALIPSO");

  /** SMF_DPD: 0x08 */
  public static final IpV6OptionType SMF_DPD = new IpV6OptionType((byte) 0x08, "SMF_DPD");

  /** Home Address: 0xC9 */
  public static final IpV6OptionType HOME_ADDRESS = new IpV6OptionType((byte) 0xC9, "Home Address");

  /** Endpoint Identification: 0x8A */
  public static final IpV6OptionType ENDPOINT_IDENTIFICATION =
      new IpV6OptionType((byte) 0x8A, "Endpoint Identification");

  /** ILNP Nonce: 0x8B */
  public static final IpV6OptionType ILNP_NONCE = new IpV6OptionType((byte) 0x8B, "ILNP Nonce");

  /** Line-Identification: 0x8C */
  public static final IpV6OptionType LINE_IDENTIFICATION =
      new IpV6OptionType((byte) 0x8C, "Line-Identification");

  /** MPL: 0x6D */
  public static final IpV6OptionType MPL = new IpV6OptionType((byte) 0x6D, "MPL");

  /** IP_DFF: 0xEE */
  public static final IpV6OptionType IP_DFF = new IpV6OptionType((byte) 0xEE, "IP_DFF");

  private static final Map<Byte, IpV6OptionType> registry = new HashMap<Byte, IpV6OptionType>();

  static {
    registry.put(PAD1.value(), PAD1);
    registry.put(PADN.value(), PADN);
    registry.put(JUMBO_PAYLOAD.value(), JUMBO_PAYLOAD);
    registry.put(RPL.value(), RPL);
    registry.put(TUNNEL_ENCAPSULATION_LIMIT.value(), TUNNEL_ENCAPSULATION_LIMIT);
    registry.put(ROUTER_ALERT.value(), ROUTER_ALERT);
    registry.put(QUICK_START.value(), QUICK_START);
    registry.put(CALIPSO.value(), CALIPSO);
    registry.put(SMF_DPD.value(), SMF_DPD);
    registry.put(HOME_ADDRESS.value(), HOME_ADDRESS);
    registry.put(ENDPOINT_IDENTIFICATION.value(), ENDPOINT_IDENTIFICATION);
    registry.put(ILNP_NONCE.value(), ILNP_NONCE);
    registry.put(LINE_IDENTIFICATION.value(), LINE_IDENTIFICATION);
    registry.put(MPL.value(), MPL);
    registry.put(IP_DFF.value(), IP_DFF);
  }

  private final IpV6OptionTypeAction action;

  /**
   * @param value value
   * @param name name
   */
  public IpV6OptionType(Byte value, String name) {
    super(value, name);

    switch (value & 0xC0) {
      case 0x00:
        this.action = IpV6OptionTypeAction.SKIP;
        break;
      case 0x40:
        this.action = IpV6OptionTypeAction.DISCARD;
        break;
      case 0x80:
        this.action = IpV6OptionTypeAction.DISCARD_AND_SEND_ICMP;
        break;
      case 0xC0:
        this.action = IpV6OptionTypeAction.DISCARD_AND_SEND_ICMP_IF_NOT_MULTICAST;
        break;
      default:
        throw new AssertionError("Never get here");
    }
  }

  /**
   * @param value value
   * @return a IpV6OptionType object.
   */
  public static IpV6OptionType getInstance(Byte value) {
    if (registry.containsKey(value)) {
      return registry.get(value);
    } else {
      return new IpV6OptionType(value, "unknown");
    }
  }

  /**
   * @param type type
   * @return a IpV6OptionType object.
   */
  public static IpV6OptionType register(IpV6OptionType type) {
    return registry.put(type.value(), type);
  }

  @Override
  public String valueAsString() {
    return "0x" + ByteArrays.toHexString(value(), "");
  }

  @Override
  public int compareTo(IpV6OptionType o) {
    return value().compareTo(o.value());
  }

  /**
   * The act field (The highest-order two bits of the Option Type)
   *
   * @return action
   */
  public IpV6OptionTypeAction getAction() {
    return action;
  }

  /**
   * The chg field (The third-highest-order bit of the Option Type)
   *
   * @return true if the option data may change en-route; false the option data does not change
   *     en-route.
   */
  public boolean optionDataMayChange() {
    return (value() & 0x20) != 0;
  }

  /**
   * The act field (The highest-order two bits of the Option Type). This specifies the action that
   * must be taken if the processing IPv6 node does not recognize the Option Type.
   *
   * @see <a href="http://tools.ietf.org/html/rfc2460#section-4.2">RFC 2460 section 4.2</a>
   * @author Kaito
   * @since pcap4j 0.9.10
   */
  public static enum IpV6OptionTypeAction {

    /** Skip over this option and continue processing the header: 0 */
    SKIP((byte) 0),

    /** Discard the packet: 1 */
    DISCARD((byte) 1),

    /**
     * Discard the packet and, regardless of whether or not the packet's Destination Address was a
     * multicast address, send an ICMP Parameter Problem, Code 2, message to the packet's Source
     * Address, pointing to the unrecognized Option Type: 2
     */
    DISCARD_AND_SEND_ICMP((byte) 2),

    /**
     * Discard the packet and, only if the packet's Destination Address was not a multicast address,
     * send an ICMP Parameter Problem, Code 2, message to the packet's Source Address, pointing to
     * the unrecognized Option Type: 3
     */
    DISCARD_AND_SEND_ICMP_IF_NOT_MULTICAST((byte) 3);

    private final byte value;

    private IpV6OptionTypeAction(byte value) {
      this.value = value;
    }

    /** @return value */
    public int getValue() {
      return value;
    }
  }
}
