/*_##########################################################################
  _##
  _##  Copyright (C) 2012-2015  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet.namednumber;

import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Map;

/**
 * IpV6 Option Type
 *
 * @see <a href="http://www.iana.org/assignments/ipv6-parameters/ipv6-parameters.xml#ipv6-parameters-2">IANA Registry</a>
 * @see <a href="http://tools.ietf.org/html/rfc2460#section-4.2">RFC 2460 section 4.2</a>
 * @author Kaito Yamada
 * @since pcap4j 0.9.10
 */
public final class IpV6OptionType extends NamedNumber<Byte, IpV6OptionType> {

  /**
   *
   */
  private static final long serialVersionUID = 2460312908857953021L;

  /**
   *
   */
  public static final IpV6OptionType PAD1
    = new IpV6OptionType((byte)0, "Pad1");

  /**
   *
   */
  public static final IpV6OptionType PADN
    = new IpV6OptionType((byte)1, "PadN");

  private static final Map<Byte, IpV6OptionType> registry
    = new HashMap<Byte, IpV6OptionType>();

  static {
    for (Field field: IpV6OptionType.class.getFields()) {
      if (IpV6OptionType.class.isAssignableFrom(field.getType())) {
        try {
          IpV6OptionType f = (IpV6OptionType)field.get(null);
          registry.put(f.value(), f);
        } catch (IllegalArgumentException e) {
          throw new AssertionError(e);
        } catch (IllegalAccessException e) {
          throw new AssertionError(e);
        } catch (NullPointerException e) {
          continue;
        }
      }
    }
  }

  private final IpV6OptionTypeAction action;

  /**
   *
   * @param value
   * @param name
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
   *
   * @param value
   * @return a IpV6OptionType object.
   */
  public static IpV6OptionType getInstance(Byte value) {
    if (registry.containsKey(value)) {
      return registry.get(value);
    }
    else {
      return new IpV6OptionType(value, "unknown");
    }
  }

  /**
   *
   * @param type
   * @return a IpV6OptionType object.
   */
  public static IpV6OptionType register(IpV6OptionType type) {
    return registry.put(type.value(), type);
  }

  @Override
  public String valueAsString() {
    return String.valueOf(value() & 0xFF);
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
   * @return true if the option data may change en-route;
   *         false the option data does not change en-route.
   */
  public boolean optionDataMayChange() {
    return (value() & 0x20) != 0;
  }

  /**
   * The act field (The highest-order two bits of the Option Type).
   * This specifies the action that must be taken if the
   * processing IPv6 node does not recognize the Option Type.
   *
   * @see <a href="http://tools.ietf.org/html/rfc2460#section-4.2">RFC 2460 section 4.2</a>
   * @author Kaito
   * @since pcap4j 0.9.10
   */
  public static enum IpV6OptionTypeAction {

    /**
     * Skip over this option and continue processing the header: 0
     */
    SKIP((byte)0),

    /**
     * Discard the packet: 1
     */
    DISCARD((byte)1),

    /**
     * Discard the packet and, regardless of whether or not the
     * packet's Destination Address was a multicast address, send an
     * ICMP Parameter Problem, Code 2, message to the packet's
     * Source Address, pointing to the unrecognized Option Type: 2
     */
    DISCARD_AND_SEND_ICMP((byte)2),

    /**
     * Discard the packet and, only if the packet's Destination
     * Address was not a multicast address, send an ICMP Parameter
     * Problem, Code 2, message to the packet's Source Address,
     * pointing to the unrecognized Option Type: 3
     */
    DISCARD_AND_SEND_ICMP_IF_NOT_MULTICAST((byte)3);

    private final byte value;

    private IpV6OptionTypeAction(byte value) {
      this.value = value;
    }

    /**
     *
     * @return value
     */
    public int getValue() {
      return value;
    }

  }

}