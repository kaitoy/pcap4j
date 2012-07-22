/*_##########################################################################
  _##
  _##  Copyright (C) 2012  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet.namednumber;

import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Map;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.10
 */
public final class IpV6OptionType extends NamedNumber<Byte> {

  // http://www.ietf.org/rfc/rfc2460.txt

  /**
   *
   */
  private static final long serialVersionUID = -5043412814955401877L;

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
          IpV6OptionType typeCode = (IpV6OptionType)field.get(null);
          registry.put(typeCode.value(), typeCode);
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

  private final IpV6OptionTypeCode code;

  private IpV6OptionType(Byte value, String name) {
    super(value, name);

    switch (value & 0xC0) {
      case 0x00:
        this.code = IpV6OptionTypeCode.SKIP;
        break;
      case 0x40:
        this.code = IpV6OptionTypeCode.DISCARD;
        break;
      case 0x80:
        this.code = IpV6OptionTypeCode.DISCARD_AND_SEND_ICMP;
        break;
      case 0xC0:
        this.code = IpV6OptionTypeCode.DISCARD_AND_SEND_ICMP_IF_NOT_MULTICAST;
        break;
      default:
        throw new AssertionError("Never get here");
    }
  }

  /**
   *
   * @param value
   * @return
   */
  public static IpV6OptionType getInstance(Byte value) {
    if (registry.containsKey(value)) {
      return registry.get(value);
    }
    else {
      return new IpV6OptionType(value, "unknown");
    }
  }

  @Override
  public int compareTo(Byte o) {
    return value().compareTo(o);
  }

  public IpV6OptionTypeCode getCode() {
    return code;
  }

  public boolean optionDataIsChangable() {
    return (value() & 0x20) != 0;
  }

  public static enum IpV6OptionTypeCode {
    SKIP((byte)0),
    DISCARD((byte)1),
    DISCARD_AND_SEND_ICMP((byte)3),
    DISCARD_AND_SEND_ICMP_IF_NOT_MULTICAST((byte)4);

    private final byte value;

    private IpV6OptionTypeCode(byte value) {
      this.value = value;
    }

    /**
     *
     * @return
     */
    public int getValue() {
      return value;
    }
  }

}