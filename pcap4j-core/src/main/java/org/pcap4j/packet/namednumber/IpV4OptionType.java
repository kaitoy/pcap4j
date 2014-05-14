/*_##########################################################################
  _##
  _##  Copyright (C) 2012-2014  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet.namednumber;

import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Map;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.11
 */
public final class IpV4OptionType extends NamedNumber<Byte, IpV4OptionType> {

  // http://www.iana.org/assignments/ip-parameters

  /**
   *
   */
  private static final long serialVersionUID = -7033971699970069137L;

  /**
   *
   */
  public static final IpV4OptionType END_OF_OPTION_LIST
    = new IpV4OptionType((byte)0, "End of Option List");

  /**
   *
   */
  public static final IpV4OptionType NO_OPERATION
    = new IpV4OptionType((byte)1, "No Operation");

  /**
   *
   */
  public static final IpV4OptionType SECURITY
    = new IpV4OptionType((byte)130, "Security");

  /**
   *
   */
  public static final IpV4OptionType LOOSE_SOURCE_ROUTING
    = new IpV4OptionType((byte)131, "Loose Source Routing");

  /**
   *
   */
  public static final IpV4OptionType INTERNET_TIMESTAMP
    = new IpV4OptionType((byte)68, "Internet Timestamp");

  /**
   *
   */
  public static final IpV4OptionType RECORD_ROUTE
    = new IpV4OptionType((byte)7, "Record Route");

  /**
   *
   */
  public static final IpV4OptionType STREAM_ID
    = new IpV4OptionType((byte)136, "Stream ID");

  /**
   *
   */
  public static final IpV4OptionType STRICT_SOURCE_ROUTING
    = new IpV4OptionType((byte)137, "Strict Source Routing");

  private static final Map<Byte, IpV4OptionType> registry
    = new HashMap<Byte, IpV4OptionType>();

  static {
    for (Field field: IpV4OptionType.class.getFields()) {
      if (IpV4OptionType.class.isAssignableFrom(field.getType())) {
        try {
          IpV4OptionType f = (IpV4OptionType)field.get(null);
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

  private final boolean copied;
  private final IpV4OptionClass optionClass;
  private final byte number;

  /**
   *
   * @param value
   * @param name
   */
  public IpV4OptionType(Byte value, String name) {
    super(value, name);

    this.copied = (value & 0x80) != 0;
    this.number = (byte)(value & 0x1F);

    switch (value & 0x60) {
      case 0x00:
        this.optionClass = IpV4OptionClass.CONTROL;
        break;
      case 0x20:
        this.optionClass = IpV4OptionClass.RESERVED_FOR_FUTURE_USE1;
        break;
      case 0x40:
        this.optionClass = IpV4OptionClass.DEBUGGING_AND_MEASUREMENT;
        break;
      case 0x60:
        this.optionClass = IpV4OptionClass.RESERVED_FOR_FUTURE_USE3;
        break;
      default:
        throw new AssertionError("Never get here");
    }
  }

  /**
   *
   * @return true if the copied flag of the packet represented by this object is true;
   *         false otherwise.
   */
  public boolean isCopied() { return copied; }

  /**
   *
   * @return optionClass
   */
  public IpV4OptionClass getOptionClass() { return optionClass; }

  /**
   *
   * @return number
   */
  public byte getNumber() { return number; }

  /**
   *
   * @param value
   * @return a IpV4OptionType object.
   */
  public static IpV4OptionType getInstance(Byte value) {
    if (registry.containsKey(value)) {
      return registry.get(value);
    }
    else {
      return new IpV4OptionType(value, "unknown");
    }
  }

  /**
   *
   * @param type
   * @return a IpV4OptionType object.
   */
  public static IpV4OptionType register(IpV4OptionType type) {
    return registry.put(type.value(), type);
  }

  @Override
  public int compareTo(IpV4OptionType o) {
    return value().compareTo(o.value());
  }

  /**
   *
   */
  @Override
  public String valueAsString() {
    return String.valueOf(value() & 0xFF);
  }

  /**
   * @author Kaito Yamada
   * @since pcap4j 0.9.11
   */
  public static enum IpV4OptionClass {

    /**
     *
     */
    CONTROL((byte)0),

    /**
     *
     */
    RESERVED_FOR_FUTURE_USE1((byte)1),

    /**
     *
     */
    DEBUGGING_AND_MEASUREMENT((byte)2),

    /**
     *
     */
    RESERVED_FOR_FUTURE_USE3((byte)3);

    private final byte value;

    private IpV4OptionClass(byte value) {
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