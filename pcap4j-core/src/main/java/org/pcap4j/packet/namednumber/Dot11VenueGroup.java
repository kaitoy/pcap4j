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
 * IEEE802.11 Venue Group
 *
 * @see <a href="http://standards.ieee.org/getieee802/download/802.11-2012.pdf">IEEE802.11</a>
 * @author Kaito Yamada
 * @since pcap4j 1.7.0
 */
public final class Dot11VenueGroup extends NamedNumber<Byte, Dot11VenueGroup> {

  /** */
  private static final long serialVersionUID = 1522500014088468419L;

  /** Unspecified: 0 */
  public static final Dot11VenueGroup UNSPECIFIED = new Dot11VenueGroup((byte) 0, "Unspecified");

  /** Assembly: 1 */
  public static final Dot11VenueGroup ASSEMBLY = new Dot11VenueGroup((byte) 1, "Assembly");

  /** Business: 2 */
  public static final Dot11VenueGroup BUSINESS = new Dot11VenueGroup((byte) 2, "Business");

  /** Educational: 3 */
  public static final Dot11VenueGroup EDUCATIONAL = new Dot11VenueGroup((byte) 3, "Educational");

  /** Factory and Industrial: 4 */
  public static final Dot11VenueGroup FACTORY_AND_INDUSTRIAL =
      new Dot11VenueGroup((byte) 4, "Factory and Industrial");

  /** Institutional: 5 */
  public static final Dot11VenueGroup INSTITUTIONAL =
      new Dot11VenueGroup((byte) 5, "Institutional");

  /** Mercantile: 6 */
  public static final Dot11VenueGroup MERCANTILE = new Dot11VenueGroup((byte) 6, "Mercantile");

  /** Residential: 7 */
  public static final Dot11VenueGroup RESIDENTIAL = new Dot11VenueGroup((byte) 7, "Residential");

  /** Storage: 8 */
  public static final Dot11VenueGroup STORAGE = new Dot11VenueGroup((byte) 8, "Storage");

  /** Utility and Miscellaneous: 9 */
  public static final Dot11VenueGroup UTILITY_AND_MISCELLANEOUS =
      new Dot11VenueGroup((byte) 9, "Utility and Miscellaneous");

  /** Vehicular: 10 */
  public static final Dot11VenueGroup VEHICULAR = new Dot11VenueGroup((byte) 10, "Vehicular");

  /** Outdoor: 11 */
  public static final Dot11VenueGroup OUTDOOR = new Dot11VenueGroup((byte) 11, "Outdoor");

  private static final Map<Byte, Dot11VenueGroup> registry = new HashMap<Byte, Dot11VenueGroup>();

  static {
    registry.put(UNSPECIFIED.value(), UNSPECIFIED);
    registry.put(ASSEMBLY.value(), ASSEMBLY);
    registry.put(BUSINESS.value(), BUSINESS);
    registry.put(EDUCATIONAL.value(), EDUCATIONAL);
    registry.put(FACTORY_AND_INDUSTRIAL.value(), FACTORY_AND_INDUSTRIAL);
    registry.put(INSTITUTIONAL.value(), INSTITUTIONAL);
    registry.put(MERCANTILE.value(), MERCANTILE);
    registry.put(RESIDENTIAL.value(), RESIDENTIAL);
    registry.put(STORAGE.value(), STORAGE);
    registry.put(UTILITY_AND_MISCELLANEOUS.value(), UTILITY_AND_MISCELLANEOUS);
    registry.put(VEHICULAR.value(), VEHICULAR);
    registry.put(OUTDOOR.value(), OUTDOOR);
  }

  /**
   * @param value value
   * @param name name
   */
  public Dot11VenueGroup(Byte value, String name) {
    super(value, name);
  }

  /**
   * @param value value
   * @return a Dot11VenueGroup object.
   */
  public static Dot11VenueGroup getInstance(Byte value) {
    if (registry.containsKey(value)) {
      return registry.get(value);
    } else {
      return new Dot11VenueGroup(value, "unknown");
    }
  }

  /**
   * @param number number
   * @return a Dot11VenueGroup object.
   */
  public static Dot11VenueGroup register(Dot11VenueGroup number) {
    return registry.put(number.value(), number);
  }

  @Override
  public int compareTo(Dot11VenueGroup o) {
    return value().compareTo(o.value());
  }

  /** */
  @Override
  public String valueAsString() {
    return String.valueOf(value() & 0xFF);
  }
}
