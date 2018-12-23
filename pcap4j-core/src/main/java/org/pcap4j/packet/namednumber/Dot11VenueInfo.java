/*_##########################################################################
  _##
  _##  Copyright (C) 2016  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.namednumber;

import java.util.HashMap;
import java.util.Map;
import org.pcap4j.util.ByteArrays;

/**
 * IEEE802.11 Venue Info field
 *
 * <pre>{@code
 *        1          1
 * +-----------+-----------+
 * |Venue Group|Venue Type |
 * +-----------+-----------+
 * }</pre>
 *
 * @see <a href="http://standards.ieee.org/getieee802/download/802.11-2012.pdf">IEEE802.11</a>
 * @see Dot11VenueGroup
 * @author Kaito Yamada
 * @since pcap4j 1.7.0
 */
public final class Dot11VenueInfo extends NamedNumber<Short, Dot11VenueInfo> {

  /** */
  private static final long serialVersionUID = 7218904434618722743L;

  /** Emergency Coordination Center: 0x010F */
  public static final Dot11VenueInfo EMERGENCY_COORDINATION_CENTER =
      new Dot11VenueInfo((short) 0x010F, "Emergency Coordination Center");

  /** Unspecified Business: 0x0200 */
  public static final Dot11VenueInfo UNSPECIFIED_BUSINESS =
      new Dot11VenueInfo((short) 0x0200, "Unspecified Business");

  /** Doctor or Dentist office: 0x0201 */
  public static final Dot11VenueInfo DOCTOR_OR_DENTIST_OFFICE =
      new Dot11VenueInfo((short) 0x0201, "Doctor or Dentist office");

  /** Bank: 0x0202 */
  public static final Dot11VenueInfo BANK = new Dot11VenueInfo((short) 0x0202, "Bank");

  /** Fire Station: 0x0203 */
  public static final Dot11VenueInfo FIRE_STATION =
      new Dot11VenueInfo((short) 0x0203, "Fire Station");

  /** Police Station: 0x0204 */
  public static final Dot11VenueInfo POLICE_STATION =
      new Dot11VenueInfo((short) 0x0204, "Police Station");

  /** Post Office: 0x0206 */
  public static final Dot11VenueInfo POST_OFFICE =
      new Dot11VenueInfo((short) 0x0206, "Post Office");

  /** Professional Office: 0x0207 */
  public static final Dot11VenueInfo PROFESSIONAL_OFFICE =
      new Dot11VenueInfo((short) 0x0207, "Professional Office");

  /** Research and Development Facility: 0x0208 */
  public static final Dot11VenueInfo RESEARCH_AND_DEVELOPMENT_FACILITY =
      new Dot11VenueInfo((short) 0x0208, "Research and Development Facility");

  /** Attorney Office: 0x0209 */
  public static final Dot11VenueInfo ATTORNEY_OFFICE =
      new Dot11VenueInfo((short) 0x0209, "Attorney Office");

  /** Unspecified Educational: 0x0300 */
  public static final Dot11VenueInfo UNSPECIFIED_EDUCATIONAL =
      new Dot11VenueInfo((short) 0x0300, "Unspecified Educational");

  /** School Primary: 0x0301 */
  public static final Dot11VenueInfo SCHOOL_PRIMARY =
      new Dot11VenueInfo((short) 0x0301, "School Primary");

  /** School Secondary: 0x0302 */
  public static final Dot11VenueInfo SCHOOL_SECONDARY =
      new Dot11VenueInfo((short) 0x0302, "School Secondary");

  /** University or College: 0x0303 */
  public static final Dot11VenueInfo UNIVERSITY_OR_COLLEGE =
      new Dot11VenueInfo((short) 0x0303, "University or College");

  /** Unspecified Factory and Industrial: 0x0400 */
  public static final Dot11VenueInfo UNSPECIFIED_FACTORY_AND_INDUSTRIAL =
      new Dot11VenueInfo((short) 0x0400, "Unspecified Factory and Industrial");

  /** Factory: 0x0401 */
  public static final Dot11VenueInfo FACTORY = new Dot11VenueInfo((short) 0x0401, "Factory");

  /** Unspecified Institutional: 0x0500 */
  public static final Dot11VenueInfo UNSPECIFIED_INSTITUTIONAL =
      new Dot11VenueInfo((short) 0x0500, "Unspecified Institutional");

  /** Hospital: 0x0501 */
  public static final Dot11VenueInfo HOSPITAL = new Dot11VenueInfo((short) 0x0501, "Hospital");

  /** Long-Term Care Facility: 0x0502 */
  public static final Dot11VenueInfo LONG_TERM_CARE_FACILITY =
      new Dot11VenueInfo((short) 0x0502, "Long-Term Care Facility");

  /** Alcohol and Drug Rehabilitation Center: 0x0503 */
  public static final Dot11VenueInfo ALCOHOL_AND_DRUG_REHABILITATION_CENTER =
      new Dot11VenueInfo((short) 0x0503, "Alcohol and Drug Rehabilitation Center");

  /** Group Home: 0x0504 */
  public static final Dot11VenueInfo GROUP_HOME = new Dot11VenueInfo((short) 0x0504, "Group Home");

  /** Prison or Jail: 0x0505 */
  public static final Dot11VenueInfo PRISON_OR_JAIL =
      new Dot11VenueInfo((short) 0x0505, "Prison or Jail");

  /** Unspecified Mercantile: 0x0600 */
  public static final Dot11VenueInfo UNSPECIFIED_MERCANTILE =
      new Dot11VenueInfo((short) 0x0600, "Unspecified Mercantile");

  /** Retail Store: 0x0601 */
  public static final Dot11VenueInfo RETAIL_STORE =
      new Dot11VenueInfo((short) 0x0601, "Retail Store");

  /** Grocery Market: 0x0602 */
  public static final Dot11VenueInfo GROCERY_MARKET =
      new Dot11VenueInfo((short) 0x0602, "Grocery Market");

  /** Automotive Service Station: 0x0603 */
  public static final Dot11VenueInfo AUTOMOTIVE_SERVICE_STATION =
      new Dot11VenueInfo((short) 0x0603, "Automotive Service Station");

  /** Shopping Mall: 0x0604 */
  public static final Dot11VenueInfo SHOPPING_MALL =
      new Dot11VenueInfo((short) 0x0604, "Shopping Mall");

  /** Gas Station: 0x0605 */
  public static final Dot11VenueInfo GAS_STATION =
      new Dot11VenueInfo((short) 0x0605, "Gas Station");

  /** Unspecified Residential: 0x0700 */
  public static final Dot11VenueInfo UNSPECIFIED_RESIDENTIAL =
      new Dot11VenueInfo((short) 0x0700, "Unspecified Residential");

  /** Private Residence: 0x0701 */
  public static final Dot11VenueInfo PRIVATE_RESIDENCE =
      new Dot11VenueInfo((short) 0x0701, "Private Residence");

  /** Hotel or Motel: 0x0702 */
  public static final Dot11VenueInfo HOTEL_OR_MOTEL =
      new Dot11VenueInfo((short) 0x0702, "Hotel or Motel");

  /** Dormitory: 0x0703 */
  public static final Dot11VenueInfo DORMITORY = new Dot11VenueInfo((short) 0x0703, "Dormitory");

  /** Boarding House: 0x0704 */
  public static final Dot11VenueInfo BOARDING_HOUSE =
      new Dot11VenueInfo((short) 0x0704, "Boarding House");

  /** Unspecified Storage: 0x0800 */
  public static final Dot11VenueInfo UNSPECIFIED_STORAGE =
      new Dot11VenueInfo((short) 0x0800, "Unspecified Storage");

  /** Unspecified Utility and Miscellaneous: 0x0900 */
  public static final Dot11VenueInfo UNSPECIFIED_UTILITY_AND_MISCELLANEOUS =
      new Dot11VenueInfo((short) 0x0900, "Unspecified Utility and Miscellaneous");

  /** Unspecified Vehicular: 0x0A00 */
  public static final Dot11VenueInfo UNSPECIFIED_VEHICULAR =
      new Dot11VenueInfo((short) 0x0A00, "Unspecified Vehicular");

  /** Automobile or Truck: 0x0A01 */
  public static final Dot11VenueInfo AUTOMOBILE_OR_TRUCK =
      new Dot11VenueInfo((short) 0x0A01, "Automobile or Truck");

  /** Airplane: 0x0A02 */
  public static final Dot11VenueInfo AIRPLANE = new Dot11VenueInfo((short) 0x0A02, "Airplane");

  /** Bus: 0x0A03 */
  public static final Dot11VenueInfo BUS = new Dot11VenueInfo((short) 0x0A03, "Bus");

  /** Ferry: 0x0A04 */
  public static final Dot11VenueInfo FERRY = new Dot11VenueInfo((short) 0x0A04, "Ferry");

  /** Ship or Boat: 0x0A05 */
  public static final Dot11VenueInfo SHIP_OR_BOAT =
      new Dot11VenueInfo((short) 0x0A05, "Ship or Boat");

  /** Train: 0x0A06 */
  public static final Dot11VenueInfo TRAIN = new Dot11VenueInfo((short) 0x0A06, "Train");

  /** Motor Bike: 0x0A07 */
  public static final Dot11VenueInfo MOTOR_BIKE = new Dot11VenueInfo((short) 0x0A07, "Motor Bike");

  /** Unspecified Outdoor: 0x0B00 */
  public static final Dot11VenueInfo UNSPECIFIED_OUTDOOR =
      new Dot11VenueInfo((short) 0x0B00, "Unspecified Outdoor");

  /** Muni-mesh Network: 0x0B01 */
  public static final Dot11VenueInfo MUNI_MESH_NETWORK =
      new Dot11VenueInfo((short) 0x0B01, "Muni-mesh Network");

  /** City Park: 0x0B02 */
  public static final Dot11VenueInfo CITY_PARK = new Dot11VenueInfo((short) 0x0B02, "City Park");

  /** Rest Area: 0x0B03 */
  public static final Dot11VenueInfo REST_AREA = new Dot11VenueInfo((short) 0x0B03, "Rest Area");

  /** Traffic Control: 0x0B04 */
  public static final Dot11VenueInfo TRAFFIC_CONTROL =
      new Dot11VenueInfo((short) 0x0B04, "Traffic Control");

  /** Bus Stop: 0x0B05 */
  public static final Dot11VenueInfo BUS_STOP = new Dot11VenueInfo((short) 0x0B05, "Bus Stop");

  /** Kiosk: 0x0B06 */
  public static final Dot11VenueInfo KIOSK = new Dot11VenueInfo((short) 0x0B06, "Kiosk");

  private static final Map<Short, Dot11VenueInfo> registry = new HashMap<Short, Dot11VenueInfo>();

  static {
    registry.put(EMERGENCY_COORDINATION_CENTER.value(), EMERGENCY_COORDINATION_CENTER);
    registry.put(UNSPECIFIED_BUSINESS.value(), UNSPECIFIED_BUSINESS);
    registry.put(DOCTOR_OR_DENTIST_OFFICE.value(), DOCTOR_OR_DENTIST_OFFICE);
    registry.put(BANK.value(), BANK);
    registry.put(FIRE_STATION.value(), FIRE_STATION);
    registry.put(POLICE_STATION.value(), POLICE_STATION);
    registry.put(POST_OFFICE.value(), POST_OFFICE);
    registry.put(PROFESSIONAL_OFFICE.value(), PROFESSIONAL_OFFICE);
    registry.put(RESEARCH_AND_DEVELOPMENT_FACILITY.value(), RESEARCH_AND_DEVELOPMENT_FACILITY);
    registry.put(ATTORNEY_OFFICE.value(), ATTORNEY_OFFICE);
    registry.put(UNSPECIFIED_EDUCATIONAL.value(), UNSPECIFIED_EDUCATIONAL);
    registry.put(SCHOOL_PRIMARY.value(), SCHOOL_PRIMARY);
    registry.put(SCHOOL_SECONDARY.value(), SCHOOL_SECONDARY);
    registry.put(UNIVERSITY_OR_COLLEGE.value(), UNIVERSITY_OR_COLLEGE);
    registry.put(UNSPECIFIED_FACTORY_AND_INDUSTRIAL.value(), UNSPECIFIED_FACTORY_AND_INDUSTRIAL);
    registry.put(FACTORY.value(), FACTORY);
    registry.put(UNSPECIFIED_INSTITUTIONAL.value(), UNSPECIFIED_INSTITUTIONAL);
    registry.put(HOSPITAL.value(), HOSPITAL);
    registry.put(LONG_TERM_CARE_FACILITY.value(), LONG_TERM_CARE_FACILITY);
    registry.put(
        ALCOHOL_AND_DRUG_REHABILITATION_CENTER.value(), ALCOHOL_AND_DRUG_REHABILITATION_CENTER);
    registry.put(GROUP_HOME.value(), GROUP_HOME);
    registry.put(PRISON_OR_JAIL.value(), PRISON_OR_JAIL);
    registry.put(UNSPECIFIED_MERCANTILE.value(), UNSPECIFIED_MERCANTILE);
    registry.put(RETAIL_STORE.value(), RETAIL_STORE);
    registry.put(GROCERY_MARKET.value(), GROCERY_MARKET);
    registry.put(AUTOMOTIVE_SERVICE_STATION.value(), AUTOMOTIVE_SERVICE_STATION);
    registry.put(SHOPPING_MALL.value(), SHOPPING_MALL);
    registry.put(GAS_STATION.value(), GAS_STATION);
    registry.put(UNSPECIFIED_RESIDENTIAL.value(), UNSPECIFIED_RESIDENTIAL);
    registry.put(PRIVATE_RESIDENCE.value(), PRIVATE_RESIDENCE);
    registry.put(HOTEL_OR_MOTEL.value(), HOTEL_OR_MOTEL);
    registry.put(DORMITORY.value(), DORMITORY);
    registry.put(BOARDING_HOUSE.value(), BOARDING_HOUSE);
    registry.put(UNSPECIFIED_STORAGE.value(), UNSPECIFIED_STORAGE);
    registry.put(
        UNSPECIFIED_UTILITY_AND_MISCELLANEOUS.value(), UNSPECIFIED_UTILITY_AND_MISCELLANEOUS);
    registry.put(UNSPECIFIED_VEHICULAR.value(), UNSPECIFIED_VEHICULAR);
    registry.put(AUTOMOBILE_OR_TRUCK.value(), AUTOMOBILE_OR_TRUCK);
    registry.put(AIRPLANE.value(), AIRPLANE);
    registry.put(BUS.value(), BUS);
    registry.put(FERRY.value(), FERRY);
    registry.put(SHIP_OR_BOAT.value(), SHIP_OR_BOAT);
    registry.put(TRAIN.value(), TRAIN);
    registry.put(MOTOR_BIKE.value(), MOTOR_BIKE);
    registry.put(UNSPECIFIED_OUTDOOR.value(), UNSPECIFIED_OUTDOOR);
    registry.put(MUNI_MESH_NETWORK.value(), MUNI_MESH_NETWORK);
    registry.put(CITY_PARK.value(), CITY_PARK);
    registry.put(REST_AREA.value(), REST_AREA);
    registry.put(TRAFFIC_CONTROL.value(), TRAFFIC_CONTROL);
    registry.put(BUS_STOP.value(), BUS_STOP);
    registry.put(KIOSK.value(), KIOSK);
  }

  /** @return a Dot11VenueGroup object representing this venue group sub field. */
  public Dot11VenueGroup getVenueGroup() {
    return Dot11VenueGroup.getInstance((byte) (value() >> 8));
  }

  /**
   * @param value value
   * @param name name
   */
  public Dot11VenueInfo(Short value, String name) {
    super(value, name);
  }

  /**
   * @param value value
   * @return a Dot11VenueInfo object.
   */
  public static Dot11VenueInfo getInstance(Short value) {
    if (registry.containsKey(value)) {
      return registry.get(value);
    } else {
      return new Dot11VenueInfo(value, "unknown");
    }
  }

  /**
   * @param type type
   * @return a Dot11VenueInfo object.
   */
  public static Dot11VenueInfo register(Dot11VenueInfo type) {
    return registry.put(type.value(), type);
  }

  /** @return a string representation of this value. */
  @Override
  public String valueAsString() {
    return "0x" + ByteArrays.toHexString(value(), "");
  }

  @Override
  public int compareTo(Dot11VenueInfo o) {
    return value().compareTo(o.value());
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder(70);
    return sb.append(getVenueGroup().name())
        .append("/")
        .append(name())
        .append(" (")
        .append(valueAsString())
        .append(")")
        .toString();
  }
}
