package org.pcap4j.packet.namednumber;

/**
 * Transport layer Port
 *
 * @author Ferran Altimiras
 */
public abstract class Port extends NamedNumber<Short, Port> {

  public Port(Short value, String name) {
    super(value, name);
  }

  /** @return the value of this object as an int. */
  public int valueAsInt() {
    return 0xFFFF & value();
  }

  /** @return a string representation of this value. */
  @Override
  public String valueAsString() {
    return String.valueOf(valueAsInt());
  }

  @Override
  public int compareTo(Port o) {
    return value().compareTo(o.value());
  }
}
