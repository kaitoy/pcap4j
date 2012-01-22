/*_##########################################################################
  _##
  _##  Copyright (C) 2011  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet.namedvalue;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.1
 */
public abstract class NamedNumber<T extends Number> {

  private final T value;
  private final String name;

  /**
   *
   * @param value
   * @param name
   */
  protected NamedNumber(T value, String name) {
    this.value = value;
    this.name = name;
  }

  /**
   *
   * @return
   */
  public T value() {
    return value;
  }

  /**
   *
   * @return
   */
  public String name() {
    return name;
  }

  /**
   *
   * @return
   */
  public String valueAsString() {
    return value.toString();
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    return sb.append(valueAsString()).append("(")
             .append(name).append(")").toString();
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) { return true; }
    if (!this.getClass().getName().equals(obj.getClass().getName())) {
      return false;
    }
    return this.value.equals(this.getClass().cast(obj).value());
  }

  @Override
  public int hashCode() {
    return value.intValue();
  }

}
