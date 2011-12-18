/*_##########################################################################
  _##
  _##  Copyright (C) 2011  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet.namedvalue;


public abstract class NamedNumber<T extends Number> {

  private final T value;
  private final String name;

  protected NamedNumber(T value, String name) {
    this.value = value;
    this.name = name;
  }

  public T value() {
    return value;
  }

  public String name() {
    return name;
  }

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
