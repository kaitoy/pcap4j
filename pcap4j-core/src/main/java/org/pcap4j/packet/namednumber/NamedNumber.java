/*_##########################################################################
  _##
  _##  Copyright (C) 2011-2015  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.namednumber;

import java.io.Serializable;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.1
 * @param <T> number
 * @param <U> named number
 */
public
abstract class NamedNumber<T extends Number, U extends NamedNumber<T, ?>>
implements Comparable<U>, Serializable {

  /**
   *
   */
  private static final long serialVersionUID = 3858426889927624965L;

  private final T value;
  private final String name;

  /**
   *
   * @param value value
   * @param name name
   */
  protected NamedNumber(T value, String name) {
    this.value = value;
    this.name = name;
  }

  /**
   *
   * @return value
   */
  public T value() {
    return value;
  }

  /**
   *
   * @return name
   */
  public String name() {
    return name;
  }

  /**
   *
   * @return a string representation of this value.
   */
  public String valueAsString() {
    return value.toString();
  }

  @Override
  public abstract int compareTo(U o);

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder(70);
    return sb.append(valueAsString()).append(" (")
             .append(name).append(")").toString();
  }

  @Override
  public boolean equals(Object obj) {
    if (obj == this) { return true; }
    if (!this.getClass().isInstance(obj)) { return false; }
    return this.value.equals(this.getClass().cast(obj).value());
  }

  @Override
  public int hashCode() {
    return value.hashCode();
  }

}
