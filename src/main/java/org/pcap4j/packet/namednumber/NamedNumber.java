/*_##########################################################################
  _##
  _##  Copyright (C) 2011-2012  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet.namednumber;

import java.io.Serializable;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.1
 */
public
abstract class NamedNumber<T extends Number>
implements Comparable<T>, Serializable {

  /**
   *
   */
  private static final long serialVersionUID = 3858426889927624965L;

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

  public abstract int compareTo(T o);

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder(70);
    return sb.append(valueAsString()).append("(")
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
