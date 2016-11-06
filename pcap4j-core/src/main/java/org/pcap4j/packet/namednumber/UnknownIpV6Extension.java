/*_##########################################################################
  _##
  _##  Copyright (C) 2016  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.namednumber;

import java.io.ObjectStreamException;

/**
 * Unknown IPv6 Extension
 *
 * @author Kaito Yamada
 * @since pcap4j 2.0.0
 */
public final class UnknownIpV6Extension extends IpNumber {

  /**
   *
   */
  private static final long serialVersionUID = -2782771635662625494L;

  private static UnknownIpV6Extension INSTANCE
    = new UnknownIpV6Extension((byte) 255, "Unknown IPv6 Extension");

  /**
   * @param value value
   * @param name name
   */
  private UnknownIpV6Extension(Byte value, String name) {
    super(value, name);
  }

  /**
   * @return the singleton instance of UnknownIpV6Extension.
   */
  public static UnknownIpV6Extension getInstance() {
    return INSTANCE;
  }

  /**
   * This method is just to hide a method of the super class.
   *
   * @param value value
   * @return the singleton instance of UnknownIpV6Extension.
   * @deprecated Use {@link #getInstance()} instead.
   */
  @Deprecated
  public static UnknownIpV6Extension getInstance(Byte value) {
    return INSTANCE;
  }

  /**
   * This method is just to hide a method of the super class.
   *
   * @param number number
   * @return N/A
   * @throws UnsupportedOperationException always.
   * @deprecated This method always throws UnsupportedOperationException.
   */
  @Deprecated
  public static UnknownIpV6Extension register(IpNumber number) {
    throw new UnsupportedOperationException();
  }

  /**
   * @deprecated This method returns a dummy value.
   */
  @Override
  @Deprecated
  public Byte value() {
    return super.value();
  }

  /**
   * @deprecated This method returns a dummy name.
   */
  @Override
  @Deprecated
  public String name() {
    return super.name();
  }

  /**
   * @deprecated This method returns a dummy value.
   */
  @Override
  @Deprecated
  public String valueAsString() {
    return super.valueAsString();
  }

  /**
   * @deprecated Comparing this to an IpNumber instance is no use.
   */
  @Override
  @Deprecated
  public int compareTo(IpNumber o) {
    return super.compareTo(o);
  }

  @Override
  public String toString() {
    return "Unknown IPv6 Extension";
  }

  @Override
  public int hashCode() {
    return 0;
  }

  @Override
  public boolean equals(Object obj) {
    return (this == obj);
  }

  // Override deserializer to keep singleton
  private Object readResolve() throws ObjectStreamException {
    return INSTANCE;
  }

}