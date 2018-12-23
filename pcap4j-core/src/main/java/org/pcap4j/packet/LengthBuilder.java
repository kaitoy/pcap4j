/*_##########################################################################
  _##
  _##  Copyright (C) 2012 Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.11
 * @param <T> tye type of object this builder builds.
 */
public interface LengthBuilder<T> {

  /**
   * @param correctLengthAtBuild correctLengthAtBuild
   * @return LengthBuilder
   */
  public LengthBuilder<T> correctLengthAtBuild(boolean correctLengthAtBuild);

  /** @return a new object. */
  public T build();
}
