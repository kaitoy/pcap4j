/*_##########################################################################
  _##
  _##  Copyright (C) 2012 Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.11
 * @param <T>
 */
public interface ChecksumBuilder<T> {

  /**
   *
   * @param correctChecksumAtBuild
   * @return ChecksumBuilder
   */
  public ChecksumBuilder<T> correctChecksumAtBuild(
    boolean correctChecksumAtBuild
  );

  /**
   *
   * @return a new ChecksumBuilder object.
   */
  public T build();

}
