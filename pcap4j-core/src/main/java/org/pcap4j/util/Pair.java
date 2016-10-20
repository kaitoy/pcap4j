/*_##########################################################################
  _##
  _##  Copyright (C) 2017  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.util;

/**
 * A pair of objects
 * @author Kaito Yamada
 * @since pcap4j 1.7.2
 * @param <L> the type of the left object
 * @param <R> the type of the right object
 */
public final class Pair<L, R> {

  private final L left;
  private final R right;

  /**
   * @param left left
   * @param right right
   */
  public Pair(L left, R right) {
    this.left = left;
    this.right = right;
  }

  /**
   * @return left
   */
  public L getLeft() {
    return left;
  }

  /**
   * @return right
   */
  public R getRight() {
    return right;
  }

}
