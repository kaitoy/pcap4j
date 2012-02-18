/*_##########################################################################
  _##
  _##  Copyright (C) 2012  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.util;

import java.io.Serializable;

/**
 *
 * @author Kaito Yamada
 * @since pcap4j 0.9.5
 */
public class ValueCache<T> implements Serializable {

  /**
   *
   */
  private static final long serialVersionUID = 1379102837076225509L;

  private volatile T value = null;

  /**
   *
   * @param value
   */
  public void setValue(T value) { this.value = value; }

  /**
   *
   * @return
   */
  public T getValue() { return value; }

}
