/*_##########################################################################
  _##
  _##  Copyright (C) 2012  Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.util;

import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.Serializable;

/**
 *
 * @author Kaito Yamada
 * @since pcap4j 0.9.6
 */
public final class LazyValue<T1> implements Serializable {

  /**
   *
   */
  private static final long serialVersionUID = 1379102837076225509L;

  private final transient BuildValueCommand<T1> command;
  private final transient Object thisLock = new Object();

  private volatile T1 value = null;

  public LazyValue(BuildValueCommand<T1> command) {
    this.command = command;
  }

  /**
   *
   * @return value
   */
  public T1 getValue() {
    T1 result = value;
    if (result == null) {
      synchronized (thisLock) {
        result = value;
        if (result == null) {
          result = value = command.buildValue();
        }
      }
    }
    return value;
  }

  private void writeObject(ObjectOutputStream out) throws IOException {
    getValue();
    if (value == null) {
      throw new AssertionError();
    }
    out.defaultWriteObject();
  }

  /**
   *
   * @author Kaito Yamada
   * @since pcap4j 0.9.6
   * @param <T2>
   */
  public interface BuildValueCommand<T2> {

    /**
     *
     * @return value
     */
    public T2 buildValue();

  }

}
