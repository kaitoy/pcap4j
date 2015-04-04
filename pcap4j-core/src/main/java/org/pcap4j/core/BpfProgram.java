/*_##########################################################################
  _##
  _##  Copyright (C) 2013  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.core;

import org.pcap4j.core.NativeMappings.bpf_program;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.16
 */
public final class BpfProgram {

  private final bpf_program program;
  private final String expression;
  private volatile boolean freed = false;

  BpfProgram(bpf_program program, String expression) {
    this.program = program;
    this.expression = expression;
  }

  bpf_program getProgram() {
    return program;
  }

  /**
   *
   * @return expression
   */
  public String getExpression() {
    return expression;
  }

  /**
   *
   * @return true if the bpf_program represented by this object is freed;
   *         false otherwise.
   */
  public boolean isFreed() {
    return freed;
  }

  /**
   *
   */
  public void free() {
    NativeMappings.pcap_freecode(program);
    freed = true;
  }

  @Override
  protected void finalize() throws Throwable {
    super.finalize();
    free();
  }

  /**
   *
   * @author Kaito Yamada
   * @version pcap4j 0.9.16
   */
  public static enum BpfCompileMode {

    /**
     *
     */
    OPTIMIZE(1),

    /**
     *
     */
    NONOPTIMIZE(0);

    private final int value;

    private BpfCompileMode(int value) {
      this.value = value;
    }

    /**
     *
     * @return value
     */
    public int getValue() {
      return value;
    }

  }

}
