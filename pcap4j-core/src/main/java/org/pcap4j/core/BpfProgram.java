/*_##########################################################################
  _##
  _##  Copyright (C) 2013-2019  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.core;

import org.pcap4j.core.NativeMappings.bpf_program;
import org.pcap4j.packet.Packet;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.16
 */
public final class BpfProgram {

  private final bpf_program program;
  private final String expression;
  private volatile boolean freed = false;
  private final Object lock = new Object();

  BpfProgram(bpf_program program, String expression) {
    this.program = program;
    this.expression = expression;
  }

  bpf_program getProgram() {
    return program;
  }

  /** @return expression */
  public String getExpression() {
    return expression;
  }

  /**
   * Apply the filter on a given packet. Return true if the packet given passes the filter that is
   * built from this program.
   *
   * @param packet the packet to apply the filter on
   * @return true if this program is not freed and the packet passes the filter; false otherwise.
   */
  public boolean applyFilter(Packet packet) {
    return applyFilter(packet.getRawData());
  }

  /**
   * Apply the filter on a given packet. Return true if the packet given passes the filter that is
   * built from this program.
   *
   * @param packet the packet to apply the filter on
   * @return true if this program is not freed and the packet passes the filter; false otherwise.
   */
  public boolean applyFilter(byte[] packet) {
    return applyFilter(packet, packet.length, packet.length);
  }

  /**
   * Apply the filter on a given packet. Return true if the packet given passes the filter that is
   * built from this program.
   *
   * @param packet a byte array including the packet to apply the filter on
   * @param orgPacketLen the length of the original packet
   * @param packetLen the length of the packet present
   * @return true if this program is not freed and the packet passes the filter; false otherwise.
   */
  public boolean applyFilter(byte[] packet, int orgPacketLen, int packetLen) {
    synchronized (lock) {
      if (freed) {
        return false;
      }

      if (program.bf_insns == null) {
        program.read();
      }

      return NativeMappings.bpf_filter(program.bf_insns, packet, orgPacketLen, packetLen) != 0;
    }
  }

  /** @return true if the bpf_program represented by this object is freed; false otherwise. */
  public boolean isFreed() {
    return freed;
  }

  /** */
  public void free() {
    if (freed) {
      return;
    }
    synchronized (lock) {
      if (freed) {
        return;
      }
      NativeMappings.pcap_freecode(program);
      freed = true;
    }
  }

  /**
   * @author Kaito Yamada
   * @version pcap4j 0.9.16
   */
  public static enum BpfCompileMode {

    /** */
    OPTIMIZE(1),

    /** */
    NONOPTIMIZE(0);

    private final int value;

    private BpfCompileMode(int value) {
      this.value = value;
    }

    /** @return value */
    public int getValue() {
      return value;
    }
  }
}
