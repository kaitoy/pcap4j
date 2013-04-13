/*_##########################################################################
  _##
  _##  Copyright (C) 2012 Kaito Yamada
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory;

import org.pcap4j.packet.IpV6Packet.IpV6FlowLabel;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.11
 */
public interface IpV6FlowLabelFactory {

  // /* must implement. called by IpV6FlowLabelFactories. */
  // public static IpV6FlowLabelFactory getInstance();

  /**
   *
   * @param value
   * @return a new IpV6FlowLabel object.
   */
  public IpV6FlowLabel newFlowLabel(int value);

}
