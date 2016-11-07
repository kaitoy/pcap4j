/*_##########################################################################
  _##
  _##  Copyright (C) 2012-2016  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory;

import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.IllegalRawDataHolder;
import org.pcap4j.packet.IllegalRawDataPacket;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.namednumber.NamedNumber;

/**
 * An interface that provides a factory method to build a packet or a packet field.
 *
 * @author Kaito Yamada
 * @since pcap4j 0.9.11
 * @param <T> the type of object the factory method returns.
 * @param <N> the type of object that is given to the factory method.
 */
public interface PacketFactory<T, N extends NamedNumber<?, ?>> {

  /**
   * A factory method to build a packet or a packet field.
   * The numbers are used as hints during the build.
   * If no number is given, this method usually return an object which just wraps the specified
   * part of the rawData without dissection.
   * If one or more numbers are given, this method attempts to find a concrete class corresponding
   * to the number for each of them in the order given. The class this method first find will be
   * instantiated and returned. If no class is found, this method behaves in the same way as no
   * number was given.
   *
   * This method doesn't throw {@link IllegalRawDataException}. Instead, if an
   * IllegalRawDataException occurred during a packet dissection, this instantiates
   * {@link IllegalRawDataPacket} (if T is {@link Packet}) or {@link IllegalRawDataHolder}
   * (if T is not {@link Packet}) and returns it.
   *
   * @param rawData a byte array including data this method will use for building a T instance.
   * @param offset offset of the data in the rawData.
   * @param length length of the data. The object to be returned is not required to use or represent
   *               entire data. It means this length is not required to be exactly same as the
   *               returning object's length, but is required to be not smaller than it.
   * @param numbers {@link NamedNumber} instances this method will refer to in order to decide
   *        which concrete class to instantiate during building a T instance.
   * @return a new packet or packet field object.
   */
  @SuppressWarnings("unchecked") // instead of @SafeVarargs which can use only for final method.
  public T newInstance(byte[] rawData, int offset, int length, N... numbers);

}
