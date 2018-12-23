/*_##########################################################################
  _##
  _##  Copyright (C) 2012  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.util;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.List;
import org.pcap4j.core.PcapAddress;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.1
 */
public class NifSelector {

  private static String LINE_SEPARATOR = System.getProperty("line.separator");

  /**
   * @return a PcapNetworkInterface object which represents a selected network interface.
   * @throws IOException if no network interface is available.
   */
  public final PcapNetworkInterface selectNetworkInterface() throws IOException {
    List<PcapNetworkInterface> allDevs = null;
    try {
      allDevs = Pcaps.findAllDevs();
    } catch (PcapNativeException e) {
      throw new IOException(e.getMessage());
    }

    if (allDevs == null || allDevs.isEmpty()) {
      throw new IOException("No NIF to capture.");
    }

    showNifList(allDevs);

    return doSelect(allDevs);
  }

  /**
   * @param msg msg
   * @throws IOException if fails to write.
   */
  protected void write(String msg) throws IOException {
    System.out.print(msg);
  }

  /**
   * @return string
   * @throws IOException if fails to read.
   */
  protected String read() throws IOException {
    BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
    return reader.readLine();
  }

  /**
   * @param nifs nifs
   * @throws IOException if fails to show.
   */
  protected void showNifList(List<PcapNetworkInterface> nifs) throws IOException {
    StringBuilder sb = new StringBuilder(200);
    int nifIdx = 0;
    for (PcapNetworkInterface nif : nifs) {
      sb.append("NIF[").append(nifIdx).append("]: ").append(nif.getName()).append(LINE_SEPARATOR);

      if (nif.getDescription() != null) {
        sb.append("      : description: ").append(nif.getDescription()).append(LINE_SEPARATOR);
      }

      for (LinkLayerAddress addr : nif.getLinkLayerAddresses()) {
        sb.append("      : link layer address: ").append(addr).append(LINE_SEPARATOR);
      }

      for (PcapAddress addr : nif.getAddresses()) {
        sb.append("      : address: ").append(addr.getAddress()).append(LINE_SEPARATOR);
      }
      nifIdx++;
    }
    sb.append(LINE_SEPARATOR);

    write(sb.toString());
  }

  /**
   * @param nifs nifs
   * @return a PcapNetworkInterface object which represents a selected network interface.
   * @throws IOException if fails in something around IO.
   */
  protected PcapNetworkInterface doSelect(List<PcapNetworkInterface> nifs) throws IOException {
    int nifIdx;
    while (true) {
      write("Select a device number to capture packets, or enter 'q' to quit > ");

      String input;
      if ((input = read()) == null) {
        continue;
      }

      if (input.equals("q")) {
        return null;
      }

      try {
        nifIdx = Integer.parseInt(input);
        if (nifIdx < 0 || nifIdx >= nifs.size()) {
          write("Invalid input." + LINE_SEPARATOR);
          continue;
        } else {
          break;
        }
      } catch (NumberFormatException e) {
        write("Invalid input." + LINE_SEPARATOR);
        continue;
      }
    }

    return nifs.get(nifIdx);
  }
}
