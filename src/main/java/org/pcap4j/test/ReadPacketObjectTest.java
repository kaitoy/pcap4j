package org.pcap4j.test;

import java.io.EOFException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.ObjectInputStream;

public class ReadPacketObjectTest {

  public static void main(String[] args) throws FileNotFoundException, IOException, ClassNotFoundException {
    ObjectInputStream ois = new ObjectInputStream(new FileInputStream(new File("out")));
    try {
      while (true) {
        System.out.println(ois.readObject());
      }
    } catch (EOFException e) {}
  }

}
