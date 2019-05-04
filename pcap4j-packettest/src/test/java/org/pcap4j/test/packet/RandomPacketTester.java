package org.pcap4j.test.packet;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.Packet;

/**
 * Utility class to assist in testing random modifications to packets to ensure robustness of the
 * parsers.
 *
 * @author philip
 */
public class RandomPacketTester {
  private static Random r = new Random();

  /**
   * @param clazz The Packet class to test
   * @param original A packet of the right type with data in it
   */
  public static void testClass(Class<? extends Packet> clazz, Packet original) {
    Method newPacket = null;
    try {
      newPacket = clazz.getMethod("newPacket", byte[].class, int.class, int.class);
    } catch (SecurityException e) {
      fail(e.toString());
    } catch (NoSuchMethodException e) {
      fail(e.toString());
    }

    ExecutorService executor = Executors.newSingleThreadExecutor();
    Task theTask = new Task(10000, newPacket, original);
    Future<String> future = executor.submit(theTask);
    String result = null;

    for (int loop = 0; loop < 2; loop++) {
      try {
        result = future.get(30, TimeUnit.SECONDS);
      } catch (TimeoutException e) {
        if (loop == 0) {
          theTask.shutdown();
        } else {
          executor.shutdownNow();
          fail("Timed out. Possible loop?");
        }
      } catch (InterruptedException e) {
        executor.shutdownNow();
        fail(e.toString());
      } catch (ExecutionException e) {
        executor.shutdownNow();
        if (e.getCause() instanceof RuntimeException) {
          throw (RuntimeException) e.getCause();
        }

        if (e.getCause() instanceof AssertionError) {
          throw (AssertionError) e.getCause();
        }
        fail(e.toString());
      }
    }

    executor.shutdownNow();

    System.out.println(result);
  }

  private static void testMethod(Method newPacket, byte[] data) throws Throwable {
    try {
      newPacket.invoke(null, data, 0, data.length);
    } catch (InvocationTargetException e) {
      throw e.getCause();
    }
  }

  private static class StackTracePrinter {
    Throwable t;
    byte[] data;

    public StackTracePrinter(Throwable t, byte[] data) {
      this.t = t;
      this.data = data;
    }

    @Override
    public String toString() {
      StringWriter sw = new StringWriter();
      for (byte b : data) {
        sw.append(String.format("%02X ", b));
      }
      sw.append("\n");
      t.printStackTrace(new PrintWriter(sw));
      return sw.toString();
    }
  }

  private static class Task implements Callable<String> {
    private Method newPacket;
    private Packet original;
    private int loopCount;
    private boolean shutdown;

    public Task(int loopCount, Method newPacket, Packet original) {
      this.loopCount = loopCount;
      this.newPacket = newPacket;
      this.original = original;
    }

    public void shutdown() {
      shutdown = true;
    }

    @Override
    public String call() throws Exception {
      shutdown = false;
      Map<String, Integer> failures = new HashMap<String, Integer>();
      Map<String, StackTracePrinter> details = new HashMap<String, StackTracePrinter>();
      for (int i = 0; i < loopCount && !shutdown; i++) {
        byte[] data = original.getRawData();

        for (int j = r.nextInt(4); j >= 0; j--) {
          data[r.nextInt(data.length)] ^= 1 << r.nextInt(8);
        }

        if (r.nextInt(3) == 0) {
          // Lets swap a chunk of bytes
          int len = r.nextInt(8) + 1;
          int pos1 = r.nextInt(data.length - len);
          int pos2 = r.nextInt(data.length - len);

          byte[] buff = new byte[len];
          System.arraycopy(data, pos1, buff, 0, len);
          System.arraycopy(data, pos2, data, pos1, len);
          System.arraycopy(buff, 0, data, pos2, len);
        }
        try {
          testMethod(newPacket, data);
        } catch (IllegalRawDataException e) {

        } catch (Throwable e) {
          String name = e.getClass().getCanonicalName();
          Integer count = failures.get(name);
          if (count == null) {
            count = 0;
          }
          failures.put(name, count + 1);
          if (details.get(name) == null) {
            details.put(name, new StackTracePrinter(e, data));
          }
        }
      }
      assertEquals("Got failures: " + failures + "\n" + details, 0, failures.size());

      return String.format("Processed %d randomized packets", loopCount);
    }
  }
}
