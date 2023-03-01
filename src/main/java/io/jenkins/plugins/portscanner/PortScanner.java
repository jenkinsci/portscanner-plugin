package io.jenkins.plugins.portscanner;

import java.io.PrintStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.AbstractMap.SimpleEntry;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;

public class PortScanner
{
  private int timeout;
  private String hostUnderTest;
  private List<OpenPort> openPorts = new ArrayList<>();
  private transient ExecutorService execService;
  private PrintStream logger;

  public PortScanner(String hostUnderTest, int timeout,int threadNmb, PrintStream logger)
  {
    this.hostUnderTest = hostUnderTest;
    this.timeout = timeout;
    this.logger = logger;
    execService = Executors.newFixedThreadPool(threadNmb);
  }


  public Future<SimpleEntry<Integer, Boolean>> portIsOpen(final String ip, final int port)
  {
    return execService.submit(new Callable<SimpleEntry<Integer, Boolean>>()
    {
      @edu.umd.cs.findbugs.annotations.SuppressFBWarnings(value = "REC_CATCH_EXCEPTION", justification = "It's a  false positive")
      @Override
      public SimpleEntry<Integer, Boolean> call()
      {
        try (Socket socket = new Socket())
        {
          if (port % 10000 == 0)
          {
            logger.println("Checking port " + port + " from " + 65535);
          }
          socket.connect(new InetSocketAddress(ip, port), timeout);
        }
        catch (Exception ex)
        {
          return new SimpleEntry<>(port, false);
        }
        return new SimpleEntry<>(port, true);
      }
    });
  }

  public List<OpenPort> quickFindOpenPorts()
  {
    logger.println("Scanning " + hostUnderTest + ", ports from 0 to 65535..");
    final List<Future<SimpleEntry<Integer, Boolean>>> futures = new ArrayList<>();
    for (int port = 1; port <= 65535; port++)
    {
      futures.add(portIsOpen(hostUnderTest, port));
    }
    execService.shutdown();
    for (final Future<SimpleEntry<Integer, Boolean>> f : futures)
    {
      try
      {
        if (Boolean.TRUE.equals(f.get().getValue()))
        {
          openPorts.add(new OpenPort(hostUnderTest, f.get().getKey()));
        }
      }
      catch (Exception e)
      {
        e.printStackTrace();
      }
    }
    return openPorts;
  }
}
