package io.jenkins.plugins.portscanner;

import java.io.Serializable;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

public class OpenPort implements Serializable
{
  private static final long serialVersionUID = 1L;
  private int portNmb;
  private List<Cipher> supportedCiphers = new ArrayList<>();
  private transient String hostUnderTest;

  public OpenPort(String hostUnderTest, int portNmb)
  {
    this.hostUnderTest = hostUnderTest;
    this.portNmb = portNmb;
  }

  public int getPortNmb()
  {
    return portNmb;
  }

  public void setPortNmb(int portNmb)
  {
    this.portNmb = portNmb;
  }

  public boolean isTlsPort()
  {
    return false;
  }

  public String connectWithCipher(String host, int port, String cipher, String prot) throws Exception
  {
    TrustManager[] trustAllCerts = new TrustManager[] { new X509TrustManager()
    {
      public java.security.cert.X509Certificate[] getAcceptedIssuers()
      {
        return null;
      }

      public void checkClientTrusted(java.security.cert.X509Certificate[] certs, String authType)
      {
        // No need to implement.
      }

      public void checkServerTrusted(java.security.cert.X509Certificate[] certs, String authType)
      {
        // No need to implement.
      }
    } };

    SSLContext sc = SSLContext.getInstance("TLS");
    sc.init(null, trustAllCerts, new java.security.SecureRandom());
    SSLSocketFactory factory = sc.getSocketFactory();
    try (SSLSocket connection = (SSLSocket) factory.createSocket(host, port))
    {
      connection.setEnabledCipherSuites(new String[] { cipher });
      connection.setEnabledProtocols(new String[] { prot });
      connection.setSoTimeout(1000);
      connection.startHandshake();
      return connection.getSession().getProtocol();
    }
  }

  public void detectCiphers()
  {
    Security.setProperty("jdk.tls.disabledAlgorithms", "");
    System.setProperty("jdk.tls.namedGroups",
        "secp256r1, secp384r1, secp521r1, sect283k1, sect283r1, sect409k1, sect409r1, sect571k1, sect571r1, secp256k1");
    System.setProperty("jdk.disabled.namedCurves", "");
    Security.setProperty("crypto.policy", "unlimited"); // For Java 9+
    System.setProperty("jdk.sunec.disableNative", "false");
    
    SSLServerSocketFactory ssf = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
    String[] prots = new String[] { "SSLv2Hello", "SSLv3", "TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3" };
    try
    {
      prots = SSLContext.getDefault().getSupportedSSLParameters().getProtocols();
    }
    catch (NoSuchAlgorithmException e1)
    {
      e1.printStackTrace();
    }
    for (String p : prots)
    {
      for (String cipher : ssf.getSupportedCipherSuites())
      {
        try
        {
          String prot = connectWithCipher(hostUnderTest, portNmb, cipher,p);
          supportedCiphers.add(new Cipher(prot, cipher));
        }
        catch (Exception e)
        {
          //ignore
        }
      }
    }
  }

  public List<Cipher> getSupportedCiphers()
  {
    return supportedCiphers;
  }
}
