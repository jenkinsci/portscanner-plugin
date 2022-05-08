package io.jenkins.plugins.portscanner;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Serializable;
import java.net.URL;
import java.net.URLConnection;
import java.util.Map;
import java.util.Set;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

public class Cipher implements Serializable
{
  private static final long serialVersionUID = 1L;
  private String name;
  private String prot;
  private CipherState isSecure = CipherState.UNKNOWN;
  
  public enum CipherState {SECURE,INSECURE,UNKNOWN}
  
  public Cipher(String prot, String name)
  {
    super();
    this.name = name;
    this.prot = prot;
    try
    {
      this.isSecure = isCipherSecure(name);
    }
    catch (Exception e)
    {
      isSecure = CipherState.UNKNOWN;
    }
  }
  
  public String getName()
  {
    return name;
  }

  public void setName(String name)
  {
    this.name = name;
  }

  public String getProt()
  {
    return prot;
  }

  public void setProt(String prot)
  {
    this.prot = prot;
  }
  
  public CipherState isCipherSecure(String cipher) throws IllegalArgumentException, IOException
  {
    URL url2 = new URL("https://ciphersuite.info/api/cs/");
    URLConnection request = url2.openConnection();
    request.connect();
    JsonElement root = JsonParser.parseReader(new InputStreamReader((InputStream) request.getContent()));
    JsonObject rootobj = root.getAsJsonObject(); // May be an array, may be an object.
    JsonArray suits = rootobj.getAsJsonArray("ciphersuites");
    for (JsonElement el : suits)
    {
      Set<Map.Entry<String, JsonElement>> entries = el.getAsJsonObject().entrySet();// will return members of your
      for (Map.Entry<String, JsonElement> entry : entries)
      {
        if (entry.getKey().contentEquals(cipher) || entry.getValue().getAsJsonObject()
            .getAsJsonPrimitive("openssl_name").getAsString().contentEquals(cipher))
        {
          String sec = entry.getValue().getAsJsonObject().getAsJsonPrimitive("security").getAsString();
          // System.out.println(entry.getKey() + ": " + sec);
          return sec.contentEquals("recommended") || sec.contentEquals("secure") ? CipherState.SECURE : CipherState.INSECURE;
        }
      }
    }
    throw new IllegalArgumentException("Can't find cipher: " + cipher);
  }

  public CipherState getIsSecure()
  {
    return isSecure;
  }
}
