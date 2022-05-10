package io.jenkins.plugins.portscanner;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.StaplerRequest;

import com.google.gson.ExclusionStrategy;
import com.google.gson.FieldAttributes;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import hudson.EnvVars;
import hudson.Extension;
import hudson.FilePath;
import hudson.Launcher;
import hudson.Util;
import hudson.model.AbstractProject;
import hudson.model.Run;
import hudson.model.TaskListener;
import hudson.remoting.Future;
import hudson.tasks.ArtifactArchiver;
import hudson.tasks.BuildStepDescriptor;
import hudson.tasks.Builder;
import jenkins.security.MasterToSlaveCallable;
import jenkins.tasks.SimpleBuildStep;
import net.sf.json.JSONObject;

public class PortScannerStep extends Builder implements SimpleBuildStep
{
  private static final String SCAN_TARGET_DEFAULT = "127.0.0.1";
  private static final String REP_NAME_DEFAULT = "portScanResult_${JOB_NAME}_${BUILD_NUMBER}.json";

  private String scanDest;
  private String repName;
  private Boolean enableCipherDetection = true;

  // Fields in config.jelly must match the parameter names in the "DataBoundConstructor"
  @DataBoundConstructor
  public PortScannerStep(String scanDest, String repName, Boolean enableCipherDetection)
  {
    this.scanDest = scanDest;
    this.repName = repName;
    this.enableCipherDetection = enableCipherDetection;
  }

  @edu.umd.cs.findbugs.annotations.SuppressFBWarnings(value = "NP_NULL_ON_SOME_PATH_FROM_RETURN_VALUE", justification = "The check is already done")
  @Override
  public void perform(Run<?, ?> run, FilePath workspace, EnvVars env, Launcher launcher, TaskListener listener)
      throws InterruptedException, IOException
  {
    String hostUnderTest = Util.replaceMacro(scanDest, run.getEnvironment(listener));
    String repNameResolved = Util.replaceMacro(repName, run.getEnvironment(listener));
    int timeout = 1000;
    PortScanner ps = new PortScanner(hostUnderTest, timeout, listener.getLogger());
    List<OpenPort> openPorts = ps.quickFindOpenPorts();
    listener.getLogger().println("There are " + openPorts.size() + " detected open ports on host " + hostUnderTest
        + " (probed with a timeout of " + timeout + "ms)");
    listener.getLogger().print("Open ports: ");
    openPorts.stream().forEach(s -> listener.getLogger().print(s.getPortNmb() + " "));
    listener.getLogger().println();
    if (Boolean.TRUE.equals(enableCipherDetection))
    {
      listener.getLogger().println();
      listener.getLogger().println("Detecting supported ciphers for " + hostUnderTest
          + " and checking cipher strength under https://ciphersuite.info/");
      List<Future<OpenPort>> futures = new ArrayList<>();
      if (launcher == null || launcher.getChannel() == null)
      {
        listener.getLogger().println("Internal error: launcher.getChannel() is " + " null" );
        return;
      }
      for (OpenPort p : openPorts)
      {
        Future<OpenPort> f = launcher.getChannel().callAsync(new CipherDetector(p));
        futures.add(f);
      }

      for (Future<OpenPort> future : futures)
      {
        OpenPort p = null;
        try
        {
          p = future.get();
        }
        catch (Exception e)
        {
          e.printStackTrace();
          continue;
        }
        if (!p.getSupportedCiphers().isEmpty())
        {
          listener.getLogger().println("Port " + hostUnderTest + ":" + p.getPortNmb() + " supports TLS: ");
          for (Cipher c : p.getSupportedCiphers())
          {
            listener.getLogger().println("Cipher for port " + hostUnderTest + ":" + p.getPortNmb() + " " + c.getProt()
                + "/" + c.getName() + "  " + c.getIsSecure());
          }
          listener.getLogger().println();
        }
        else
        {
          listener.getLogger().println("Port " + hostUnderTest + ":" + p.getPortNmb() + " doesn't support TLS!");
        }
      }
    }

    Gson gson = new GsonBuilder().setPrettyPrinting().setExclusionStrategies(new ExclusionStrategy()
    {
      @Override
      public boolean shouldSkipField(FieldAttributes f)
      {
        return f.getName().contentEquals("hostUnderTest") || (f.getName().contentEquals("supportedCiphers") && !enableCipherDetection);
      }

      @Override
      public boolean shouldSkipClass(Class<?> clazz)
      {
        return false;
      }
    }).create();
    String jsonInString = gson.toJson(openPorts);
    workspace.child(repNameResolved).write(jsonInString, null);
    listener.getLogger().println("Archiving " + repNameResolved + "..");
    ArtifactArchiver artifactArchiver = new ArtifactArchiver(repNameResolved);
    artifactArchiver.perform(run, workspace, env, launcher, listener);
  }

  public String getScanDest()
  {
    return scanDest;
  }

  public void setScanDest(String scanDest)
  {
    this.scanDest = scanDest;
  }

  public String getRepName()
  {
    return repName;
  }

  public void setRepName(String repName)
  {
    this.repName = repName;
  }

  public Boolean getEnableCipherDetection()
  {
    return enableCipherDetection;
  }

  public void setEnableCipherDetection(Boolean enableCipherDetection)
  {
    this.enableCipherDetection = enableCipherDetection;
  }
  
  private static class CipherDetector extends MasterToSlaveCallable<OpenPort, IOException> {

    private static final long serialVersionUID = 1L;
    private OpenPort port;
    public CipherDetector(OpenPort port)
    {
      this.port = port;
    }
    public OpenPort call() throws IOException
    {
      try
      {
        port.detectCiphers();
      }
      catch (Exception e)
      {
        e.printStackTrace();
      }
      return port;
    }
}

  @Extension(ordinal = -2)
  public static final class DescriptorImpl extends BuildStepDescriptor<Builder>
  {

    public DescriptorImpl()
    {
      super(PortScannerStep.class);
      load();
    }

    @Override
    public boolean configure(StaplerRequest req, JSONObject json) throws FormException
    {
      req.bindJSON(this, json);
      save();
      return true;
    }

    public String getDefaultScanDest()
    {
      return SCAN_TARGET_DEFAULT;
    }

    @Override
    public String getDisplayName()
    {
      return "Port scanner";
    }

    public String getDefaultRepName()
    {
      return REP_NAME_DEFAULT;
    }

    @Override
    public boolean isApplicable(Class<? extends AbstractProject> jobType)
    {
      return true;
    }
  }
}
