// Decompiled with JetBrains decompiler
// Type: CompactFormatter.Framework
// Assembly: CompactFormatter, Version=1.0.0.0, Culture=neutral, PublicKeyToken=381bc903a79da911
// MVID: 441F1A56-E151-4D2E-A949-A5723348B8D8
// Assembly location: C:\Users\agreenbhm\Desktop\ysoserial.net-2\ysoserial\bin\Debug\CompactFormatter.dll

using System;

namespace CompactFormatter
{
  public class Framework
  {
    public static FrameworkVersion FVersion = FrameworkVersion.NET11;

    public static FrameworkVersion Detect()
    {
      OperatingSystem osVersion = Environment.OSVersion;
      if (osVersion.Platform == (PlatformID) 128)
        return FrameworkVersion.MONO;
      if (osVersion.Platform == PlatformID.WinCE && osVersion.Version.Revision == -1)
        return FrameworkVersion.NETCF10;
      if (Environment.Version.Major == 1)
      {
        if (Environment.Version.Minor == 1)
          return FrameworkVersion.NET11;
        if (Environment.Version.Minor == 0)
          return FrameworkVersion.NET10;
      }
      return FrameworkVersion.UNKNOWN;
    }
  }
}
