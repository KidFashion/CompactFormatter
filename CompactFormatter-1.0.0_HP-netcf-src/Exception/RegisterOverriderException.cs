// Decompiled with JetBrains decompiler
// Type: CompactFormatter.Exception.RegisterOverriderException
// Assembly: CompactFormatter, Version=1.0.0.0, Culture=neutral, PublicKeyToken=381bc903a79da911
// MVID: 441F1A56-E151-4D2E-A949-A5723348B8D8
// Assembly location: C:\Users\agreenbhm\Desktop\ysoserial.net-2\ysoserial\bin\Debug\CompactFormatter.dll

using System;

namespace CompactFormatter.Exception
{
  public class RegisterOverriderException : System.Exception
  {
    public RegisterOverriderException(Type t)
      : base("Error trying to register as overrider type " + t.Name + ", type is not marked with OverriderAttribute")
    {
    }
  }
}
