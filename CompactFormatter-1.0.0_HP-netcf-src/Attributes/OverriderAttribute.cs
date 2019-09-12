// Decompiled with JetBrains decompiler
// Type: CompactFormatter.Attributes.OverriderAttribute
// Assembly: CompactFormatter, Version=1.0.0.0, Culture=neutral, PublicKeyToken=381bc903a79da911
// MVID: 441F1A56-E151-4D2E-A949-A5723348B8D8
// Assembly location: C:\Users\agreenbhm\Desktop\ysoserial.net-2\ysoserial\bin\Debug\CompactFormatter.dll

using System;

namespace CompactFormatter.Attributes
{
  [AttributeUsage(AttributeTargets.Class)]
  public class OverriderAttribute : Attribute
  {
    private Type customSerializer;

    public Type CustomSerializer
    {
      get
      {
        return this.customSerializer;
      }
    }

    public OverriderAttribute(Type customSerializer)
    {
      this.customSerializer = customSerializer;
    }
  }
}
