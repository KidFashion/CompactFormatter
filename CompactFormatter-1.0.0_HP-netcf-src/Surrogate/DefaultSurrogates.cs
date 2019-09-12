// Decompiled with JetBrains decompiler
// Type: CompactFormatter.Surrogate.DefaultSurrogates
// Assembly: CompactFormatter, Version=1.0.0.0, Culture=neutral, PublicKeyToken=381bc903a79da911
// MVID: 441F1A56-E151-4D2E-A949-A5723348B8D8
// Assembly location: C:\Users\agreenbhm\Desktop\ysoserial.net-2\ysoserial\bin\Debug\CompactFormatter.dll

using System;
using System.Collections;
using System.Reflection;

namespace CompactFormatter.Surrogate
{
  public class DefaultSurrogates
  {    
    [Attributes.Surrogate(typeof (DBNull))]
    public static object DBNullSurrogate(Type t)
    {
      return (object) DBNull.Value;
    }

    [Attributes.Surrogate(typeof (ArrayList))]
    public static object DefaultSurrogate(Type t)
    {
      Type[] types = new Type[0];
      ConstructorInfo constructor = t.GetConstructor(types);
      if ((object) constructor == null)
        Console.WriteLine("No parameterless constructor available for object {0}", (object) t);
      return constructor.Invoke((object[]) null);
    }
  }
}
