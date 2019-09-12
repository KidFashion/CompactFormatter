// Decompiled with JetBrains decompiler
// Type: CompactFormatter.Exception.RegisterSurrogateException
// Assembly: CompactFormatter, Version=1.0.0.0, Culture=neutral, PublicKeyToken=381bc903a79da911
// MVID: 441F1A56-E151-4D2E-A949-A5723348B8D8
// Assembly location: C:\Users\agreenbhm\Desktop\ysoserial.net-2\ysoserial\bin\Debug\CompactFormatter.dll

using System.Reflection;

namespace CompactFormatter.Exception
{
  public class RegisterSurrogateException : System.Exception
  {
    public RegisterSurrogateException(MethodInfo m)
      : base("Error trying to register as surrogate method " + m.Name + " defined in type " + m.DeclaringType.Name + ", type is not marked with SurrogateAttribute")
    {
    }
  }
}
