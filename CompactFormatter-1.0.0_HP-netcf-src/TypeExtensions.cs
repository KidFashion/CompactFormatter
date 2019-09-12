// Decompiled with JetBrains decompiler
// Type: CompactFormatter.TypeExtensions
// Assembly: CompactFormatter, Version=1.0.0.0, Culture=neutral, PublicKeyToken=381bc903a79da911
// MVID: 441F1A56-E151-4D2E-A949-A5723348B8D8
// Assembly location: C:\Users\agreenbhm\Desktop\ysoserial.net-2\ysoserial\bin\Debug\CompactFormatter.dll

using System;
using System.Collections.Generic;

namespace CompactFormatter
{
  public static class TypeExtensions
  {
    internal static Dictionary<Type, string> fullNames = new Dictionary<Type, string>();
    private static object mFullNamesLock = new object();
    internal static Dictionary<Type, string> assemblyQualifiedNames = new Dictionary<Type, string>();
    private static object mAssemblyNamesLock = new object();

    public static string FullName(Type type)
    {
      if ((object) type == null)
        throw new ArgumentNullException(nameof (type));
      lock (TypeExtensions.mFullNamesLock)
      {
        string str1;
        if (TypeExtensions.fullNames.TryGetValue(type, out str1))
          return str1;
        string str2 = string.Intern(type.FullName);
        TypeExtensions.fullNames.Add(type, str2);
        return str2;
      }
    }

    public static string AssemblyQualifiedName(Type type)
    {
      if ((object) type == null)
        throw new ArgumentNullException(nameof (type));
      lock (TypeExtensions.mAssemblyNamesLock)
      {
        string str1;
        if (TypeExtensions.assemblyQualifiedNames.TryGetValue(type, out str1))
          return str1;
        string str2 = string.Intern(type.AssemblyQualifiedName);
        TypeExtensions.assemblyQualifiedNames.Add(type, str2);
        return str2;
      }
    }
  }
}
