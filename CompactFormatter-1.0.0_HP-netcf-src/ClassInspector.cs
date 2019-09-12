// Decompiled with JetBrains decompiler
// Type: CompactFormatter.ClassInspector
// Assembly: CompactFormatter, Version=1.0.0.0, Culture=neutral, PublicKeyToken=381bc903a79da911
// MVID: 441F1A56-E151-4D2E-A949-A5723348B8D8
// Assembly location: C:\Users\agreenbhm\Desktop\ysoserial.net-2\ysoserial\bin\Debug\CompactFormatter.dll

using System;
using System.Collections;
using System.Reflection;

namespace CompactFormatter
{
  public class ClassInspector
  {
    private static Hashtable ReflectionCache = new Hashtable();

    public static void Clear()
    {
      ClassInspector.ReflectionCache.Clear();
    }

    public static Hashtable InspectClass(Type type)
    {
      Hashtable hashtable = (Hashtable) ClassInspector.ReflectionCache[(object) type];
      if (hashtable != null)
        return hashtable;
      Hashtable h = new Hashtable();
      ClassInspector.InspectClassInternal(type, h);
      ClassInspector.ReflectionCache[(object) type] = (object) h;
      return h;
    }

    private static void InspectClassInternal(Type type, Hashtable h)
    {
      FieldInfo[] fields = type.GetFields(BindingFlags.DeclaredOnly | BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);
      int length = fields.Length;
      for (int index = 0; index < length; ++index)
      {
        if ((fields[index].Attributes & FieldAttributes.NotSerialized) != FieldAttributes.NotSerialized)
          h[(object) fields[index].Name] = (object) fields[index];
      }
      Type baseType = type.BaseType;
      if ((object) baseType == null || baseType.Equals(typeof (object)))
        return;
      ClassInspector.InspectClassInternal(baseType, h);
    }

    private class FieldInfoComparer : IComparer
    {
      public int Compare(object x, object y)
      {
        if (x == null || y == null)
          throw new System.Exception("invalid arg");
        return string.Compare(((MemberInfo) x).Name, ((MemberInfo) y).Name);
      }
    }
  }
}
