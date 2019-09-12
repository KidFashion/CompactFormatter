// Decompiled with JetBrains decompiler
// Type: CompactFormatter.SystemHashtable_Overrider
// Assembly: CompactFormatter, Version=1.0.0.0, Culture=neutral, PublicKeyToken=381bc903a79da911
// MVID: 441F1A56-E151-4D2E-A949-A5723348B8D8
// Assembly location: C:\Users\agreenbhm\Desktop\ysoserial.net-2\ysoserial\bin\Debug\CompactFormatter.dll

using CompactFormatter.Attributes;
using CompactFormatter.Interfaces;
using System;
using System.Collections;
using System.IO;

namespace CompactFormatter
{
  [Overrider(typeof (Hashtable))]
  internal class SystemHashtable_Overrider : IOverrider
  {
    public void Serialize(CompactFormatter parent, Stream serializationStream, object graph)
    {
      Hashtable hashtable = (Hashtable) graph;
      PrimitiveSerializer.Serialize(hashtable.Count, serializationStream);
      foreach (object key in (IEnumerable) hashtable.Keys)
      {
        object graph1 = hashtable[key];
        parent.innerSerialize(serializationStream, key);
        parent.innerSerialize(serializationStream, graph1);
      }
    }

    public object Deserialize(CompactFormatter parent, Stream serializationStream)
    {
      Hashtable hashtable = new Hashtable();
      if (PrimitiveSerializer.DeserializeByte(serializationStream) != (byte) 8)
        throw new System.Exception("was expecting INT32 in stream");
      int num = PrimitiveSerializer.DeserializeInt32(serializationStream);
      for (int index1 = 0; index1 < num; ++index1)
      {
        object index2 = parent.innerDeserialize(serializationStream);
        object obj = parent.innerDeserialize(serializationStream);
        hashtable[index2] = obj;
      }
      return (object) hashtable;
    }
  }
}
