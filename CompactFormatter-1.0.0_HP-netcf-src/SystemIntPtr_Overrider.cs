// Decompiled with JetBrains decompiler
// Type: CompactFormatter.SystemIntPtr_Overrider
// Assembly: CompactFormatter, Version=1.0.0.0, Culture=neutral, PublicKeyToken=381bc903a79da911
// MVID: 441F1A56-E151-4D2E-A949-A5723348B8D8
// Assembly location: C:\Users\agreenbhm\Desktop\ysoserial.net-2\ysoserial\bin\Debug\CompactFormatter.dll

using CompactFormatter.Attributes;
using CompactFormatter.Interfaces;
using System;
using System.IO;

namespace CompactFormatter
{
  [Overrider(typeof (IntPtr))]
  internal class SystemIntPtr_Overrider : IOverrider
  {
    public void Serialize(CompactFormatter parent, Stream serializationStream, object graph)
    {
      PrimitiveSerializer.Serialize(((IntPtr) graph).ToInt32(), serializationStream);
    }

    public object Deserialize(CompactFormatter parent, Stream serializationStream)
    {
      if (PrimitiveSerializer.DeserializeByte(serializationStream) != (byte) 8)
        throw new System.Exception("was expecting INT32 in stream");
      return (object) new IntPtr(PrimitiveSerializer.DeserializeInt32(serializationStream));
    }
  }
}
