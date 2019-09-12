// Decompiled with JetBrains decompiler
// Type: CompactFormatter.SystemGuid_Overrider
// Assembly: CompactFormatter, Version=1.0.0.0, Culture=neutral, PublicKeyToken=381bc903a79da911
// MVID: 441F1A56-E151-4D2E-A949-A5723348B8D8
// Assembly location: C:\Users\agreenbhm\Desktop\ysoserial.net-2\ysoserial\bin\Debug\CompactFormatter.dll

using CompactFormatter.Attributes;
using CompactFormatter.Interfaces;
using System;
using System.IO;

namespace CompactFormatter
{
  [Overrider(typeof (Guid))]
  internal class SystemGuid_Overrider : IOverrider
  {
    public void Serialize(CompactFormatter parent, Stream serializationStream, object graph)
    {
      PrimitiveSerializer.Serialize(((Guid) graph).ToString(), serializationStream);
    }

    public object Deserialize(CompactFormatter parent, Stream serializationStream)
    {
      if (PrimitiveSerializer.DeserializeByte(serializationStream) != (byte) 15)
        throw new System.Exception("was expecting STRING in stream");
      return (object) new Guid(PrimitiveSerializer.DeserializeString(serializationStream));
    }
  }
}
