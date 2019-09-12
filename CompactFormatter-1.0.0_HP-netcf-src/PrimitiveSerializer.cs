// Decompiled with JetBrains decompiler
// Type: CompactFormatter.PrimitiveSerializer
// Assembly: CompactFormatter, Version=1.0.0.0, Culture=neutral, PublicKeyToken=381bc903a79da911
// MVID: 441F1A56-E151-4D2E-A949-A5723348B8D8
// Assembly location: C:\Users\agreenbhm\Desktop\ysoserial.net-2\ysoserial\bin\Debug\CompactFormatter.dll

using System;
using System.IO;
using System.Text;

namespace CompactFormatter
{
  public class PrimitiveSerializer
  {
    internal static void Serialize(float value, Stream stream)
    {
      stream.WriteByte((byte) 5);
      byte[] buffer = new byte[4];
      Buffer.BlockCopy((Array) BitConverter.GetBytes(value), 0, (Array) buffer, 0, 4);
      stream.Write(buffer, 0, 4);
    }

    internal static float DeserializeSingle(Stream stream)
    {
      byte[] buffer = new byte[4];
      stream.Read(buffer, 0, 4);
      return BitConverter.ToSingle(buffer, 0);
    }

    internal static void Serialize(bool value, Stream stream)
    {
      stream.WriteByte((byte) 1);
      if (value)
        stream.WriteByte((byte) 1);
      else
        stream.WriteByte((byte) 0);
    }

    internal static bool DeserializeBoolean(Stream stream)
    {
      return stream.ReadByte() == 1;
    }

    internal static void Serialize(byte value, Stream stream)
    {
      stream.WriteByte((byte) 2);
      stream.WriteByte(value);
    }

    internal static byte DeserializeByte(Stream stream)
    {
      return (byte) stream.ReadByte();
    }

    internal static void Serialize(char value, Stream stream)
    {
      stream.WriteByte((byte) 3);
      byte[] buffer = new byte[2];
      Buffer.BlockCopy((Array) BitConverter.GetBytes(value), 0, (Array) buffer, 0, 2);
      stream.Write(buffer, 0, 2);
    }

    internal static char DeserializeChar(Stream stream)
    {
      byte[] buffer = new byte[2];
      stream.Read(buffer, 0, 2);
      return BitConverter.ToChar(buffer, 0);
    }

    internal static void Serialize(double value, Stream stream)
    {
      stream.WriteByte((byte) 6);
      byte[] buffer = new byte[8];
      Buffer.BlockCopy((Array) BitConverter.GetBytes(value), 0, (Array) buffer, 0, 8);
      stream.Write(buffer, 0, 8);
    }

    internal static double DeserializeDouble(Stream stream)
    {
      byte[] buffer = new byte[8];
      stream.Read(buffer, 0, 8);
      return BitConverter.ToDouble(buffer, 0);
    }

    internal static void Serialize(short value, Stream stream)
    {
      stream.WriteByte((byte) 7);
      byte[] buffer = new byte[2];
      Buffer.BlockCopy((Array) BitConverter.GetBytes(value), 0, (Array) buffer, 0, 2);
      stream.Write(buffer, 0, 2);
    }

    internal static short DeserializeInt16(Stream stream)
    {
      byte[] buffer = new byte[2];
      stream.Read(buffer, 0, 2);
      return BitConverter.ToInt16(buffer, 0);
    }

    internal static void Serialize(int value, Stream stream)
    {
      stream.WriteByte((byte) 8);
      byte[] buffer = new byte[4];
      Buffer.BlockCopy((Array) BitConverter.GetBytes(value), 0, (Array) buffer, 0, 4);
      stream.Write(buffer, 0, 4);
    }

    internal static int DeserializeInt32(Stream stream)
    {
      byte[] buffer = new byte[4];
      stream.Read(buffer, 0, 4);
      return BitConverter.ToInt32(buffer, 0);
    }

    internal static void Serialize(long value, Stream stream)
    {
      stream.WriteByte((byte) 9);
      byte[] buffer = new byte[8];
      Buffer.BlockCopy((Array) BitConverter.GetBytes(value), 0, (Array) buffer, 0, 8);
      stream.Write(buffer, 0, 8);
    }

    internal static long DeserializeInt64(Stream stream)
    {
      byte[] buffer = new byte[8];
      stream.Read(buffer, 0, 8);
      return BitConverter.ToInt64(buffer, 0);
    }

    internal static void Serialize(sbyte value, Stream stream)
    {
      stream.WriteByte((byte) 10);
      stream.WriteByte((byte) value);
    }

    internal static sbyte DeserializeSByte(Stream stream)
    {
      return (sbyte) stream.ReadByte();
    }

    internal static void Serialize(ushort value, Stream stream)
    {
      stream.WriteByte((byte) 11);
      byte[] buffer = new byte[2];
      Buffer.BlockCopy((Array) BitConverter.GetBytes(value), 0, (Array) buffer, 0, 2);
      stream.Write(buffer, 0, 2);
    }

    internal static ushort DeserializeUInt16(Stream stream)
    {
      byte[] buffer = new byte[2];
      stream.Read(buffer, 0, 2);
      return BitConverter.ToUInt16(buffer, 0);
    }

    internal static void Serialize(uint value, Stream stream)
    {
      stream.WriteByte((byte) 12);
      byte[] buffer = new byte[4];
      Buffer.BlockCopy((Array) BitConverter.GetBytes(value), 0, (Array) buffer, 0, 4);
      stream.Write(buffer, 0, 4);
    }

    internal static uint DeserializeUInt32(Stream stream)
    {
      byte[] buffer = new byte[4];
      stream.Read(buffer, 0, 4);
      return BitConverter.ToUInt32(buffer, 0);
    }

    internal static void Serialize(ulong value, Stream stream)
    {
      stream.WriteByte((byte) 13);
      byte[] buffer = new byte[8];
      Buffer.BlockCopy((Array) BitConverter.GetBytes(value), 0, (Array) buffer, 0, 8);
      stream.Write(buffer, 0, 8);
    }

    internal static ulong DeserializeUInt64(Stream stream)
    {
      byte[] buffer = new byte[8];
      stream.Read(buffer, 0, 8);
      return BitConverter.ToUInt64(buffer, 0);
    }

    internal static void Serialize(Decimal value, Stream stream)
    {
      stream.WriteByte((byte) 4);
      int[] bits = Decimal.GetBits(value);
      byte[] buffer = new byte[16];
      Buffer.BlockCopy((Array) bits, 0, (Array) buffer, 0, 16);
      stream.Write(buffer, 0, 16);
    }

    internal static Decimal DeserializeDecimal(Stream stream)
    {
      int[] bits = new int[4];
      byte[] buffer = new byte[16];
      stream.Read(buffer, 0, 16);
      Buffer.BlockCopy((Array) buffer, 0, (Array) bits, 0, 16);
      return new Decimal(bits);
    }

    internal static void Serialize(string value, Stream stream)
    {
      stream.WriteByte((byte) 15);
      byte[] buffer = new byte[value.Length * 2 + 4];
      Buffer.BlockCopy((Array) BitConverter.GetBytes(value.Length * 2), 0, (Array) buffer, 0, 4);
      Buffer.BlockCopy((Array) Encoding.Unicode.GetBytes(value), 0, (Array) buffer, 4, value.Length * 2);
      stream.Write(buffer, 0, buffer.Length);
    }

    internal static string DeserializeString(Stream stream)
    {
      byte[] buffer = new byte[4];
      stream.Read(buffer, 0, 4);
      int int32 = BitConverter.ToInt32(buffer, 0);
      byte[] numArray = new byte[int32];
      stream.Read(numArray, 0, int32);
      return Encoding.Unicode.GetString(numArray, 0, numArray.Length);
    }

    internal static void Serialize(DateTime value, Stream stream)
    {
      stream.WriteByte((byte) 14);
      byte[] buffer = new byte[8];
      Buffer.BlockCopy((Array) BitConverter.GetBytes(value.Ticks), 0, (Array) buffer, 0, 8);
      stream.Write(buffer, 0, 8);
    }

    internal static DateTime DeserializeDateTime(Stream stream)
    {
      byte[] buffer = new byte[8];
      stream.Read(buffer, 0, 8);
      return new DateTime(BitConverter.ToInt64(buffer, 0));
    }
  }
}
