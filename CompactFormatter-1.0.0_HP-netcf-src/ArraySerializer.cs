// Decompiled with JetBrains decompiler
// Type: CompactFormatter.ArraySerializer
// Assembly: CompactFormatter, Version=1.0.0.0, Culture=neutral, PublicKeyToken=381bc903a79da911
// MVID: 441F1A56-E151-4D2E-A949-A5723348B8D8
// Assembly location: C:\Users\agreenbhm\Desktop\ysoserial.net-2\ysoserial\bin\Debug\CompactFormatter.dll

using System;
using System.IO;
using System.Text;

namespace CompactFormatter
{
  public class ArraySerializer
  {
    internal static void SerializeArrayBytes(byte[] array, Stream serializationStream)
    {
      serializationStream.WriteByte((byte) 17);
      byte[] buffer = new byte[4];
      Buffer.BlockCopy((Array) BitConverter.GetBytes(array.Length), 0, (Array) buffer, 0, 4);
      serializationStream.Write(buffer, 0, 4);
      serializationStream.Write(array, 0, array.Length);
    }

    internal static void SerializeArrayBoolean(bool[] array, Stream serializationStream)
    {
      serializationStream.WriteByte((byte) 16);
      int length = array.Length;
      byte[] buffer1 = new byte[4];
      Buffer.BlockCopy((Array) BitConverter.GetBytes(length), 0, (Array) buffer1, 0, 4);
      serializationStream.Write(buffer1, 0, 4);
      byte[] buffer2 = new byte[length];
      Buffer.BlockCopy((Array) array, 0, (Array) buffer2, 0, length);
      serializationStream.Write(buffer2, 0, length);
    }

    internal static void SerializeArrayChar(char[] array, Stream serializationStream)
    {
      serializationStream.WriteByte((byte) 18);
      int count = array.Length * 2;
      byte[] buffer1 = new byte[4];
      Buffer.BlockCopy((Array) BitConverter.GetBytes(count), 0, (Array) buffer1, 0, 4);
      serializationStream.Write(buffer1, 0, 4);
      byte[] buffer2 = new byte[count];
      Buffer.BlockCopy((Array) array, 0, (Array) buffer2, 0, count);
      serializationStream.Write(buffer2, 0, count);
    }

    internal static char[] DeserializeArrayChar(Stream serializationStream)
    {
      byte[] buffer1 = new byte[4];
      serializationStream.Read(buffer1, 0, 4);
      int int32 = BitConverter.ToInt32(buffer1, 0);
      char[] chArray = new char[int32 / 2];
      byte[] buffer2 = new byte[int32];
      serializationStream.Read(buffer2, 0, int32);
      Buffer.BlockCopy((Array) buffer2, 0, (Array) chArray, 0, int32);
      return chArray;
    }

    internal static bool[] DeserializeArrayBoolean(Stream serializationStream)
    {
      byte[] buffer1 = new byte[4];
      serializationStream.Read(buffer1, 0, 4);
      int int32 = BitConverter.ToInt32(buffer1, 0);
      bool[] flagArray = new bool[int32];
      byte[] buffer2 = new byte[int32];
      serializationStream.Read(buffer2, 0, int32);
      Buffer.BlockCopy((Array) buffer2, 0, (Array) flagArray, 0, int32);
      return flagArray;
    }

    internal static byte[] DeserializeArrayByte(Stream serializationStream)
    {
      byte[] buffer1 = new byte[4];
      serializationStream.Read(buffer1, 0, 4);
      int int32 = BitConverter.ToInt32(buffer1, 0);
      byte[] buffer2 = new byte[int32];
      serializationStream.Read(buffer2, 0, int32);
      return buffer2;
    }

    internal static void SerializeArrayDecimal(Decimal[] array, Stream serializationStream)
    {
      serializationStream.WriteByte((byte) 19);
      int count = array.Length * 16;
      byte[] buffer1 = new byte[4];
      Buffer.BlockCopy((Array) BitConverter.GetBytes(count), 0, (Array) buffer1, 0, 4);
      serializationStream.Write(buffer1, 0, 4);
      byte[] buffer2 = new byte[count];
      int length = array.Length;
      for (int index = 0; index < length; ++index)
        Buffer.BlockCopy((Array) Decimal.GetBits(array[index]), 0, (Array) buffer2, index * 16, array.Length);
      serializationStream.Write(buffer2, 0, count);
    }

    internal static Decimal[] DeserializeArrayDecimal(Stream serializationStream)
    {
      byte[] buffer1 = new byte[4];
      serializationStream.Read(buffer1, 0, 4);
      int int32 = BitConverter.ToInt32(buffer1, 0);
      Decimal[] numArray = new Decimal[int32 / 16];
      byte[] buffer2 = new byte[int32];
      serializationStream.Read(buffer2, 0, int32);
      for (int index = 0; index < int32 / 16; ++index)
      {
        int[] bits = new int[4];
        Buffer.BlockCopy((Array) buffer2, index * 16, (Array) bits, 0, 16);
        numArray[index] = new Decimal(bits);
      }
      return numArray;
    }

    internal static void SerializeArraySingle(float[] array, Stream serializationStream)
    {
      serializationStream.WriteByte((byte) 20);
      int count = array.Length * 4;
      byte[] buffer1 = new byte[4];
      Buffer.BlockCopy((Array) BitConverter.GetBytes(count), 0, (Array) buffer1, 0, 4);
      serializationStream.Write(buffer1, 0, 4);
      byte[] buffer2 = new byte[count];
      Buffer.BlockCopy((Array) array, 0, (Array) buffer2, 0, count);
      serializationStream.Write(buffer2, 0, count);
    }

    internal static float[] DeserializeArraySingle(Stream serializationStream)
    {
      byte[] buffer1 = new byte[4];
      serializationStream.Read(buffer1, 0, 4);
      int int32 = BitConverter.ToInt32(buffer1, 0);
      float[] numArray = new float[int32 / 4];
      byte[] buffer2 = new byte[int32];
      serializationStream.Read(buffer2, 0, int32);
      Buffer.BlockCopy((Array) buffer2, 0, (Array) numArray, 0, int32);
      return numArray;
    }

    internal static void SerializeArrayDouble(double[] array, Stream serializationStream)
    {
      serializationStream.WriteByte((byte) 21);
      int count = array.Length * 8;
      byte[] buffer1 = new byte[4];
      Buffer.BlockCopy((Array) BitConverter.GetBytes(count), 0, (Array) buffer1, 0, 4);
      serializationStream.Write(buffer1, 0, 4);
      byte[] buffer2 = new byte[count];
      Buffer.BlockCopy((Array) array, 0, (Array) buffer2, 0, count);
      serializationStream.Write(buffer2, 0, count);
    }

    internal static double[] DeserializeArrayDouble(Stream serializationStream)
    {
      byte[] buffer1 = new byte[4];
      serializationStream.Read(buffer1, 0, 4);
      int int32 = BitConverter.ToInt32(buffer1, 0);
      double[] numArray = new double[int32 / 8];
      byte[] buffer2 = new byte[int32];
      serializationStream.Read(buffer2, 0, int32);
      Buffer.BlockCopy((Array) buffer2, 0, (Array) numArray, 0, int32);
      return numArray;
    }

    internal static void SerializeArrayShort(short[] array, Stream serializationStream)
    {
      serializationStream.WriteByte((byte) 22);
      int count = array.Length * 2;
      byte[] buffer1 = new byte[4];
      Buffer.BlockCopy((Array) BitConverter.GetBytes(count), 0, (Array) buffer1, 0, 4);
      serializationStream.Write(buffer1, 0, 4);
      byte[] buffer2 = new byte[count];
      Buffer.BlockCopy((Array) array, 0, (Array) buffer2, 0, count);
      serializationStream.Write(buffer2, 0, count);
    }

    internal static short[] DeserializeArrayShort(Stream serializationStream)
    {
      byte[] buffer1 = new byte[4];
      serializationStream.Read(buffer1, 0, 4);
      int int32 = BitConverter.ToInt32(buffer1, 0);
      short[] numArray = new short[int32 / 2];
      byte[] buffer2 = new byte[int32];
      serializationStream.Read(buffer2, 0, int32);
      Buffer.BlockCopy((Array) buffer2, 0, (Array) numArray, 0, int32);
      return numArray;
    }

    internal static void SerializeArrayInteger(int[] array, Stream serializationStream)
    {
      serializationStream.WriteByte((byte) 23);
      int count = array.Length * 4;
      byte[] buffer1 = new byte[4];
      Buffer.BlockCopy((Array) BitConverter.GetBytes(count), 0, (Array) buffer1, 0, 4);
      serializationStream.Write(buffer1, 0, 4);
      byte[] buffer2 = new byte[count];
      Buffer.BlockCopy((Array) array, 0, (Array) buffer2, 0, count);
      serializationStream.Write(buffer2, 0, count);
    }

    internal static int[] DeserializeArrayInteger(Stream serializationStream)
    {
      byte[] buffer1 = new byte[4];
      serializationStream.Read(buffer1, 0, 4);
      int int32 = BitConverter.ToInt32(buffer1, 0);
      int[] numArray = new int[int32 / 4];
      byte[] buffer2 = new byte[int32];
      serializationStream.Read(buffer2, 0, int32);
      Buffer.BlockCopy((Array) buffer2, 0, (Array) numArray, 0, int32);
      return numArray;
    }

    internal static void SerializeArrayLong(long[] array, Stream serializationStream)
    {
      serializationStream.WriteByte((byte) 24);
      int count = array.Length * 8;
      byte[] buffer1 = new byte[4];
      Buffer.BlockCopy((Array) BitConverter.GetBytes(count), 0, (Array) buffer1, 0, 4);
      serializationStream.Write(buffer1, 0, 4);
      byte[] buffer2 = new byte[count];
      Buffer.BlockCopy((Array) array, 0, (Array) buffer2, 0, count);
      serializationStream.Write(buffer2, 0, count);
    }

    internal static long[] DeserializeArrayLong(Stream serializationStream)
    {
      byte[] buffer1 = new byte[4];
      serializationStream.Read(buffer1, 0, 4);
      int int32 = BitConverter.ToInt32(buffer1, 0);
      long[] numArray = new long[int32 / 8];
      byte[] buffer2 = new byte[int32];
      serializationStream.Read(buffer2, 0, int32);
      Buffer.BlockCopy((Array) buffer2, 0, (Array) numArray, 0, int32);
      return numArray;
    }

    internal static void SerializeArraySByte(sbyte[] array, Stream serializationStream)
    {
      serializationStream.WriteByte((byte) 25);
      int length = array.Length;
      byte[] buffer1 = new byte[4];
      Buffer.BlockCopy((Array) BitConverter.GetBytes(length), 0, (Array) buffer1, 0, 4);
      serializationStream.Write(buffer1, 0, 4);
      byte[] buffer2 = new byte[length];
      Buffer.BlockCopy((Array) array, 0, (Array) buffer2, 0, length);
      serializationStream.Write(buffer2, 0, length);
    }

    internal static sbyte[] DeserializeArraySByte(Stream serializationStream)
    {
      byte[] buffer1 = new byte[4];
      serializationStream.Read(buffer1, 0, 4);
      int int32 = BitConverter.ToInt32(buffer1, 0);
      sbyte[] numArray = new sbyte[int32];
      byte[] buffer2 = new byte[int32];
      serializationStream.Read(buffer2, 0, int32);
      Buffer.BlockCopy((Array) buffer2, 0, (Array) numArray, 0, int32);
      return numArray;
    }

    internal static void SerializeArrayUInt16(ushort[] array, Stream serializationStream)
    {
      serializationStream.WriteByte((byte) 26);
      int count = array.Length * 2;
      byte[] buffer1 = new byte[4];
      Buffer.BlockCopy((Array) BitConverter.GetBytes(count), 0, (Array) buffer1, 0, 4);
      serializationStream.Write(buffer1, 0, 4);
      byte[] buffer2 = new byte[count];
      Buffer.BlockCopy((Array) array, 0, (Array) buffer2, 0, count);
      serializationStream.Write(buffer2, 0, count);
    }

    internal static ushort[] DeserializeArrayUInt16(Stream serializationStream)
    {
      byte[] buffer1 = new byte[4];
      serializationStream.Read(buffer1, 0, 4);
      int int32 = BitConverter.ToInt32(buffer1, 0);
      ushort[] numArray = new ushort[int32 / 2];
      byte[] buffer2 = new byte[int32];
      serializationStream.Read(buffer2, 0, int32);
      Buffer.BlockCopy((Array) buffer2, 0, (Array) numArray, 0, int32);
      return numArray;
    }

    internal static void SerializeArrayUInt32(uint[] array, Stream serializationStream)
    {
      serializationStream.WriteByte((byte) 27);
      int count = array.Length * 4;
      byte[] buffer1 = new byte[4];
      Buffer.BlockCopy((Array) BitConverter.GetBytes(count), 0, (Array) buffer1, 0, 4);
      serializationStream.Write(buffer1, 0, 4);
      byte[] buffer2 = new byte[count];
      Buffer.BlockCopy((Array) array, 0, (Array) buffer2, 0, count);
      serializationStream.Write(buffer2, 0, count);
    }

    internal static uint[] DeserializeArrayUInt32(Stream serializationStream)
    {
      byte[] buffer1 = new byte[4];
      serializationStream.Read(buffer1, 0, 4);
      int int32 = BitConverter.ToInt32(buffer1, 0);
      uint[] numArray = new uint[int32 / 4];
      byte[] buffer2 = new byte[int32];
      serializationStream.Read(buffer2, 0, int32);
      Buffer.BlockCopy((Array) buffer2, 0, (Array) numArray, 0, int32);
      return numArray;
    }

    internal static void SerializeArrayUInt64(ulong[] array, Stream serializationStream)
    {
      serializationStream.WriteByte((byte) 28);
      int count = array.Length * 8;
      byte[] buffer1 = new byte[4];
      Buffer.BlockCopy((Array) BitConverter.GetBytes(count), 0, (Array) buffer1, 0, 4);
      serializationStream.Write(buffer1, 0, 4);
      byte[] buffer2 = new byte[count];
      Buffer.BlockCopy((Array) array, 0, (Array) buffer2, 0, count);
      serializationStream.Write(buffer2, 0, count);
    }

    internal static ulong[] DeserializeArrayUInt64(Stream serializationStream)
    {
      byte[] buffer1 = new byte[4];
      serializationStream.Read(buffer1, 0, 4);
      int int32 = BitConverter.ToInt32(buffer1, 0);
      ulong[] numArray = new ulong[int32 / 8];
      byte[] buffer2 = new byte[int32];
      serializationStream.Read(buffer2, 0, int32);
      Buffer.BlockCopy((Array) buffer2, 0, (Array) numArray, 0, int32);
      return numArray;
    }

    internal static void SerializeArrayString(string[] array, Stream serializationStream)
    {
      serializationStream.WriteByte((byte) 30);
      byte[] buffer1 = new byte[4];
      Buffer.BlockCopy((Array) BitConverter.GetBytes(array.Length), 0, (Array) buffer1, 0, 4);
      serializationStream.Write(buffer1, 0, 4);
      int length = array.Length;
      for (int index = 0; index < length; ++index)
      {
        string s = array[index];
        if (s == null)
          s = "!";
        else if (s.StartsWith("!"))
          s = "!" + s;
        byte[] buffer2 = new byte[s.Length * 2 + 4];
        Buffer.BlockCopy((Array) BitConverter.GetBytes(s.Length * 2), 0, (Array) buffer2, 0, 4);
        Buffer.BlockCopy((Array) Encoding.Unicode.GetBytes(s), 0, (Array) buffer2, 4, s.Length * 2);
        serializationStream.Write(buffer2, 0, buffer2.Length);
      }
    }

    internal static string[] DeserializeArrayString(Stream serializationStream)
    {
      byte[] buffer1 = new byte[4];
      serializationStream.Read(buffer1, 0, 4);
      int int32_1 = BitConverter.ToInt32(buffer1, 0);
      string[] strArray = new string[int32_1];
      for (int index = 0; index < int32_1; ++index)
      {
        byte[] buffer2 = new byte[4];
        serializationStream.Read(buffer2, 0, 4);
        int int32_2 = BitConverter.ToInt32(buffer2, 0);
        byte[] numArray = new byte[int32_2];
        serializationStream.Read(numArray, 0, int32_2);
        strArray[index] = Encoding.Unicode.GetString(numArray, 0, int32_2);
        if (strArray[index].StartsWith("!"))
          strArray[index] = strArray[index].Length != 1 ? strArray[index].Substring(1) : (string) null;
      }
      return strArray;
    }

    internal static void SerializeArrayDateTime(DateTime[] array, Stream serializationStream)
    {
      serializationStream.WriteByte((byte) 29);
      int count = array.Length * 8;
      byte[] buffer1 = new byte[4];
      Buffer.BlockCopy((Array) BitConverter.GetBytes(count), 0, (Array) buffer1, 0, 4);
      serializationStream.Write(buffer1, 0, 4);
      byte[] buffer2 = new byte[count];
      int length = array.Length;
      for (int index = 0; index < length; ++index)
        Buffer.BlockCopy((Array) BitConverter.GetBytes(array[index].Ticks), 0, (Array) buffer2, index * 8, 8);
      serializationStream.Write(buffer2, 0, count);
    }

    internal static DateTime[] DeserializeArrayDateTime(Stream serializationStream)
    {
      byte[] buffer1 = new byte[4];
      serializationStream.Read(buffer1, 0, 4);
      int int32 = BitConverter.ToInt32(buffer1, 0);
      DateTime[] dateTimeArray = new DateTime[int32 / 8];
      for (int index = 0; index < int32 / 8; ++index)
      {
        byte[] buffer2 = new byte[8];
        serializationStream.Read(buffer2, 0, 8);
        dateTimeArray[index] = new DateTime(BitConverter.ToInt64(buffer2, 0));
      }
      return dateTimeArray;
    }
  }
}
