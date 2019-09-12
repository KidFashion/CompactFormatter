// Decompiled with JetBrains decompiler
// Type: CompactFormatter
// Assembly: CompactFormatter, Version=1.0.0.0, Culture=neutral, PublicKeyToken=381bc903a79da911
// MVID: 441F1A56-E151-4D2E-A949-A5723348B8D8
// Assembly location: C:\Users\agreenbhm\Desktop\ysoserial.net-2\ysoserial\bin\Debug\CompactFormatter.dll

using CompactFormatter.Attributes;
using CompactFormatter.Exception;
using CompactFormatter.Interfaces;
using CompactFormatter.Surrogate;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Net;
using System.Reflection;
using System.ServiceModel;
using System.Text;
using System.Text.RegularExpressions;

namespace CompactFormatter
{
  public class CompactFormatter : ICFormatter
  {
    private static object[] ZERO_PARAM = new object[0];
    public static long nCreationTime = 0;
    public static long nInspectTime = 0;
    public static long nOnsTime = 0;
    public static long nBadBlock = 0;
    public static List<missingTypeAndValues> missingPropertiesList = (List<missingTypeAndValues>) null;
    private static object lockObj = new object();
    private static object ignoredLockObj = new object();
    private static ParameterModifier[] pm = new ParameterModifier[0];
    private static Type[] tp = new Type[0];
    private static Hashtable IgnoredTypeList = new Hashtable(6);
    private CFormatterMode mode;
    private CFormatterMode remoteMode;
    private FrameworkVersion remoteVersion;
    private FrameworkVersion localVersion;
    private ArrayList AssemblyList;
    private Hashtable SurrogateTable;
    private Hashtable OverriderTable;
    private ObjectTable SerializedTypesList;
    private static Hashtable SpecialTypeList;
    private ObjectTable SerializedItemsList;

    public static void ResetCounters()
    {
      CompactFormatter.nCreationTime = 0L;
      CompactFormatter.nInspectTime = 0L;
      CompactFormatter.nOnsTime = 0L;
      CompactFormatter.nBadBlock = 0L;
    }

    public CFormatterMode Mode
    {
      get
      {
        return this.mode;
      }
    }

    public void ResetFormatter()
    {
      this.AssemblyList.Clear();
      this.AssemblyList.Add((object) Assembly.Load("mscorlib"));
      this.SerializedTypesList.Clear();
      this.SerializedItemsList.Clear();
    }

    static CompactFormatter()
    {
      CompactFormatter.IgnoredTypeList[(object) typeof (CallingConventions)] = (object) null;
      CompactFormatter.IgnoredTypeList[(object) typeof (EventHandler)] = (object) null;
      CompactFormatter.IgnoredTypeList[(object) typeof (PropertyChangedEventHandler)] = (object) null;
      CompactFormatter.SpecialTypeList = new Hashtable(10);
      CompactFormatter.SpecialTypeList[(object) typeof (IntPtr)] = (object) null;
      CompactFormatter.SpecialTypeList[(object) typeof (CultureInfo)] = (object) null;
      CompactFormatter.SpecialTypeList[(object) typeof (CompareInfo)] = (object) null;
      CompactFormatter.SpecialTypeList[(object) typeof (Uri)] = (object) null;
      CompactFormatter.SpecialTypeList[(object) typeof (EndpointAddress)] = (object) null;
      CompactFormatter.SpecialTypeList[(object) typeof (Guid)] = (object) null;
      CompactFormatter.SpecialTypeList[(object) typeof (Hashtable)] = (object) null;
      CompactFormatter.SpecialTypeList[(object) typeof (ArrayList)] = (object) null;
      CompactFormatter.SpecialTypeList[(object) typeof (Regex)] = (object) null;
      CompactFormatter.SpecialTypeList[(object) typeof (IPAddress)] = (object) null;
    }

    public CompactFormatter()
      : this(CFormatterMode.SURROGATE)
    {
    }

    public CompactFormatter(CFormatterMode mode)
    {
      this.mode = mode;
      this.localVersion = Framework.FVersion;
      this.AssemblyList = new ArrayList();
      this.SurrogateTable = new Hashtable();
      this.OverriderTable = new Hashtable();
      this.SerializedTypesList = new ObjectTable(1000);
      this.SerializedItemsList = new ObjectTable(1000);
      this.AssemblyList.Add((object) Assembly.Load("mscorlib"));
      this.AddOverrider(typeof (SystemIntPtr_Overrider));
      this.AddOverrider(typeof (SystemUri_Overrider));
      this.AddOverrider(typeof (SystemServiceModelEndpointAddress_Overrider));
      this.AddSurrogate(typeof (DefaultSurrogates));
      this.AddOverrider(typeof (SystemHashtable_Overrider));
      this.AddOverrider(typeof (SystemGuid_Overrider));
      this.AddOverrider(typeof (SystemRegEx_Overrider));
      this.AddOverrider(typeof (SystemIpAddr_Overrider));
    }

    public static void IgnoreType(Type t)
    {
      lock (CompactFormatter.ignoredLockObj)
        CompactFormatter.IgnoredTypeList[(object) t] = (object) null;
    }

    public void innerSerialize(Stream serializationStream, object graph)
    {
      if (graph == null)
      {
        serializationStream.WriteByte((byte) 0);
      }
      else
      {
        Type type = graph.GetType();
        TypeCode typeCode = Type.GetTypeCode(type);
        bool flag = CompactFormatter.IgnoredTypeList.ContainsKey((object) type);
        if (!flag && type.IsSubclassOf(typeof (MulticastDelegate)))
        {
          CompactFormatter.IgnoredTypeList[(object) type] = (object) null;
          flag = true;
        }
        if (flag)
        {
          serializationStream.WriteByte((byte) 0);
        }
        else
        {
          if (type.IsPrimitive)
          {
            if ((object) type == (object) typeof (int))
            {
              PrimitiveSerializer.Serialize((int) graph, serializationStream);
              return;
            }
            if ((object) type == (object) typeof (uint))
            {
              PrimitiveSerializer.Serialize((uint) graph, serializationStream);
              return;
            }
            if ((object) type == (object) typeof (short))
            {
              PrimitiveSerializer.Serialize((short) graph, serializationStream);
              return;
            }
            if ((object) type == (object) typeof (ushort))
            {
              PrimitiveSerializer.Serialize((ushort) graph, serializationStream);
              return;
            }
            if ((object) type == (object) typeof (bool))
            {
              PrimitiveSerializer.Serialize((bool) graph, serializationStream);
              return;
            }
            if ((object) type == (object) typeof (sbyte))
            {
              PrimitiveSerializer.Serialize((sbyte) graph, serializationStream);
              return;
            }
            if ((object) type == (object) typeof (byte))
            {
              PrimitiveSerializer.Serialize((byte) graph, serializationStream);
              return;
            }
            if ((object) type == (object) typeof (char))
            {
              PrimitiveSerializer.Serialize((char) graph, serializationStream);
              return;
            }
            if ((object) type == (object) typeof (long))
            {
              PrimitiveSerializer.Serialize((long) graph, serializationStream);
              return;
            }
            if ((object) type == (object) typeof (ulong))
            {
              PrimitiveSerializer.Serialize((ulong) graph, serializationStream);
              return;
            }
            if ((object) type == (object) typeof (float))
            {
              PrimitiveSerializer.Serialize((float) graph, serializationStream);
              return;
            }
            if ((object) type == (object) typeof (double))
            {
              PrimitiveSerializer.Serialize((double) graph, serializationStream);
              return;
            }
          }
          else
          {
            if ((object) type == (object) typeof (string))
            {
              PrimitiveSerializer.Serialize((string) graph, serializationStream);
              return;
            }
            if ((object) type == (object) typeof (DateTime))
            {
              PrimitiveSerializer.Serialize((DateTime) graph, serializationStream);
              return;
            }
            if ((object) type == (object) typeof (Decimal))
            {
              PrimitiveSerializer.Serialize((Decimal) graph, serializationStream);
              return;
            }
          }
          int num1 = this.SerializedItemsList.Contains(graph);
          if (num1 != -1)
          {
            serializationStream.WriteByte((byte) 38);
            this.innerSerialize(serializationStream, (object) num1);
          }
          else if (type.IsArray)
          {
            switch (type.GetElementType().ToString())
            {
              case "System.Byte":
                this.SerializedItemsList.Add(graph);
                ArraySerializer.SerializeArrayBytes((byte[]) graph, serializationStream);
                break;
              case "System.Boolean":
                this.SerializedItemsList.Add(graph);
                ArraySerializer.SerializeArrayBoolean((bool[]) graph, serializationStream);
                break;
              case "System.Char":
                this.SerializedItemsList.Add(graph);
                ArraySerializer.SerializeArrayChar((char[]) graph, serializationStream);
                break;
              case "System.Decimal":
                this.SerializedItemsList.Add(graph);
                ArraySerializer.SerializeArrayDecimal((Decimal[]) graph, serializationStream);
                break;
              case "System.Single":
                this.SerializedItemsList.Add(graph);
                ArraySerializer.SerializeArraySingle((float[]) graph, serializationStream);
                break;
              case "System.Double":
                this.SerializedItemsList.Add(graph);
                ArraySerializer.SerializeArrayDouble((double[]) graph, serializationStream);
                break;
              case "System.Int16":
                this.SerializedItemsList.Add(graph);
                ArraySerializer.SerializeArrayShort((short[]) graph, serializationStream);
                break;
              case "System.Int32":
                this.SerializedItemsList.Add(graph);
                ArraySerializer.SerializeArrayInteger((int[]) graph, serializationStream);
                break;
              case "System.Int64":
                this.SerializedItemsList.Add(graph);
                ArraySerializer.SerializeArrayLong((long[]) graph, serializationStream);
                break;
              case "System.SByte":
                this.SerializedItemsList.Add(graph);
                ArraySerializer.SerializeArraySByte((sbyte[]) graph, serializationStream);
                break;
              case "System.UInt16":
                this.SerializedItemsList.Add(graph);
                ArraySerializer.SerializeArrayUInt16((ushort[]) graph, serializationStream);
                break;
              case "System.UInt32":
                this.SerializedItemsList.Add(graph);
                ArraySerializer.SerializeArrayUInt32((uint[]) graph, serializationStream);
                break;
              case "System.UInt64":
                this.SerializedItemsList.Add(graph);
                ArraySerializer.SerializeArrayUInt64((ulong[]) graph, serializationStream);
                break;
              case "System.String":
                this.SerializedItemsList.Add(graph);
                ArraySerializer.SerializeArrayString((string[]) graph, serializationStream);
                break;
              case "System.DateTime":
                this.SerializedItemsList.Add(graph);
                ArraySerializer.SerializeArrayDateTime((DateTime[]) graph, serializationStream);
                break;
              default:
                this.SerializedItemsList.Add(graph);
                this.SerializeArrayObjects((Array) graph, serializationStream);
                break;
            }
          }
          else if (type.IsEnum)
          {
            if (typeCode == TypeCode.Int32)
              this.SerializeEnum(graph, serializationStream);
            else
              this.SerializeUintEnum(graph, serializationStream);
          }
          else if ((object) (graph as Type) != null)
          {
            int num2 = this.SerializedTypesList.IndexOf(graph);
            if (num2 == -1)
              num2 = this.WriteTypeMetadata(serializationStream, (Type) graph);
            serializationStream.WriteByte((byte) 40);
            this.innerSerialize(serializationStream, (object) num2);
          }
          else if (!CompactFormatter.isSpecialType(type))
          {
            this.SerializedItemsList.Add(graph);
            this.SerializeObject(serializationStream, graph);
          }
          else
          {
            IOverrider overrider = (IOverrider) this.OverriderTable[(object) type];
            if (overrider != null)
            {
              int num2 = this.SerializedTypesList.IndexOf((object) graph.GetType());
              if (num2 == -1)
                num2 = this.WriteTypeMetadata(serializationStream, graph.GetType());
              serializationStream.WriteByte((byte) 32);
              this.innerSerialize(serializationStream, (object) num2);
              this.SerializedItemsList.Add(graph);
              overrider.Serialize(this, serializationStream, graph);
            }
            else if ((object) (MethodInfo) this.SurrogateTable[(object) type] != null)
            {
              this.SerializedItemsList.Add(graph);
              this.SerializeObject(serializationStream, graph);
            }
            else if ((this.mode & CFormatterMode.SURROGATE) != CFormatterMode.NONE && type.IsPublic)
            {
              if (!this.SerializeSpecialType(this, serializationStream, graph))
                throw new SerializationException("Unable to serialize " + (object) type + " type, it's not marked with Serializable attribute and no surrogate or overriders are registered for it");
            }
            else
            {
              this.SerializedItemsList.Add(graph);
              this.SerializeObject(serializationStream, graph);
            }
          }
        }
      }
    }

    public object innerDeserialize(Stream serializationStream)
    {
      switch (serializationStream.ReadByte())
      {
        case 0:
          return (object) null;
        case 1:
          return (object) PrimitiveSerializer.DeserializeBoolean(serializationStream);
        case 2:
          return (object) PrimitiveSerializer.DeserializeByte(serializationStream);
        case 3:
          return (object) PrimitiveSerializer.DeserializeChar(serializationStream);
        case 4:
          return (object) PrimitiveSerializer.DeserializeDecimal(serializationStream);
        case 5:
          return (object) PrimitiveSerializer.DeserializeSingle(serializationStream);
        case 6:
          return (object) PrimitiveSerializer.DeserializeDouble(serializationStream);
        case 7:
          return (object) PrimitiveSerializer.DeserializeInt16(serializationStream);
        case 8:
          return (object) PrimitiveSerializer.DeserializeInt32(serializationStream);
        case 9:
          return (object) PrimitiveSerializer.DeserializeInt64(serializationStream);
        case 10:
          return (object) PrimitiveSerializer.DeserializeSByte(serializationStream);
        case 11:
          return (object) PrimitiveSerializer.DeserializeUInt16(serializationStream);
        case 12:
          return (object) PrimitiveSerializer.DeserializeUInt32(serializationStream);
        case 13:
          return (object) PrimitiveSerializer.DeserializeUInt64(serializationStream);
        case 14:
          return (object) PrimitiveSerializer.DeserializeDateTime(serializationStream);
        case 15:
          return (object) PrimitiveSerializer.DeserializeString(serializationStream);
        case 16:
          int i1 = this.SerializedItemsList.AddPlaceholder();
          object o1 = (object) ArraySerializer.DeserializeArrayBoolean(serializationStream);
          this.SerializedItemsList.AddAtPlace(i1, o1);
          return o1;
        case 17:
          int i2 = this.SerializedItemsList.AddPlaceholder();
          object o2 = (object) ArraySerializer.DeserializeArrayByte(serializationStream);
          this.SerializedItemsList.AddAtPlace(i2, o2);
          return o2;
        case 18:
          int i3 = this.SerializedItemsList.AddPlaceholder();
          object o3 = (object) ArraySerializer.DeserializeArrayChar(serializationStream);
          this.SerializedItemsList.AddAtPlace(i3, o3);
          return o3;
        case 19:
          int i4 = this.SerializedItemsList.AddPlaceholder();
          object o4 = (object) ArraySerializer.DeserializeArrayDecimal(serializationStream);
          this.SerializedItemsList.AddAtPlace(i4, o4);
          return o4;
        case 20:
          int i5 = this.SerializedItemsList.AddPlaceholder();
          object o5 = (object) ArraySerializer.DeserializeArraySingle(serializationStream);
          this.SerializedItemsList.AddAtPlace(i5, o5);
          return o5;
        case 21:
          int i6 = this.SerializedItemsList.AddPlaceholder();
          object o6 = (object) ArraySerializer.DeserializeArrayDouble(serializationStream);
          this.SerializedItemsList.AddAtPlace(i6, o6);
          return o6;
        case 22:
          int i7 = this.SerializedItemsList.AddPlaceholder();
          object o7 = (object) ArraySerializer.DeserializeArrayShort(serializationStream);
          this.SerializedItemsList.AddAtPlace(i7, o7);
          return o7;
        case 23:
          int i8 = this.SerializedItemsList.AddPlaceholder();
          object o8 = (object) ArraySerializer.DeserializeArrayInteger(serializationStream);
          this.SerializedItemsList.AddAtPlace(i8, o8);
          return o8;
        case 24:
          int i9 = this.SerializedItemsList.AddPlaceholder();
          object o9 = (object) ArraySerializer.DeserializeArrayLong(serializationStream);
          this.SerializedItemsList.AddAtPlace(i9, o9);
          return o9;
        case 25:
          int i10 = this.SerializedItemsList.AddPlaceholder();
          object o10 = (object) ArraySerializer.DeserializeArraySByte(serializationStream);
          this.SerializedItemsList.AddAtPlace(i10, o10);
          return o10;
        case 26:
          int i11 = this.SerializedItemsList.AddPlaceholder();
          object o11 = (object) ArraySerializer.DeserializeArrayUInt16(serializationStream);
          this.SerializedItemsList.AddAtPlace(i11, o11);
          return o11;
        case 27:
          int i12 = this.SerializedItemsList.AddPlaceholder();
          object o12 = (object) ArraySerializer.DeserializeArrayUInt32(serializationStream);
          this.SerializedItemsList.AddAtPlace(i12, o12);
          return o12;
        case 28:
          int i13 = this.SerializedItemsList.AddPlaceholder();
          object o13 = (object) ArraySerializer.DeserializeArrayUInt64(serializationStream);
          this.SerializedItemsList.AddAtPlace(i13, o13);
          return o13;
        case 29:
          int i14 = this.SerializedItemsList.AddPlaceholder();
          object o14 = (object) ArraySerializer.DeserializeArrayDateTime(serializationStream);
          this.SerializedItemsList.AddAtPlace(i14, o14);
          return o14;
        case 30:
          int i15 = this.SerializedItemsList.AddPlaceholder();
          object o15 = (object) ArraySerializer.DeserializeArrayString(serializationStream);
          this.SerializedItemsList.AddAtPlace(i15, o15);
          return o15;
        case 31:
          int i16 = this.SerializedItemsList.AddPlaceholder();
          object o16 = (object) this.DeserializeArrayObject(serializationStream);
          this.SerializedItemsList.AddAtPlace(i16, o16);
          return o16;
        case 32:
          return this.DeserializeObject(serializationStream);
        case 33:
          return (object) this.DeserializeCustom(serializationStream);
        case 36:
          this.ReadAssemblyMetadata(serializationStream);
          return this.innerDeserialize(serializationStream);
        case 37:
          this.ReadTypeMetadata(serializationStream);
          return this.innerDeserialize(serializationStream);
        case 38:
          return this.SerializedItemsList.Get((int) this.innerDeserialize(serializationStream));
        case 39:
          return this.DeserializeEnum(serializationStream);
        case 40:
          return (object) (Type) this.SerializedTypesList.Get((int) this.innerDeserialize(serializationStream));
        default:
          return (object) null;
      }
    }

    public void Serialize(Stream serializationStream, object graph)
    {
      serializationStream.WriteByte((byte) this.localVersion);
      serializationStream.WriteByte((byte) this.mode);
      Stream serializationStream1 = serializationStream;
      this.innerSerialize(serializationStream1, graph);
      serializationStream1.Flush();
    }

    public object Deserialize(Stream serializationStream)
    {
      this.remoteVersion = (FrameworkVersion) serializationStream.ReadByte();
      this.remoteMode = (CFormatterMode) serializationStream.ReadByte();
      return this.innerDeserialize(serializationStream);
    }

    public void AddOverrider(Type overrider)
    {
      if (overrider.GetCustomAttributes(typeof (OverriderAttribute), false).Length == 0)
        throw new RegisterOverriderException(overrider);
      this.OverriderTable.Add((object) ((OverriderAttribute) overrider.GetCustomAttributes(typeof (OverriderAttribute), false)[0]).CustomSerializer, Activator.CreateInstance(overrider));
    }

    public void AddSurrogate(Type surrogate)
    {
      foreach (MethodInfo method in surrogate.GetMethods())
      {
        if (method.GetCustomAttributes(typeof (SurrogateAttribute), false).Length != 0)
        {
          foreach (SurrogateAttribute customAttribute in method.GetCustomAttributes(typeof (SurrogateAttribute), false))
            this.SurrogateTable.Add((object) customAttribute.SurrogateOf, (object) method);
        }
      }
    }

    internal int WriteTypeMetadata(Stream stream, Type type)
    {
      int num = this.AssemblyList.IndexOf((object) type.Assembly);
      if (num == -1)
        num = this.WriteAssemblyMetadata(stream, type.Assembly);
      stream.WriteByte((byte) 37);
      this.innerSerialize(stream, (object) num);
      string s = TypeExtensions.FullName(type);
      byte[] buffer = new byte[s.Length * 2 + 4];
      Buffer.BlockCopy((Array) BitConverter.GetBytes(s.Length * 2), 0, (Array) buffer, 0, 4);
      Buffer.BlockCopy((Array) Encoding.Unicode.GetBytes(s), 0, (Array) buffer, 4, s.Length * 2);
      stream.Write(buffer, 0, buffer.Length);
      return this.SerializedTypesList.Add((object) type);
    }

    public void ReadTypeMetadata(Stream serializationStream)
    {
      int index = (int) this.innerDeserialize(serializationStream);
      byte[] buffer = new byte[4];
      serializationStream.Read(buffer, 0, 4);
      int int32 = BitConverter.ToInt32(buffer, 0);
      byte[] numArray = new byte[int32];
      serializationStream.Read(numArray, 0, int32);
      string name = Encoding.Unicode.GetString(numArray, 0, numArray.Length);
      try
      {
        this.SerializedTypesList.Add((object) ((Assembly) this.AssemblyList[index]).GetType(name));
      }
      catch (System.Exception ex)
      {
        throw new TypeSerializationException("Unable to load type " + name);
      }
    }

    public void ReadAssemblyMetadata(Stream serializationStream)
    {
      byte[] buffer = new byte[4];
      serializationStream.Read(buffer, 0, 4);
      int int32 = BitConverter.ToInt32(buffer, 0);
      byte[] numArray = new byte[int32];
      serializationStream.Read(numArray, 0, int32);
      string assemblyString = Encoding.Unicode.GetString(numArray, 0, numArray.Length);
      try
      {
        if ((this.Mode & CFormatterMode.EXACTASSEMBLY) != CFormatterMode.NONE)
        {
          this.AssemblyList.Add((object) Assembly.Load(assemblyString));
        }
        else
        {
          string str = assemblyString;
          int length = str.IndexOf(",");
          if (length != -1)
            str = str.Substring(0, length);
          if (str.Equals("System"))
            ;
          this.AssemblyList.Add((object) Assembly.Load(assemblyString));
        }
      }
      catch (FileNotFoundException ex)
      {
        throw new AssemblySerializationException("Unable to load assembly " + assemblyString + " file not found!");
      }
    }

    public int WriteAssemblyMetadata(Stream stream, Assembly assembly)
    {
      if (this.AssemblyList.Contains((object) assembly))
        throw new AssertionException("Assembly already contained in AssemblyList, item was already sent!");
      string fullName = assembly.FullName;
      int num = this.AssemblyList.Add((object) assembly);
      stream.WriteByte((byte) 36);
      byte[] buffer = new byte[fullName.Length * 2 + 4];
      Buffer.BlockCopy((Array) BitConverter.GetBytes(fullName.Length * 2), 0, (Array) buffer, 0, 4);
      Buffer.BlockCopy((Array) Encoding.Unicode.GetBytes(fullName), 0, (Array) buffer, 4, fullName.Length * 2);
      stream.Write(buffer, 0, buffer.Length);
      return num;
    }

    internal void SerializeCustom(ICSerializable payload, Stream stream)
    {
      int num = this.SerializedTypesList.IndexOf((object) payload.GetType());
      if (num == -1)
        num = this.WriteTypeMetadata(stream, payload.GetType());
      stream.WriteByte((byte) 33);
      this.innerSerialize(stream, (object) num);
      payload.SendObjectData(this, stream);
    }

    internal ICSerializable DeserializeCustom(Stream stream)
    {
      ICSerializable objectInstance = (ICSerializable) CompactFormatter.CreateObjectInstance((Type) this.SerializedTypesList.Get((int) this.innerDeserialize(stream)));
      this.SerializedItemsList.Add((object) objectInstance);
      objectInstance.ReceiveObjectData(this, stream);
      return objectInstance;
    }

    internal object DeserializeObject(Stream stream)
    {
      Type type = (Type) this.SerializedTypesList.Get((int) this.innerDeserialize(stream));
      if (!CompactFormatter.isSpecialType(type))
      {
        object objectInstance = CompactFormatter.CreateObjectInstance(type);
        this.SerializedItemsList.Add(objectInstance);
        return this.populateObject(stream, objectInstance);
      }
      IOverrider overrider = (IOverrider) this.OverriderTable[(object) type];
      if (overrider != null)
      {
        int i = this.SerializedItemsList.AddPlaceholder();
        object o = overrider.Deserialize(this, stream);
        this.SerializedItemsList.AddAtPlace(i, o);
        return o;
      }
      MethodInfo methodInfo = (MethodInfo) this.SurrogateTable[(object) type];
      if ((object) methodInfo != null)
      {
        object[] parameters = new object[1]{ (object) type };
        object obj = methodInfo.Invoke((object) null, parameters);
        this.SerializedItemsList.Add(obj);
        return this.populateObject(stream, obj);
      }
      if ((this.mode & CFormatterMode.SURROGATE) == CFormatterMode.NONE || !type.IsPublic)
      {
        object objectInstance = CompactFormatter.CreateObjectInstance(type);
        return this.populateObject(stream, objectInstance);
      }
      object obj1 = this.DeserializeSpecialType(stream, type);
      if (obj1 != null)
        return obj1;
      throw new SerializationException("Unable to deserialize " + type.Name + " instances: it lacks Serializable attribute, overrider or surrogate. Try running CFormatter in UNSAFE mode");
    }

    internal void SerializeObject(Stream stream, object obj)
    {
      long tickCount1 = (long) Environment.TickCount;
      bool isPrimitive = obj.GetType().IsPrimitive;
      if (!isPrimitive)
        this.OnSerializing(obj);
      long tickCount2 = (long) Environment.TickCount;
      CompactFormatter.nOnsTime += tickCount2 - tickCount1;
      int num = this.SerializedTypesList.IndexOf((object) obj.GetType());
      if (num == -1)
        num = this.WriteTypeMetadata(stream, obj.GetType());
      stream.WriteByte((byte) 32);
      this.innerSerialize(stream, (object) num);
      long tickCount3 = (long) Environment.TickCount;
      Hashtable hashtable = ClassInspector.InspectClass(obj.GetType());
      long tickCount4 = (long) Environment.TickCount;
      CompactFormatter.nInspectTime += tickCount4 - tickCount3;
      IEnumerator enumerator = hashtable.Keys.GetEnumerator();
      int count = hashtable.Count;
      this.innerSerialize(stream, (object) count);
      while (enumerator.MoveNext())
      {
        string current = (string) enumerator.Current;
        FieldInfo fieldInfo = (FieldInfo) hashtable[(object) current];
        this.innerSerialize(stream, (object) fieldInfo.Name);
        this.innerSerialize(stream, fieldInfo.GetValue(obj));
      }
      long tickCount5 = (long) Environment.TickCount;
      if (!isPrimitive)
        this.OnSerialized(obj);
      long tickCount6 = (long) Environment.TickCount;
      CompactFormatter.nOnsTime += tickCount6 - tickCount5;
    }

    protected virtual void OnSerializing(object o)
    {
    }

    protected virtual void OnSerialized(object o)
    {
    }

    protected virtual void OnDeserializing(object o)
    {
    }

    protected virtual void OnDeserialized(object o)
    {
    }

    private object populateObject(Stream stream, object graph)
    {
      this.OnDeserializing(graph);
      Hashtable hashtable = ClassInspector.InspectClass(graph.GetType());
      int num = (int) this.innerDeserialize(stream);
      for (int index = 0; index < num; ++index)
      {
        string str = (string) this.innerDeserialize(stream);
        object obj = this.innerDeserialize(stream);
        if (hashtable.ContainsKey((object) str))
          ((FieldInfo) hashtable[(object) str]).SetValue(graph, obj);
      }
      this.OnDeserialized(graph);
      return graph;
    }

    private object DeserializeEnum(Stream stream)
    {
      Type enumType = (Type) this.SerializedTypesList.Get((int) this.innerDeserialize(stream));
      byte[] buffer = new byte[4];
      stream.Read(buffer, 0, 4);
      long int32 = (long) BitConverter.ToInt32(buffer, 0);
      return System.Enum.ToObject(enumType, (object) int32);
    }

    private void SerializeEnum(object value, Stream stream)
    {
      int num = this.SerializedTypesList.IndexOf((object) value.GetType());
      if (num == -1)
        num = this.WriteTypeMetadata(stream, value.GetType());
      stream.WriteByte((byte) 39);
      this.innerSerialize(stream, (object) num);
      byte[] buffer = new byte[4];
      Buffer.BlockCopy((Array) BitConverter.GetBytes((int) value), 0, (Array) buffer, 0, 4);
      stream.Write(buffer, 0, 4);
    }

    private void SerializeUintEnum(object value, Stream stream)
    {
      int num = this.SerializedTypesList.IndexOf((object) value.GetType());
      if (num == -1)
        num = this.WriteTypeMetadata(stream, value.GetType());
      stream.WriteByte((byte) 39);
      this.innerSerialize(stream, (object) num);
      byte[] buffer = new byte[4];
      Buffer.BlockCopy((Array) BitConverter.GetBytes((uint) value), 0, (Array) buffer, 0, 4);
      stream.Write(buffer, 0, 4);
    }

    private void SerializeArrayObjects(Array array, Stream serializationStream)
    {
      int num = this.SerializedTypesList.IndexOf((object) array.GetType().GetElementType());
      if (num == -1)
        num = this.WriteTypeMetadata(serializationStream, array.GetType().GetElementType());
      serializationStream.WriteByte((byte) 31);
      this.innerSerialize(serializationStream, (object) num);
      int length1 = array.Length;
      byte[] buffer = new byte[4];
      Buffer.BlockCopy((Array) BitConverter.GetBytes(length1), 0, (Array) buffer, 0, 4);
      serializationStream.Write(buffer, 0, 4);
      int length2 = array.Length;
      for (int index = 0; index < length2; ++index)
        this.innerSerialize(serializationStream, array.GetValue(index));
    }

    private Array DeserializeArrayObject(Stream serializationStream)
    {
      Type elementType = (Type) this.SerializedTypesList.Get((int) this.innerDeserialize(serializationStream));
      byte[] buffer = new byte[4];
      serializationStream.Read(buffer, 0, 4);
      int int32 = BitConverter.ToInt32(buffer, 0);
      Array instance = Array.CreateInstance(elementType, int32);
      for (int index = 0; index < int32; ++index)
        instance.SetValue(this.innerDeserialize(serializationStream), index);
      return instance;
    }

    public static Type GetType(string name)
    {
      return Assembly.GetExecutingAssembly().GetType(name);
    }

    private bool SerializeSpecialType(
      CompactFormatter parent,
      Stream serializationStream,
      object graph)
    {
      Type type1 = graph.GetType();
      string str = TypeExtensions.FullName(type1);
      bool flag1 = false;
      bool flag2 = false;
      bool flag3 = false;
      if (str.IndexOf("System.Collections.Generic.List") == 0)
      {
        flag1 = true;
      }
      else
      {
        int num1;
        if ((num1 = str.IndexOf("System.Collections.Generic.Stack")) == 0)
        {
          flag2 = true;
        }
        else
        {
          if ((num1 = str.IndexOf("System.Globalization.CultureInfo")) == 0)
          {
            int num2 = this.SerializedTypesList.IndexOf((object) type1);
            if (num2 == -1)
              num2 = this.WriteTypeMetadata(serializationStream, type1);
            serializationStream.WriteByte((byte) 32);
            CultureInfo cultureInfo = (CultureInfo) graph;
            this.innerSerialize(serializationStream, (object) num2);
            this.SerializedItemsList.Add(graph);
            this.innerSerialize(serializationStream, (object) cultureInfo.LCID);
            return true;
          }
          if ((num1 = str.IndexOf("System.Globalization.CompareInfo")) == 0)
          {
            int num2 = this.SerializedTypesList.IndexOf((object) type1);
            if (num2 == -1)
              num2 = this.WriteTypeMetadata(serializationStream, type1);
            serializationStream.WriteByte((byte) 32);
            CompareInfo compareInfo = (CompareInfo) graph;
            this.innerSerialize(serializationStream, (object) num2);
            this.SerializedItemsList.Add(graph);
            this.innerSerialize(serializationStream, (object) compareInfo.LCID);
            return true;
          }
          if ((num1 = str.IndexOf("System.Collections.Generic.Dictionary")) == 0)
          {
            int num2 = this.SerializedTypesList.IndexOf((object) type1);
            if (num2 == -1)
              num2 = this.WriteTypeMetadata(serializationStream, type1);
            serializationStream.WriteByte((byte) 32);
            this.innerSerialize(serializationStream, (object) num2);
            this.SerializedItemsList.Add(graph);
            this.SerializeDictionary(graph, serializationStream);
            return true;
          }
          if ((num1 = str.IndexOf("System.Collections.ObjectModel.ReadOnlyCollection")) == 0)
            flag3 = true;
        }
      }
      if (!flag1 && !flag2 && !flag3)
        return false;
      PayloadType payloadType = PayloadType.OBJECT;
      int num3 = this.SerializedTypesList.IndexOf((object) type1);
      if (num3 == -1)
        num3 = this.WriteTypeMetadata(serializationStream, type1);
      serializationStream.WriteByte((byte) 32);
      this.innerSerialize(serializationStream, (object) num3);
      this.SerializedItemsList.Add(graph);
      if (payloadType == PayloadType.OBJECT)
      {
        Type type2 = type1;
        int num1 = (int) type2.GetProperty("Count").GetValue(graph, CompactFormatter.ZERO_PARAM);
        PrimitiveSerializer.Serialize(num1, serializationStream);
        if (flag1 || flag3)
        {
          if (num1 > 0)
          {
            IEnumerator enumerator = (IEnumerator) type2.GetMethod("GetEnumerator").Invoke(graph, CompactFormatter.ZERO_PARAM);
            while (enumerator.MoveNext())
              this.innerSerialize(serializationStream, enumerator.Current);
          }
        }
        else if (flag2)
        {
          IEnumerator enumerator = (IEnumerator) type2.GetMethod("GetEnumerator").Invoke(graph, CompactFormatter.ZERO_PARAM);
          ArrayList arrayList = new ArrayList();
          while (enumerator.MoveNext())
            arrayList.Add(enumerator.Current);
          for (int index = arrayList.Count - 1; index >= 0; --index)
            this.innerSerialize(serializationStream, arrayList[index]);
        }
      }
      return true;
    }

    private object DeserializeSpecialType(Stream serializationStream, Type t)
    {
      string str1 = TypeExtensions.FullName(t);
      object o = (object) null;
      bool flag1 = false;
      bool flag2 = false;
      bool flag3 = false;
      if (str1.IndexOf("System.Collections.Generic.List") == 0)
        flag1 = true;
      else if (str1.IndexOf("System.Collections.Generic.Stack") == 0)
      {
        flag2 = true;
      }
      else
      {
        if (str1.IndexOf("System.Globalization.CultureInfo") == 0)
        {
          int i = this.SerializedItemsList.AddPlaceholder();
          CultureInfo cultureInfo = new CultureInfo((int) this.innerDeserialize(serializationStream));
          this.SerializedItemsList.AddAtPlace(i, (object) cultureInfo);
          return (object) cultureInfo;
        }
        if (str1.IndexOf("System.Globalization.CompareInfo") == 0)
        {
          int i = this.SerializedItemsList.AddPlaceholder();
          CompareInfo compareInfo = CompareInfo.GetCompareInfo((int) this.innerDeserialize(serializationStream));
          this.SerializedItemsList.AddAtPlace(i, (object) compareInfo);
          return (object) compareInfo;
        }
        if (str1.IndexOf("System.Collections.Generic.Dictionary") == 0)
          return this.DeserializeDictionary(serializationStream, t);
        if (str1.IndexOf("System.Collections.ObjectModel.ReadOnlyCollection") == 0)
          flag3 = true;
      }
      if (!flag1 && !flag2 && !flag3)
        return (object) null;
      int num1 = str1.IndexOf("[[");
      if (num1 == -1)
        throw new System.Exception("cannot parse de-serialized type [[");
      string str2 = str1.Substring(num1 + 2);
      int length1 = str2.IndexOf(",");
      if (length1 == -1)
        throw new System.Exception("cannot parse de-serialized type ,");
      string str3 = str2.Substring(0, length1);
      PayloadType payloadType = !str3.Equals("System.String") ? (!str3.Equals("System.Int32") ? PayloadType.OBJECT : PayloadType.INT32) : PayloadType.STRING;
      int i1 = this.SerializedItemsList.AddPlaceholder();
      switch (payloadType)
      {
        case PayloadType.BOOLEAN:
          List<bool> boolList1 = (List<bool>) null;
          Stack<bool> boolStack = (Stack<bool>) null;
          List<bool> boolList2 = (List<bool>) null;
          if (flag1)
          {
            boolList1 = new List<bool>();
            o = (object) boolList1;
          }
          else if (flag2)
          {
            boolStack = new Stack<bool>();
            o = (object) boolStack;
          }
          else if (flag3)
          {
            boolList2 = new List<bool>();
            o = (object) new ReadOnlyCollection<bool>((IList<bool>) boolList2);
          }
          if (PrimitiveSerializer.DeserializeByte(serializationStream) != (byte) 8)
            throw new System.Exception("was expecting INT32 in stream");
          int num2 = PrimitiveSerializer.DeserializeInt32(serializationStream);
          for (int index = 0; index < num2; ++index)
          {
            if (PrimitiveSerializer.DeserializeByte(serializationStream) != (byte) 1)
              throw new System.Exception("was expecting BOOLEAN in stream");
            bool flag4 = PrimitiveSerializer.DeserializeBoolean(serializationStream);
            if (flag1)
              boolList1.Add(flag4);
            else if (flag2)
              boolStack.Push(flag4);
            else if (flag3)
              boolList2.Add(flag4);
          }
          break;
        case PayloadType.BYTE:
          List<byte> byteList1 = (List<byte>) null;
          Stack<byte> byteStack = (Stack<byte>) null;
          List<byte> byteList2 = (List<byte>) null;
          if (flag1)
          {
            byteList1 = new List<byte>();
            o = (object) byteList1;
          }
          else if (flag2)
          {
            byteStack = new Stack<byte>();
            o = (object) byteStack;
          }
          else if (flag3)
          {
            byteList2 = new List<byte>();
            o = (object) new ReadOnlyCollection<byte>((IList<byte>) byteList2);
          }
          if (PrimitiveSerializer.DeserializeByte(serializationStream) != (byte) 8)
            throw new System.Exception("was expecting INT32 in stream");
          int num3 = PrimitiveSerializer.DeserializeInt32(serializationStream);
          for (int index = 0; index < num3; ++index)
          {
            if (PrimitiveSerializer.DeserializeByte(serializationStream) != (byte) 2)
              throw new System.Exception("was expecting BYTE in stream");
            byte num4 = PrimitiveSerializer.DeserializeByte(serializationStream);
            if (flag1)
              byteList1.Add(num4);
            else if (flag2)
              byteStack.Push(num4);
            else if (flag3)
              byteList2.Add(num4);
          }
          break;
        case PayloadType.CHAR:
          List<char> charList1 = (List<char>) null;
          Stack<char> charStack = (Stack<char>) null;
          List<char> charList2 = (List<char>) null;
          if (flag1)
          {
            charList1 = new List<char>();
            o = (object) charList1;
          }
          else if (flag2)
          {
            charStack = new Stack<char>();
            o = (object) charStack;
          }
          else if (flag3)
          {
            charList2 = new List<char>();
            o = (object) new ReadOnlyCollection<char>((IList<char>) charList2);
          }
          if (PrimitiveSerializer.DeserializeByte(serializationStream) != (byte) 8)
            throw new System.Exception("was expecting INT32 in stream");
          int num5 = PrimitiveSerializer.DeserializeInt32(serializationStream);
          for (int index = 0; index < num5; ++index)
          {
            if (PrimitiveSerializer.DeserializeByte(serializationStream) != (byte) 3)
              throw new System.Exception("was expecting CHAR in stream");
            char ch = PrimitiveSerializer.DeserializeChar(serializationStream);
            if (flag1)
              charList1.Add(ch);
            else if (flag2)
              charStack.Push(ch);
            else if (flag3)
              charList2.Add(ch);
          }
          break;
        case PayloadType.SINGLE:
          List<float> floatList1 = (List<float>) null;
          Stack<float> floatStack = (Stack<float>) null;
          List<float> floatList2 = (List<float>) null;
          if (flag1)
          {
            floatList1 = new List<float>();
            o = (object) floatList1;
          }
          else if (flag2)
          {
            floatStack = new Stack<float>();
            o = (object) floatStack;
          }
          else if (flag3)
          {
            floatList2 = new List<float>();
            o = (object) new ReadOnlyCollection<float>((IList<float>) floatList2);
          }
          if (PrimitiveSerializer.DeserializeByte(serializationStream) != (byte) 8)
            throw new System.Exception("was expecting INT32 in stream");
          int num6 = PrimitiveSerializer.DeserializeInt32(serializationStream);
          for (int index = 0; index < num6; ++index)
          {
            if (PrimitiveSerializer.DeserializeByte(serializationStream) != (byte) 5)
              throw new System.Exception("was expecting SINGLE in stream");
            float num4 = PrimitiveSerializer.DeserializeSingle(serializationStream);
            if (flag1)
              floatList1.Add(num4);
            else if (flag2)
              floatStack.Push(num4);
            else if (flag3)
              floatList2.Add(num4);
          }
          break;
        case PayloadType.INT32:
          List<int> intList1 = (List<int>) null;
          Stack<int> intStack = (Stack<int>) null;
          List<int> intList2 = (List<int>) null;
          if (flag1)
          {
            intList1 = new List<int>();
            o = (object) intList1;
          }
          else if (flag2)
          {
            intStack = new Stack<int>();
            o = (object) intStack;
          }
          else if (flag3)
          {
            intList2 = new List<int>();
            o = (object) new ReadOnlyCollection<int>((IList<int>) intList2);
          }
          if (PrimitiveSerializer.DeserializeByte(serializationStream) != (byte) 8)
            throw new System.Exception("was expecting INT32 in stream");
          int num7 = PrimitiveSerializer.DeserializeInt32(serializationStream);
          for (int index = 0; index < num7; ++index)
          {
            if (PrimitiveSerializer.DeserializeByte(serializationStream) != (byte) 8)
              throw new System.Exception("was expecting INT32 in stream");
            int num4 = PrimitiveSerializer.DeserializeInt32(serializationStream);
            if (flag1)
              intList1.Add(num4);
            else if (flag2)
              intStack.Push(num4);
            else if (flag3)
              intList2.Add(num4);
          }
          break;
        case PayloadType.STRING:
          List<string> stringList1 = (List<string>) null;
          Stack<string> stringStack = (Stack<string>) null;
          List<string> stringList2 = (List<string>) null;
          if (flag1)
          {
            stringList1 = new List<string>();
            o = (object) stringList1;
          }
          else if (flag2)
          {
            stringStack = new Stack<string>();
            o = (object) stringStack;
          }
          else if (flag3)
          {
            stringList2 = new List<string>();
            o = (object) new ReadOnlyCollection<string>((IList<string>) stringList2);
          }
          if (PrimitiveSerializer.DeserializeByte(serializationStream) != (byte) 8)
            throw new System.Exception("was expecting INT32 in stream");
          int num8 = PrimitiveSerializer.DeserializeInt32(serializationStream);
          for (int index = 0; index < num8; ++index)
          {
            if (flag1)
            {
              string str4 = (string) this.innerDeserialize(serializationStream);
              stringList1.Add(str4);
            }
            else if (flag2)
            {
              string str4 = (string) this.innerDeserialize(serializationStream);
              stringStack.Push(str4);
            }
            else if (flag3)
            {
              string str4 = (string) this.innerDeserialize(serializationStream);
              stringList2.Add(str4);
            }
          }
          break;
        case PayloadType.OBJECT:
          object obj1;
          if (flag3)
          {
            ConstructorInfo constructor = t.GetConstructors()[0];
            Type parameterType = constructor.GetParameters()[0].ParameterType;
            string str4 = TypeExtensions.FullName(parameterType);
            int length2 = str4.IndexOf("IList");
            string name = str4.Substring(0, length2) + str4.Substring(length2 + 1);
            Type type = parameterType.Assembly.GetType(name);
            obj1 = Activator.CreateInstance(type);
            t = type;
            o = constructor.Invoke(new object[1]{ obj1 });
          }
          else
          {
            obj1 = CompactFormatter.CreateObjectInstance(t);
            o = obj1;
          }
          if (PrimitiveSerializer.DeserializeByte(serializationStream) != (byte) 8)
            throw new System.Exception("was expecting INT32 in stream");
          int num9 = PrimitiveSerializer.DeserializeInt32(serializationStream);
          MethodInfo methodInfo = flag1 || flag3 ? t.GetMethod("Add") : t.GetMethod("Push");
          for (int index = 0; index < num9; ++index)
          {
            object obj2 = this.innerDeserialize(serializationStream);
            methodInfo.Invoke(obj1, new object[1]{ obj2 });
          }
          break;
      }
      this.SerializedItemsList.AddAtPlace(i1, o);
      return o;
    }

    public static object CreateObjectInstance(Type theType)
    {
      long tickCount1 = (long) Environment.TickCount;
      ConstructorInfo constructor = theType.GetConstructor(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic, (Binder) null, CompactFormatter.tp, CompactFormatter.pm);
      object obj = (object) constructor == null ? Activator.CreateInstance(theType) : constructor.Invoke(CompactFormatter.ZERO_PARAM);
      long tickCount2 = (long) Environment.TickCount;
      CompactFormatter.nCreationTime += tickCount2 - tickCount1;
      return obj;
    }

    private static bool isSpecialType(Type t)
    {
      long tickCount1 = (long) Environment.TickCount;
      lock (CompactFormatter.lockObj)
      {
        long tickCount2 = (long) Environment.TickCount;
        CompactFormatter.nBadBlock += tickCount2 - tickCount1;
        if (CompactFormatter.SpecialTypeList.ContainsKey((object) t))
          return true;
        string str = TypeExtensions.FullName(t);
        if (str.StartsWith("System.Collections."))
        {
          if (!str.StartsWith("System.Collections.Generic.List") && !str.StartsWith("System.Collections.Generic.Dictionary") && !str.StartsWith("System.Collections.ObjectModel.ReadOnlyCollection"))
          {
            if (!str.StartsWith("System.Collections.Generic.Stack"))
              goto label_8;
          }
          CompactFormatter.SpecialTypeList.Add((object) t, (object) null);
          return true;
        }
      }
label_8:
      return false;
    }

    private void SerializeDictionary(object graph, Stream serializationStream)
    {
      Type type = graph.GetType();
      int num = (int) type.GetProperty("Count").GetValue(graph, CompactFormatter.ZERO_PARAM);
      this.innerSerialize(serializationStream, (object) num);
      if (num == 0)
        return;
      object obj1 = type.GetProperty("Keys").GetValue(graph, CompactFormatter.ZERO_PARAM);
      IEnumerator enumerator1 = (IEnumerator) obj1.GetType().GetMethod("GetEnumerator").Invoke(obj1, CompactFormatter.ZERO_PARAM);
      object obj2 = type.GetProperty("Values").GetValue(graph, CompactFormatter.ZERO_PARAM);
      IEnumerator enumerator2 = (IEnumerator) obj2.GetType().GetMethod("GetEnumerator").Invoke(obj2, CompactFormatter.ZERO_PARAM);
      while (enumerator1.MoveNext() && enumerator2.MoveNext())
      {
        object current1 = enumerator1.Current;
        object current2 = enumerator2.Current;
        this.innerSerialize(serializationStream, current1);
        this.innerSerialize(serializationStream, current2);
      }
    }

    private object DeserializeDictionary(Stream serializationStream, Type t)
    {
      int i = this.SerializedItemsList.AddPlaceholder();
      object objectInstance = CompactFormatter.CreateObjectInstance(t);
      int num = (int) this.innerDeserialize(serializationStream);
      MethodInfo method = t.GetMethod("Add");
      for (int index = 0; index < num; ++index)
      {
        object obj1 = this.innerDeserialize(serializationStream);
        object obj2 = this.innerDeserialize(serializationStream);
        method.Invoke(objectInstance, new object[2]
        {
          obj1,
          obj2
        });
      }
      this.SerializedItemsList.AddAtPlace(i, objectInstance);
      return objectInstance;
    }
  }
}
