#region LGPL_License
/* CompactFormatter: A generic formatter for the .NET Compact Framework
 * Copyright (C) 2003 Angelo S. Scotto (scotto_a@hotmail.com) Politecnico di Milano
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 * 
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA  02111-1307, USA.
 * */
#endregion

#define	OBJTABLE
using System;
using System.IO;
using System.Reflection;
using System.Collections;
using System.Security.Permissions;
using System.Diagnostics;
using System.Data;

/* Compact Formatter: A	generic	binary formatter working on	Compact	Framework */

namespace Serialization.Formatters
{
	///	<summary>
	///	CompactFormatter is	the	Formatter main class: It contains all methods used to
	///	serialize and deserialize objects using	CompactFormatter
	///	</summary>
	public class CompactFormatter
	{

#if	DEBUG
	///	<summary>
	///	An enum	enumerating	all	levels available for debug messages.
	///	</summary>
	internal enum DebugLevel {NONE,ERROR,INFO,VERBOSE}
	///	<summary>
	///	The	debug level	selected for this instance.
	///	</summary>
	internal static	DebugLevel level=DebugLevel.VERBOSE;
#endif
		///	<summary>
		///	Delimiter is simply	a flag which can assume	two	values OBJECT or RESET
		///	It is sent through the Wire	by the Formatter as	preamble for any serialization.
		///	</summary>
		enum Delimiter {OBJECT,RESET};

		enum ObjType
		{
			NULL,OBJECT,ALREADYWROTE,BOOL,BYTE,CHAR,DOUBLE,SHORT,INT,
			LONG,SBYTE,FLOAT,STRING,USHORT,UINT,ULONG,A4BOOL,A4BYTE,A4CHAR,
			A4DOUBLE,A4SHORT,A4INT,A4LONG,A4SBYTE,A4FLOAT,A4STRING,
			A4USHORT,A4UINT,A4ULONG,A4OBJECT,A4FOBJECT,FOBJECT,CUSTOM,FCUSTOM,FTYPE,TYPE,DBNULL
		};

		///	<summary>
		///	It's the same of NameGenerator(ref bool	f,Type t).
		///	The	only difference	is that	this takes the object and extracts the type
		///	from it	automatically.
		///	</summary>
		///	<param name="f">a flag,	if the object name was shrinked	it is true,
		///	false otherwise</param>
		///	<param name="obj">the Type from	which the name must	be extracted</param>
		///	<returns>A string representing the Type	FullName in	CompactFormatter standard
		///	</returns>
		string NameGenerator(ref bool f,object obj)
		{
			Type t=obj.GetType();
			return NameGenerator(ref f,t);
		}

		///	<summary>
		///	NameGenerator takes	a Type and returns its name	according to the
		///	CompactFormatter standard.
		///	To save	space on the Wire in fact, CompactFormatter	send the type FullName
		///	only when necessary, avoiding to insert	redundancy in the name.
		///	i.e. if	the	fullname of	the	type is	"Alfa.Beta,Gamma" (meaning that	we're
		///	referring to the Beta class	in the Alfa	namespace contained	in the Gamma
		///	assembly) it returns "Alfa.Beta,Gamma".
		///	But	if the fullname	is "Alfa.Beta,Alfa"	(meaning that the assembly is called
		///	as the first level of the namespace	as often happens)
		///	it returns "Alfa.Beta".
		///	</summary>
		///	<param name="f">a flag,	if the object name was shrinked	it is true,
		///	false otherwise</param>
		///	<param name="t">the	Type from which	the	name must be extracted</param>
		///	<returns>A string representing the Type	FullName in	CompactFormatter standard
		///	</returns>
		string NameGenerator(ref bool f,Type t)
		{
			string AssemblyName=t.Assembly.FullName;
			string Namespace="";
			//If is	-1 error, at least a dot must be in
			if (t.FullName.IndexOf('.')!=-1)
				Namespace=t.FullName.Substring(0,t.FullName.IndexOf('.'));
			//If is	-1 error, at least a comma must	be in
			if (AssemblyName.IndexOf(',')!=-1)
				AssemblyName=
					AssemblyName.Substring(0,AssemblyName.IndexOf(','));
			return t.FullName+","+AssemblyName;
			//return t.AssemblyQualifiedName;
		}

		///	<summary>
		///	Similar	to the NameGenerator, the only difference is that, instead of taking a
		///	bool parameter,	it takes an	ObjType	one.
		///	It is useful to	serialize Array	elements when the runtime type of the element
		///	differs	from the static	defined	type of	array elements
		///	</summary>
		///	<param name="type">At the end of the call, it will contain the correct
		///	ObjType	for	the	array element being	serialized</param>
		///	<param name="elType">is	the	type of	the	array element being	serialized</param>
		///	<returns>A string representing the Type	FullName in	CompactFormatter standard
		///	</returns>
		static string NameArrayElementGenerator(ref	ObjType	type,Type elType)
		{
			string AssemblyName=elType.Assembly.FullName;
			string Namespace="";
			return elType.FullName+","+AssemblyName;;	
			//return elType.AssemblyQualifiedName;
		}

		#region	Deserializers

		private	object Deserialize(Stream Wire,ArrayList ObjectTable)
		{
			this.ObjectTable=ObjectTable;
			return Deserialize(Wire);
		}

		public object Deserialize(Stream Wire)
		{
			Object isNull=null;
			return Deserialize(Wire,ref isNull);
		}

		///	<summary>
		///	Used to	Deserialize	an object from a stream
		///	</summary>
		///	<param name="Wire">Wire	is the stream were the object is received</param>
		///	<param name="parent">parent is the object which, at the end of the method call
		///	must contain the deserialized object, if it's null the object is newly allocated and
		///	returned.</param>
		///	<returns>the object	deserialized from Wire</returns>
		//[System.Security.Permissions.ReflectionPermission(SecurityAction.Demand)]
		private object Deserialize(Stream Wire,ref Object parent)
		{
			string ClassName;
#if	DEBUG

		WriteDebug(DebugLevel.VERBOSE,"Starting	Deserializing object...");
#endif

			if (Wire==null)
				throw new ArgumentNullException();

			object Answer=null;
			int	reset=Wire.ReadByte();//Reading	the	Reset flag
			if (reset==1)
				ObjectTable.Clear();
			if (reset==-1)
				throw new System.IO.IOException("End of	stream reached.");

			ObjType	TypeRead=(ObjType)Wire.ReadByte();//Reading	the	type
			if (TypeRead==ObjType.DBNULL)
				return System.DBNull.Value;
			if (TypeRead==ObjType.NULL)
				return null;
			else if	(TypeRead==ObjType.CUSTOM || TypeRead==ObjType.FCUSTOM)
			{
				return CustomDeserialize(TypeRead,Wire);
			}
			else if(TypeRead==ObjType.FOBJECT)
			{
				if(!firstcallR)
				{
					firstcallR=true;
					BR=new BinaryReader(Wire);
				}
				ClassName=BR.ReadString();
				if(parent!=null)
				{Answer=parent;}
				else
				{
					if (Type.GetType(ClassName).IsValueType)
						Answer=Activator.CreateInstance(Type.GetType(ClassName));
					else
					{
						ConstructorInfo	C=Type.GetType(ClassName).GetConstructor(BindingFlags.Instance |BindingFlags.NonPublic|BindingFlags.Public,null,new	Type[0],null);
						if (C==null)
							throw new SerializationException("Unable to	find no-parameters constructor!	this constructor must be implemented to	allow CompactFormatter to work");
						Answer=C.Invoke(null);
					}
				}
#if	OBJTABLE
				if(TypeRead!=ObjType.ALREADYWROTE)
					ObjectTable.Add(Answer);
#endif

				Array A=CInspector.InspectClass(Answer);

//				for(int	i=0;i<A.Length;i++)
//				{
					try
					{
						Type t=Answer.GetType();
						int j=0;

						while (t.BaseType!=null)
						{
							FieldInfo[] InnerList=(t.GetFields(BindingFlags.Public| BindingFlags.NonPublic | BindingFlags.Instance|BindingFlags.DeclaredOnly));
							for(int i=0;i<InnerList.Length;i++)
							{
								if (!InnerList[i].FieldType.IsPointer && InnerList[i].GetCustomAttributes(typeof
									(Serialization.Formatters.NotSerializable),false).Length==0)
								{
									Object Temp=InnerList[i].GetValue(Answer);
									InnerList[i].SetValue(Answer,Deserialize(Wire,ref Temp));
								}

							}
							t=t.BaseType;
					
						}
					}
					catch(Exception err)
					{
							throw new SerializationException("Error while summoning class with the Compact Inspector:"
						 + err.Message);}

					
//				}
//
//					A.SetValue(Deserialize(Wire,ObjectTable),i);
//				WriteDebug(DebugLevel.VERBOSE,"Deserializing instance of type "+ClassName);
//				CInspector.SummonClass(Answer,A);

			}

			else if	(TypeRead==ObjType.ALREADYWROTE)
			{
				if(!firstcallR)
				{
					firstcallR=true;
					BR=new BinaryReader(Wire);
				}
				int	index=BR.ReadInt32();
				Answer=ObjectTable[index];
			}
			else if	(TypeRead>ObjType.ALREADYWROTE && TypeRead<=ObjType.ULONG)
			{//It's	a primitive	type, i've to deserialize it using BinaryReader
				if(!firstcallR)
				{
					firstcallR=true;
					BR=new BinaryReader(Wire);
				}
				if(TypeRead==ObjType.BOOL)
					Answer=BR.ReadBoolean();
				else if(TypeRead==ObjType.BYTE)
					Answer=BR.ReadByte();
				else if(TypeRead==ObjType.CHAR)
					Answer=BR.ReadChar();
					//else if(TypeRead==ObjType.DECIMAL) Answer=BR.ReadDecimal();
				else if(TypeRead==ObjType.DOUBLE)
					Answer=BR.ReadDouble();
				else if(TypeRead==ObjType.FLOAT)
					Answer=BR.ReadSingle();
				else if(TypeRead==ObjType.INT)
					Answer=BR.ReadInt32();
				else if(TypeRead==ObjType.LONG)
					Answer=BR.ReadInt64();
				else if(TypeRead==ObjType.SBYTE)
					Answer=BR.ReadSByte();
				else if(TypeRead==ObjType.SHORT)
					Answer=BR.ReadInt16();
				else if(TypeRead==ObjType.STRING)
					Answer=BR.ReadString();
				else if(TypeRead==ObjType.UINT)
					Answer=BR.ReadUInt32();
				else if(TypeRead==ObjType.ULONG)
					Answer=BR.ReadUInt64();
				else if(TypeRead==ObjType.USHORT)
					Answer=BR.ReadUInt16();
				return Answer;
			}
			else if(TypeRead>ObjType.ULONG)
			{
				if (TypeRead==ObjType.A4OBJECT)
				{
					if(!firstcallR)
					{
						firstcallR=true;
						BR=new BinaryReader(Wire);
					}
					string elementName=BR.ReadString();
					string AssemblyName="";
					if (elementName.IndexOf('.')!=-1)//If -1 there's an	error
						AssemblyName=elementName.Substring(0,elementName.IndexOf('.'));
					//Object is	OBJECT,	it means that Assembly is named	as the namespace
					if (AssemblyName!="System")
						elementName=elementName+","+AssemblyName;
					int	Size=BR.ReadInt32();
					System.Array Arr=Array.CreateInstance(Type.GetType(elementName),Size);

//					ObjectTable.Add(Arr);

					object cal;
					for(int	i=0;i<Size;i++)
						try
						{
							cal=Deserialize(Wire,ObjectTable);
							if (cal!=null)
								Arr.SetValue(cal,i);
						}
						catch(Exception	err)
						{
#if	DEBUG
						WriteDebug(DebugLevel.ERROR,"exception raised: "+err);
#endif

							throw new SerializationException(err.Message);
						}
					Answer=Arr;
				}
				if (TypeRead==ObjType.A4FOBJECT)
				{
					if(!firstcallR)
					{
						firstcallR=true;
						BR=new BinaryReader(Wire);
					}
					string elementName=BR.ReadString();

					int	Size=BR.ReadInt32();
					System.Array Arr=Array.CreateInstance(Type.GetType(elementName),Size);

					//ObjectTable.Add(Arr);

					object cal;
					for(int	i=0;i<Size;i++)
						try
						{
							cal=Deserialize(Wire,ObjectTable);
							if (cal!=null)
								Arr.SetValue(cal,i);
						}
						catch(Exception	err)
						{
#if	DEBUG
						WriteDebug(DebugLevel.ERROR,"exception raised: "+err);
#endif

							throw new SerializationException(err.Message);
						}
					Answer=Arr;

				}

				if(TypeRead==ObjType.A4BOOL)
				{
					if(!firstcallR)
					{
						firstcallR=true;
						BR=new BinaryReader(Wire);
					}
					int	Size=BR.ReadInt32();
					bool[] Arr=new bool[Size];
					for(int	i=0;i<Size;i++)
						Arr[i]=BR.ReadBoolean();
					return Arr;
				}
				if(TypeRead==ObjType.A4INT)
				{
					if(!firstcallR)
					{
						firstcallR=true;
						BR=new BinaryReader(Wire);
					}
					int	Size=BR.ReadInt32();
					int[] Arr=new int[Size];
					for(int	i=0;i<Size;i++)
						Arr[i]=BR.ReadInt32();
					return Arr;
				}
				if(TypeRead==ObjType.A4BYTE)
				{
					if(!firstcallR)
					{
						firstcallR=true;
						BR=new BinaryReader(Wire);
					}
					int	Size=BR.ReadInt32();
					byte[] Arr=new byte[Size];
					for(int	i=0;i<Size;i++)
						Arr[i]=BR.ReadByte();
					return Arr;
				}
				if(TypeRead==ObjType.A4CHAR)
				{
					if(!firstcallR)
					{
						firstcallR=true;
						BR=new BinaryReader(Wire);
					}
					int	Size=BR.ReadInt32();
					char[] Arr=new char[Size];
					for(int	i=0;i<Size;i++)
						Arr[i]=BR.ReadChar();
					return Arr;
				}
				/*				if(TypeRead==ObjType.A4DECIMAL)
									{
										BinaryReader BR=new	BinaryReader(Wire);
										int	Size=BR.ReadInt32();
										//?Size=Size?;
										decimal[] Arr=new decimal[Size];
										byte[] Buffer=new byte[Size];
										Wire.Read(Buffer,0,Size);
										MemoryStream MS=new	MemoryStream(Buffer);
										BR=new BinaryReader(MS);
										for(int	i=0;i<Size;i++)
											Arr[i]=BR.ReadDecimal();
										return Arr;
									}*/
				if(TypeRead==ObjType.A4DOUBLE)
				{
					if(!firstcallR)
					{
						firstcallR=true;
						BR=new BinaryReader(Wire);
					}
					int	Size=BR.ReadInt32();
					double[] Arr=new double[Size];
					for(int	i=0;i<Size;i++)
						Arr[i]=BR.ReadDouble();
					return Arr;
				}
				if(TypeRead==ObjType.A4FLOAT)
				{
					if(!firstcallR)
					{
						firstcallR=true;
						BR=new BinaryReader(Wire);
					}
					int	Size=BR.ReadInt32();
					float[]	Arr=new	float[Size];
					for(int	i=0;i<Size;i++)
						Arr[i]=BR.ReadSingle();
					return Arr;
				}
				if(TypeRead==ObjType.A4LONG)
				{
					if(!firstcallR)
					{
						firstcallR=true;
						BR=new BinaryReader(Wire);
					}
					int	Size=BR.ReadInt32();
					long[] Arr=new long[Size];
					for(int	i=0;i<Size;i++)
						Arr[i]=BR.ReadInt64();
					return Arr;
				}
				if(TypeRead==ObjType.A4SBYTE)
				{
					if(!firstcallR)
					{
						firstcallR=true;
						BR=new BinaryReader(Wire);
					}
					int	Size=BR.ReadInt32();
					sbyte[]	Arr=new	sbyte[Size];
					for(int	i=0;i<Size;i++)
						Arr[i]=BR.ReadSByte();
					return Arr;
				}
				if(TypeRead==ObjType.A4SHORT)
				{
					if(!firstcallR)
					{
						firstcallR=true;
						BR=new BinaryReader(Wire);
					}
					int	Size=BR.ReadInt32();
					short[]	Arr=new	short[Size];
					for(int	i=0;i<Size;i++)
						Arr[i]=BR.ReadInt16();
					return Arr;
				}
				if(TypeRead==ObjType.A4STRING)
				{
					if(!firstcallR)
					{
						firstcallR=true;
						BR=new BinaryReader(Wire);
					}
					int	Size=BR.ReadInt32();
					string[] Arr=new string[Size];
					for(int	i=0;i<Size;i++)
					{
						Arr[i]=BR.ReadString();
						if (Arr[i]=="$")
							Arr[i]=null;
						else if	(new String('$',Arr[i].Length).Equals(Arr[i]))
							Arr[i]=Arr[i].Substring(1,Arr[i].Length-1);
					}
					return Arr;
				}
				if(TypeRead==ObjType.A4UINT)
				{
					if(!firstcallR)
					{
						firstcallR=true;
						BR=new BinaryReader(Wire);
					}
					int	Size=BR.ReadInt32();
					uint[] Arr=new uint[Size];
					for(int	i=0;i<Size;i++)
						Arr[i]=BR.ReadUInt32();
					return Arr;
				}
				if(TypeRead==ObjType.A4ULONG)
				{
					if(!firstcallR)
					{
						firstcallR=true;
						BR=new BinaryReader(Wire);
					}
					int	Size=BR.ReadInt32();
					ulong[]	Arr=new	ulong[Size];
					for(int	i=0;i<Size;i++)
						Arr[i]=BR.ReadUInt64();
					return Arr;
				}
				if(TypeRead==ObjType.A4USHORT)
				{
					if(!firstcallR)
					{
						firstcallR=true;
						BR=new BinaryReader(Wire);
					}
					int	Size=BR.ReadInt32();
					ushort[] Arr=new ushort[Size];
					for(int	i=0;i<Size;i++)
						Arr[i]=BR.ReadUInt16();
					return Arr;
				}
				else if	(TypeRead == ObjType.TYPE || TypeRead == ObjType.FTYPE)
				{
					if(!firstcallR)
					{
						firstcallR=true;
						BR=new BinaryReader(Wire);
					}
					ClassName=BR.ReadString();
					/*if (TypeRead==ObjType.TYPE)
					{
						string AssemblyName="";
						if (ClassName.IndexOf('.')!=-1)//If	is -1 there's an error
							AssemblyName=ClassName.Substring(0,ClassName.IndexOf('.'));
						if (AssemblyName!="System")
							ClassName=ClassName+","+AssemblyName;
					}*/
					Answer=Type.GetType(ClassName);
#if	OBJTABLE
					if(TypeRead!=ObjType.ALREADYWROTE)
						ObjectTable.Add(Answer);
#endif

				}

			}
			else if(TypeRead==ObjType.OBJECT)
			{
				if(!firstcallR)
				{
					firstcallR=true;
					BR=new BinaryReader(Wire);
				}
				ClassName=BR.ReadString();
				
				/*string AssemblyName="";
				if (ClassName.IndexOf('.')!=-1)//If	it's -1	there's	an error
					AssemblyName=ClassName.Substring(0,ClassName.IndexOf('.'));
				if (AssemblyName!="System")
					ClassName=ClassName+","+AssemblyName;*/
				if(parent!=null)
				{Answer=parent;}
				else
				{
					if (Type.GetType(ClassName).IsValueType)
						Answer=Activator.CreateInstance(Type.GetType(ClassName));
					else
					{	
						switch(Type.GetType(ClassName).FullName)
						{
							case "System.Globalization.CompareInfo":
							{
								Answer=System.Globalization.CompareInfo.GetCompareInfo(1);
								break;
							}
							case "System.Globalization.CultureInfo":
							case "System.Globalization.TextInfo":
							{
								Type[] temp={typeof(int)};
								Object[] param={1};
								Answer=typeof(System.Globalization.CultureInfo).GetConstructor(BindingFlags.Instance	|BindingFlags.NonPublic|BindingFlags.Public,null,temp,null).Invoke(param);
								if (Type.GetType(ClassName).FullName=="System.Globalization.TextInfo")
									Answer=((System.Globalization.CultureInfo)Answer).TextInfo;
								break;
							}
							default:
							{
								ConstructorInfo[] ci=Type.GetType(ClassName).GetConstructors();							
								Answer=Type.GetType(ClassName).GetConstructor(BindingFlags.Instance	|BindingFlags.NonPublic|BindingFlags.Public,null,new Type[0],null).Invoke(null);
								break;
							}
						}
					}
				}

#if	OBJTABLE
				if(TypeRead!=ObjType.ALREADYWROTE)
					ObjectTable.Add(Answer);
#endif

				Array A=CInspector.InspectClass(Answer);
				try
				{
					Type t=Answer.GetType();
					int j=0;

					while (t.BaseType!=null)
					{
						FieldInfo[] InnerList=(t.GetFields(BindingFlags.Public| BindingFlags.NonPublic | BindingFlags.Instance|BindingFlags.DeclaredOnly));
						for(int i=0;i<InnerList.Length;i++)
						{
							if (!InnerList[i].FieldType.IsPointer && InnerList[i].GetCustomAttributes(typeof
								(Serialization.Formatters.NotSerializable),false).Length==0)
							{
								Object Temp=InnerList[i].GetValue(Answer);
								InnerList[i].SetValue(Answer,Deserialize(Wire,ref Temp));
							}

						}
						t=t.BaseType;
					
					}
				}
				catch(Exception err)
				{
					throw new SerializationException("Error while summoning class with the Compact Inspector:"
						+ err.Message);}

//				for(int	i=0;i<A.Length;i++)
//					A.SetValue(Deserialize(Wire,ObjectTable),i);
//				WriteDebug(DebugLevel.VERBOSE,"Deserializing instance of type "+ClassName);
//				CInspector.SummonClass(Answer,A);
			}
			return Answer;
		}

		#endregion
		#region	Serializers

		private	void Serialize(Stream Wire,string Payload)
		{
			if(!firstcallF)
			{
				firstcallF=true;
				BF=new BinaryWriter(Wire);
				Reset();
			}
			BF.Write((byte)(ResetToken?1:0));
			ResetToken=false;
			BF.Write((byte)ObjType.STRING);
			BF.Write(Payload);
			BF.Flush();
		}

		private	void Serialize(Stream Wire,bool[] Payload)
		{
			if(!firstcallF)
			{
				firstcallF=true;
				BF=new BinaryWriter(Wire);
				Reset();
			}

			BF.Write((byte)(ResetToken?1:0));
			ResetToken=false;
			BF.Write((byte)ObjType.A4BOOL);
			int	Size=Payload.GetLength(0);
			BF.Write(Size);
			for(int	i=0;i<Size;i++)
			{
				BF.Write(Payload[i]);
			}
		}

		private	void Serialize(Stream Wire,byte[] Payload)
		{
			if(!firstcallF)
			{
				firstcallF=true;
				BF=new BinaryWriter(Wire);
				Reset();
			}

			BF.Write((byte)(ResetToken?1:0));
			ResetToken=false;
			BF.Write((byte)ObjType.A4BYTE);
			int	Size=Payload.GetLength(0);
			BF.Write(Size);
			for(int	i=0;i<Size;i++)
			{
				BF.Write(Payload[i]);
			}
		}

		private	void Serialize(Stream Wire,char[] Payload)
		{
			if(!firstcallF)
			{
				firstcallF=true;
				BF=new BinaryWriter(Wire);
				Reset();
			}

			BF.Write((byte)(ResetToken?1:0));
			ResetToken=false;
			BF.Write((byte)ObjType.A4CHAR);
			int	Size=Payload.GetLength(0);
			BF.Write(Size);
			for(int	i=0;i<Size;i++)
			{
				BF.Write(Payload[i]);
			}
		}

		private	 void Serialize(Stream Wire,double[] Payload)
		{
			if(!firstcallF)
			{
				firstcallF=true;
				BF=new BinaryWriter(Wire);
				Reset();
			}

			BF.Write((byte)(ResetToken?1:0));
			ResetToken=false;
			BF.Write((byte)ObjType.A4DOUBLE);
			int	Size=Payload.GetLength(0);
			BF.Write(Size);
			for(int	i=0;i<Size;i++)
			{
				BF.Write(Payload[i]);
			}
		}

		private	 void Serialize(Stream Wire,short[]	Payload)
		{
			if(!firstcallF)
			{
				firstcallF=true;
				BF=new BinaryWriter(Wire);
				Reset();
			}

			BF.Write((byte)(ResetToken?1:0));
			ResetToken=false;
			BF.Write((byte)ObjType.A4SHORT);
			int	Size=Payload.GetLength(0);
			BF.Write(Size);
			for(int	i=0;i<Size;i++)
			{
				BF.Write(Payload[i]);
			}
		}

		private	 void Serialize(Stream Wire,int[] Payload)
		{
			if(!firstcallF)
			{
				firstcallF=true;
				BF=new BinaryWriter(Wire);
				Reset();
			}

			BF.Write((byte)(ResetToken?1:0));
			ResetToken=false;
			BF.Write((byte)ObjType.A4INT);
			int	Size=Payload.GetLength(0);
			BF.Write(Size);
			for(int	i=0;i<Size;i++)
			{
				BF.Write(Payload[i]);
			}
		}

		private	 void Serialize(Stream Wire,long[] Payload)
		{
			if(!firstcallF)
			{
				firstcallF=true;
				BF=new BinaryWriter(Wire);
				Reset();
			}

			BF.Write((byte)(ResetToken?1:0));
			ResetToken=false;
			BF.Write((byte)ObjType.A4LONG);
			int	Size=Payload.GetLength(0);
			BF.Write(Size);
			for(int	i=0;i<Size;i++)
			{
				BF.Write(Payload[i]);
			}
		}

		private	 void Serialize(Stream Wire,sbyte[]	Payload)
		{
			if(!firstcallF)
			{
				firstcallF=true;
				BF=new BinaryWriter(Wire);
				Reset();
			}

			BF.Write((byte)(ResetToken?1:0));
			ResetToken=false;
			BF.Write((byte)ObjType.A4SBYTE);
			int	Size=Payload.GetLength(0);
			BF.Write(Size);
			for(int	i=0;i<Size;i++)
			{
				BF.Write(Payload[i]);
			}
		}

		private	 void Serialize(Stream Wire,float[]	Payload)
		{
			if(!firstcallF)
			{
				firstcallF=true;
				BF=new BinaryWriter(Wire);
				Reset();
			}

			BF.Write((byte)(ResetToken?1:0));
			ResetToken=false;
			BF.Write((byte)ObjType.A4FLOAT);
			int	Size=Payload.GetLength(0);
			BF.Write(Size);
			for(int	i=0;i<Size;i++)
			{
				BF.Write(Payload[i]);
			}
		}

		private	 void Serialize(Stream Wire,string[] Payload)
		{
			if(!firstcallF)
			{
				firstcallF=true;
				BF=new BinaryWriter(Wire);
				Reset();
			}

			BF.Write((byte)(ResetToken?1:0));
			ResetToken=false;
			BF.Write((byte)ObjType.A4STRING);
			int	Size=Payload.GetLength(0);
			BF.Write(Size);
			for(int	i=0;i<Size;i++)
			{
				//Necessary	because	null elements throws Exceptions	when deserialized using
				//BinaryReader
				if (Payload[i]==null)
					BF.Write("$");
				else if	(new String('$',Payload[i].Length).Equals(Payload[i]))
					BF.Write(Payload[i]+"$");
				else
					BF.Write(Payload[i]);
			}
		}

		private	 void Serialize(Stream Wire,ushort[] Payload)
		{
			if(!firstcallF)
			{
				firstcallF=true;
				BF=new BinaryWriter(Wire);
				Reset();
			}

			BF.Write((byte)(ResetToken?1:0));
			ResetToken=false;
			BF.Write((byte)ObjType.A4USHORT);
			int	Size=Payload.GetLength(0);
			BF.Write(Size);
			for(int	i=0;i<Size;i++)
			{
				BF.Write(Payload[i]);
			}
		}

		private	 void Serialize(Stream Wire,uint[] Payload)
		{
			if(!firstcallF)
			{
				firstcallF=true;
				BF=new BinaryWriter(Wire);
				Reset();
			}

			BF.Write((byte)(ResetToken?1:0));
			ResetToken=false;
			BF.Write((byte)ObjType.UINT);
			int	Size=Payload.GetLength(0);
			BF.Write(Size);
			for(int	i=0;i<Size;i++)
			{
				BF.Write(Payload[i]);
			}
		}

		private	 void Serialize(Stream Wire,ulong[]	Payload)
		{
			if(!firstcallF)
			{
				firstcallF=true;
				BF=new BinaryWriter(Wire);
				Reset();
			}

			BF.Write((byte)(ResetToken?1:0));
			ResetToken=false;
			BF.Write((byte)ObjType.A4ULONG);
			int	Size=Payload.GetLength(0);
			BF.Write(Size);
			for(int	i=0;i<Size;i++)
			{
				BF.Write(Payload[i]);
			}
		}

		private	 void Serialize(Stream Wire,byte Payload)
		{
			if(!firstcallF)
			{
				firstcallF=true;
				BF=new BinaryWriter(Wire);
				Reset();
			}

			BF.Write((byte)(ResetToken?1:0));
			ResetToken=false;
			BF.Write((byte)ObjType.BYTE);
			BF.Write(Payload);
			BF.Flush();
		}

		private	 void Serialize(Stream Wire,char Payload)
		{
			if(!firstcallF)
			{
				firstcallF=true;
				BF=new BinaryWriter(Wire);
				Reset();
			}

			BF.Write((byte)(ResetToken?1:0));
			ResetToken=false;
			BF.Write((byte)ObjType.CHAR);
			BF.Write(Payload);
			BF.Flush();
		}

		private	 void Serialize(Stream Wire,double Payload)
		{
			if(!firstcallF)
			{
				firstcallF=true;
				BF=new BinaryWriter(Wire);
				Reset();
			}

			BF.Write((byte)(ResetToken?1:0));
			ResetToken=false;
			BF.Write((byte)ObjType.DOUBLE);
			BF.Write(Payload);
			BF.Flush();
		}

		private	 void Serialize(Stream Wire,short Payload)
		{
			if(!firstcallF)
			{
				firstcallF=true;
				BF=new BinaryWriter(Wire);
				Reset();
			}
			BF.Write((byte)(ResetToken?1:0));
			ResetToken=false;
			BF.Write((byte)ObjType.SHORT);
			BF.Write(Payload);
			BF.Flush();
		}

		private	 void Serialize(Stream Wire,int	Payload)
		{
			if(!firstcallF)
			{
				firstcallF=true;
				BF=new BinaryWriter(Wire);
				Reset();
			}
			BF.Write((byte)(ResetToken?1:0));
			ResetToken=false;
			BF.Write((byte)ObjType.INT);
			BF.Write(Payload);
			BF.Flush();
		}

		private	 void Serialize(Stream Wire,long Payload)
		{
			if(!firstcallF)
			{
				firstcallF=true;
				BF=new BinaryWriter(Wire);
				Reset();
			}
			BF.Write((byte)(ResetToken?1:0));
			ResetToken=false;
			BF.Write((byte)ObjType.LONG);
			BF.Write(Payload);
			BF.Flush();
		}

		private	 void Serialize(Stream Wire,sbyte Payload)
		{
			if(!firstcallF)
			{
				firstcallF=true;
				BF=new BinaryWriter(Wire);
				Reset();
			}
			BF.Write((byte)(ResetToken?1:0));
			ResetToken=false;
			BF.Write((byte)ObjType.SBYTE);
			BF.Write(Payload);
			BF.Flush();
		}

		private	 void Serialize(Stream Wire,float Payload)
		{
			if(!firstcallF)
			{
				firstcallF=true;
				BF=new BinaryWriter(Wire);
				Reset();
			}
			BF.Write((byte)(ResetToken?1:0));
			ResetToken=false;
			BF.Write((byte)ObjType.FLOAT);
			BF.Write(Payload);
			BF.Flush();
		}

		private	 void Serialize(Stream Wire,ushort Payload)
		{
			if(!firstcallF)
			{
				firstcallF=true;
				BF=new BinaryWriter(Wire);
				Reset();
			}
			BF.Write((byte)(ResetToken?1:0));
			ResetToken=false;
			BF.Write((byte)ObjType.USHORT);
			BF.Write(Payload);
			BF.Flush();
		}

		private	 void Serialize(Stream Wire,uint Payload)
		{
			if(!firstcallF)
			{
				firstcallF=true;
				BF=new BinaryWriter(Wire);
				Reset();
			}
			BF.Write((byte)(ResetToken?1:0));
			ResetToken=false;
			BF.Write((byte)ObjType.UINT);
			BF.Write(Payload);
			BF.Flush();
		}

		private	 void Serialize(Stream Wire,ulong Payload)
		{
			if(!firstcallF)
			{
				firstcallF=true;
				BF=new BinaryWriter(Wire);
				Reset();
			}
			BF.Write((byte)(ResetToken?1:0));
			ResetToken=false;
			BF.Write((byte)ObjType.ULONG);
			BF.Write(Payload);
			BF.Flush();
		}

		private	bool firstcallF;
		private	bool firstcallR;

		BinaryWriter BF;
		BinaryReader BR;

		///	<summary>
		///	Main Constructor.
		///	</summary>
		public CompactFormatter()
		{
			firstcallR=false;
			firstcallF=false;
		}

		private	void Serialize(Stream Wire,bool	Payload)
		{
			if(!firstcallF)
			{
				firstcallF=true;
				BF=new BinaryWriter(Wire);
				// I've	to send	the	reset
				Reset();
			}

			BF.Write((byte)(ResetToken?1:0));
			ResetToken=false;
			BF.Write((byte)ObjType.BOOL);
			BF.Write(Payload);
			BF.Flush();
		}

		private	void Serialize(Stream Wire,	object Payload,ArrayList ObjectTable)
		{
			this.ObjectTable=ObjectTable;
			Serialize(Wire,Payload);
		}

		///	<summary>
		///	Used to	Serialize an object	to a stream
		///	</summary>
		///	<param name="Wire">Wire	is the stream where	the	object must	be serialized</param>
		///	<param name="Payload">Payload is the object	which has to be	serialized</param>
		public void Serialize(Stream Wire,	object Payload)
		{
#if	DEBUG
		WriteDebug(DebugLevel.VERBOSE,"Starting	Serializing	object...");
#endif

			if (Wire==null)
				throw new ArgumentNullException();

			if (Payload==null)
			{
#if	DEBUG
			CompactFormatter.WriteDebug(DebugLevel.VERBOSE,"Payload	is null, serializing it");
#endif

				if(!firstcallF)
				{
					firstcallF=true;
					BF=new BinaryWriter(Wire);
					Reset();
				}

				BF.Write((byte)(ResetToken?1:0));
				ResetToken=false;
				BF.Write((byte)ObjType.NULL);
				BF.Flush();
				return;
			}
			for(int	i=0;i<ObjectTable.Count;i++)
				if (Payload.Equals(ObjectTable[i]))
				{
					if(!firstcallF)
					{
						firstcallF=true;
						BF=new BinaryWriter(Wire);
						Reset();
					}

					BF.Write((byte)0);//Here i can't ask for a reset!!!
					BF.Write((byte)ObjType.ALREADYWROTE);
					BF.Write(i);
					BF.Flush();
					return;
				}

			switch(Payload.GetType().ToString())
			{
				case "System.Int32":
				{
					Serialize(Wire,(int)Payload);
					break;
				}
				case "System.String":
				{
					Serialize(Wire,(string)Payload);
					break;
				}
				case "System.Boolean":
				{
					Serialize(Wire,(bool)Payload);
					break;
				}
				case "System.SByte":
				{
					Serialize(Wire,(sbyte)Payload);
					break;
				}
				case "System.Byte":
				{
					Serialize(Wire,(byte)Payload);
					break;
				}
				case "System.Char":
				{
					Serialize(Wire,(char)Payload);
					break;
				}
				case "System.Int16":
				{
					Serialize(Wire,(short)Payload);
					break;
				}
				case "System.UInt16":
				{
					Serialize(Wire,(ushort)Payload);
					break;
				}
				case "System.UInt32":
				{
					Serialize(Wire,(uint)Payload);
					break;
				}
				case "System.Int64":
				{
					Serialize(Wire,(long)Payload);
					break;
				}
				case "System.UInt64":
				{
					Serialize(Wire,(ulong)Payload);
					break;
				}
				case "System.Single":
				{
					Serialize(Wire,(float)Payload);
					break;
				}
				case "System.Double":
				{
					Serialize(Wire,(double)Payload);
					break;
				}
					//case "System.Decimal": {Serialize(Wire,(decimal)Payload);break;}
				case "System.Int32[]":
				{
					Serialize(Wire,(int[])Payload);
					break;
				}
				case "System.Boolean[]":
				{
					Serialize(Wire,(bool[])Payload);
					break;
				}
				case "System.Byte[]":
				{
					Serialize(Wire,(byte[])Payload);
					break;
				}
				case "System.Char[]":
				{
					Serialize(Wire,(char[])Payload);
					break;
				}
				//case "System.Decimal[]": {Serialize(Wire,(decimal[])Payload);break;}
				case "System.Double[]":
				{
					Serialize(Wire,(double[])Payload);
					break;
				}
				case "System.Int16[]":
				{
					Serialize(Wire,(short[])Payload);
					break;
				}
				case "System.Int64[]":
				{
					Serialize(Wire,(short[])Payload);
					break;
				}
				case "System.SByte[]":
				{
					Serialize(Wire,(sbyte[])Payload);
					break;
				}
				case "System.Float[]":
				{
					Serialize(Wire,(float[])Payload);
					break;
				}
				case "System.String[]":
				{
					Serialize(Wire,(string[])Payload);
					break;
				}
				case "System.UInt16[]":
				{
					Serialize(Wire,(ushort[])Payload);
					break;
				}
				case "System.UInt32[]":
				{
					Serialize(Wire,(uint[])Payload);
					break;
				}
				case "System.UInt64[]":
				{
					Serialize(Wire,(ulong[])Payload);
					break;
				}
				default:
				{
#if	DEBUG
				CompactFormatter.WriteDebug(DebugLevel.INFO,"Object	is not of base Type, inspecting...");
				CompactFormatter.WriteDebug(DebugLevel.INFO,"Type is "+Payload.GetType().Name);

#endif
					if (!Payload.GetType().IsArray && !Payload.GetType().IsEnum && !Payload.GetType().ToString().StartsWith("System.")	&&
						Payload.GetType().GetCustomAttributes(typeof(Serialization.
						Formatters.Serializable),false).Length==0	&& Payload.GetType().
						GetCustomAttributes(typeof(Serialization.
						Formatters.CustomSerializable),false).Length==0)
						throw new SerializationException(
							"Unable	to serialize type "+Payload.GetType().
							ToString()+
							", type	is not marked with Serializable	or CustomSerializable attribute");

					/*If it	has	a custom serialization mechanism call it*/
					if (Payload.GetType().
						GetCustomAttributes(typeof(Serialization.
						Formatters.CustomSerializable),false).Length!=0)
					{
						CustomSerialize(Payload,Wire);
						return;
					}

					if(!firstcallF)
					{
						firstcallF=true;
						BF=new BinaryWriter(Wire);
						Reset();
					}

					BF.Write((byte)(ResetToken?1:0));
					ResetToken=false;

					if (Payload.GetType().FullName.Equals("System.RuntimeType"))
					{
						ObjType	type;
						bool f=false;
						string Name=NameGenerator(ref f,(Type)Payload);
						type=ObjType.TYPE;
#if	DEBUG

						CompactFormatter.WriteDebug(DebugLevel.INFO,"Object	is a RuntimeType representing a	"+((Type)Payload).Name+" type");
#endif

						BF.Write((byte)type);
						/* fix:	In questo caso l'oggetto non ha	il namespace, devo aggiungerlo
						 */
						BF.Write(Name);
						ObjectTable.Add(Payload);
					}
					else if(System.Convert.IsDBNull(Payload))
					{
						BF.Write((byte)ObjType.DBNULL);
						BF.Flush();
						return;
					}
					else
						if(Payload.GetType().IsArray)
					{
						ObjType	type=ObjType.A4OBJECT;
						string Name=CompactFormatter.NameArrayElementGenerator(ref type,Payload.GetType().GetElementType());
#if	DEBUG

						CompactFormatter.WriteDebug(DebugLevel.INFO,"Object	is an array	of "+Name+"	type");
#endif

						BF.Write((byte)type);
						BF.Write(Name);
						int	Size=((System.Array)Payload).GetLength(0);
#if	DEBUG

						CompactFormatter.WriteDebug(DebugLevel.INFO,"Array Size	is "+Size);
#endif

						BF.Write(Size);

						for(int	i=0;i<Size;i++)
						{
							Serialize(Wire,((System.Array)Payload).GetValue(i),ObjectTable);
						}
#if	DEBUG
						CompactFormatter.WriteDebug(DebugLevel.VERBOSE,"Object written to the wire");
#endif
//#if	OBJTABLE

						//ObjectTable.Add(Payload);
//#endif

					}
					else
					{
						bool f=false;
						ObjType	type;
						string Name=NameGenerator(ref f,Payload);
						if (f)
							type=ObjType.FOBJECT;
						else
							type=ObjType.OBJECT;
#if	DEBUG

						CompactFormatter.WriteDebug(DebugLevel.INFO,"Object	is of "+Name+" type");
#endif
						BF.Write((byte)type);

						BF.Write(Name);
#if	OBJTABLE
						ObjectTable.Add(Payload);
#endif

						foreach(object Item	in CInspector.InspectClass(Payload))
						{
							Serialize(Wire,Item,ObjectTable);
						}

					}
					break;
				}
			}

		}

		#endregion

		///	<summary>
		///	The	instance of	the	compact	inspector used by this CompactFormatter	instance.
		///	</summary>
		private	CompactInspector CInspector=new	CompactInspector();
		///	<summary>
		///	An arraylist containing	the	object table.
		///	</summary>
		private	 ArrayList ObjectTable=new ArrayList();
		///	<summary>
		///	A flag indicating wether the other side	requested a	Reset.
		///	</summary>
		private	 bool ResetToken=false;

		///	<summary>
		///	Reset will empty the ObjectTable and raise the ResetToken flag.
		///	</summary>
		public void	Reset()
		{
#if	DEBUG
		CompactFormatter.WriteDebug(DebugLevel.VERBOSE,"Reset Called: Flushing the ObjectTable");
#endif

			ResetToken=true;
			// Empty the ArrayList
			ObjectTable.Clear();
		}
#if!DEBUG
		public enum	DebugLevel {NONE,ERROR,INFO,VERBOSE};
#endif
#if	DEBUG

	///	<summary>
	///	The	method used	to print debug messages.
	///	</summary>
	///	<param name="RequestedLevel">A DebugLevel constant representing	the	minimum
	///	level requested	to signal the event</param>
	///	<param name="Message">The debug	message	to write</param>
	internal static	void WriteDebug(DebugLevel RequestedLevel, string Message)
	{
		string NewLine="\r\n";
		if (level>=RequestedLevel)
			Debug.Write(Message+NewLine,"CompactFormatter");
	}
#endif
		private	void CustomSerialize(object	Payload,Stream Wire)
		{
			if(!firstcallF)
			{
				firstcallF=true;
				BF=new BinaryWriter(Wire);
				Reset();
			}

			BF.Write((byte)(ResetToken?1:0));
			ResetToken=false;
			bool f=false;
			ObjType	type;
			string Name=NameGenerator(ref f,Payload);
				type=ObjType.CUSTOM;
#if	DEBUG

		CompactFormatter.WriteDebug(DebugLevel.INFO,"Object	is of "+Name+" type");
#endif

			BF.Write((byte)type);

			BF.Write(Name);
			//Find the Method decorated	with the CustomSerialize attribute
			MethodInfo[] MI=Payload.GetType().GetMethods(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);
			for(int	i=0;i<MI.Length;i++)
			{
				if (MI[i].GetCustomAttributes(typeof(Serialization.Formatters.CustomSerialize),false)!=null	&& MI[i].GetCustomAttributes(typeof(Serialization.Formatters.CustomSerialize),false).Length!=0)
				{
					object[] param={Wire};
					MI[i].Invoke(Payload,param);
					return;
				}
			}
			throw new SerializationException(
				"No	method decorated with the CustomSerialize attribute");
		}

		private	object CustomDeserialize(ObjType type,Stream Wire)
		{
			if(!firstcallR)
			{
				firstcallR=true;
				BR=new BinaryReader(Wire);
			}

			String ClassName;
			if (type==ObjType.FCUSTOM)
			{
				ClassName=BR.ReadString();
			}
			else
			{
				ClassName=BR.ReadString();
			}

			ConstructorInfo	C=Type.GetType(ClassName).GetConstructor(BindingFlags.Instance |BindingFlags.NonPublic|BindingFlags.Public,null,new	Type[0],null);
			if (C==null)
				throw new SerializationException("Unable to	find no-parameters constructor!	this constructor must be implemented to	allow CompactFormatter to work");
			Object Answer=C.Invoke(null);

			//Find the Method decorated	with the CustomDeserialize attribute
			MethodInfo[] MI=Type.GetType(ClassName).GetMethods(BindingFlags.Instance |
				BindingFlags.Public	| BindingFlags.NonPublic);
			for(int	i=0;i<MI.Length;i++)
			{
				if (MI[i].GetCustomAttributes(typeof(Serialization.Formatters.
					CustomDeserialize),false)!=null &&	MI[i].GetCustomAttributes(typeof
					(Serialization.Formatters.CustomDeserialize),false).Length!=0)
				{
					object[] param={Wire};
					MI[i].Invoke(Answer,param);
					return Answer;
				}
			}
			throw new SerializationException("No method	decorated with the CustomDeserialize attribute");
		}

	}


}
