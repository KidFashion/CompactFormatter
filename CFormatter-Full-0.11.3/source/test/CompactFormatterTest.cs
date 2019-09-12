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

using System;
using NUnit.Framework;
using System.IO;
using System.Collections;
using System.Diagnostics;
using System.Data;

namespace Serialization.Formatters.Test
{
	/// <summary>
	/// A Test class for the CompactFormatter designed to be used with NUnit.
	/// </summary>
	[TestFixture]
	public class CompactFormatterTest
	{

		/// <summary>
		/// A simple flag depicting the use or not of debug messages
		/// </summary>
		private bool debugging=false;

		/// <summary>
		/// The SetUp method for this test case, it simply set Debug environment if 
		/// necessary.
		/// </summary>
		[SetUp]
		public void SetUp()
		{
			if (debugging) return;
#if !CF
			Debug.Listeners.Add(new TextWriterTraceListener(Console.Out));
			Debug.AutoFlush = true;
#endif
			debugging=true;
		}

		/// <summary>
		/// Testing the serialization of enum types:
		/// Enums should be serializable even if not decorated with Serializable attribute like in standard Formatters.
		/// </summary>
		[Test]
		public void SerializeEnumTypes()
		{
			FileStream FS=new FileStream("Test.bin",FileMode.Create);
			CompactFormatter CS=new CompactFormatter();
			EnumType en=EnumType.SECOND;
			try
			{
				CS.Serialize(FS,en);
			}
			finally
			{FS.Close();}
			FileStream FS2=new FileStream("Test.bin",FileMode.Open);
			try
			{
				EnumType en2=(EnumType)CS.Deserialize(FS2);
				FS2.Close();
				NUnit.Framework.Assertion.AssertEquals(en,en2);
			}
			finally
			{
				FS2.Close();
			}
		
		}


		/// <summary>
		/// Testing the serialization of DataSet types.
		/// </summary>
		[Test]
		public void SerializeDataSetType()
		{
			DataSetType DST=new DataSetType();
			FileStream FS=new FileStream("Test.bin",FileMode.Create);
			CompactFormatter CS=new CompactFormatter();
			try
			{
				CS.Serialize(FS,DST.DSet);
			}
			finally
			{FS.Close();}
			FileStream FS2=new FileStream("Test.bin",FileMode.Open);
			try
			{
				DataSet DSet2=(DataSet)CS.Deserialize(FS2);
				FS2.Close();
				NUnit.Framework.Assertion.AssertEquals(DST.DSet,DSet2);
			}
			finally
			{
				FS2.Close();
			}

		}

		/// <summary>
		/// Testing the serialization of SelfReferencing types:
		/// This method tries to serialize an instance of a SelfReferencing tem.
		/// After this, it tries to re-read variable from the file.
		/// </summary>
		[Test]
		public void SerializeSelfReferencingTypes()
		{
			FileStream FS=new FileStream("Test.bin",FileMode.Create);
			CompactFormatter CS=new CompactFormatter();
			SelfReferencingItem SRI=new SelfReferencingItem(12);
			try
			{
				CS.Serialize(FS,SRI);
			}
			finally
			{FS.Close();}
			FileStream FS2=new FileStream("Test.bin",FileMode.Open);
			try
			{
				SelfReferencingItem SRI2=(SelfReferencingItem)CS.Deserialize(FS2);
				FS2.Close();
				NUnit.Framework.Assertion.AssertEquals(SRI,SRI2);
			}
			finally
			{
				FS2.Close();
			}
		}

		/// <summary>
		/// Testing the serialization of base types:
		/// This method tries to serialize an integer, a double and a string on a file stream.
		/// After this, it tries to re-read variable from the file.
		/// </summary>
		[Test]
		public void SerializeBaseTypes()
		{
			FileStream FS=new FileStream("Test.bin",FileMode.Create);
			CompactFormatter CS=new CompactFormatter();
			int number=42;
			double fnumber=3.1415;
			string name="CompactFormatter";
			try
			{
				CS.Serialize(FS,number);
				CS.Serialize(FS,fnumber);
				CS.Serialize(FS,name);
			}
			finally
			{FS.Close();}
			FileStream FS2=new FileStream("Test.bin",FileMode.Open);
			try
			{
				int number2=(int)CS.Deserialize(FS2);
				double fnumber2=(double)CS.Deserialize(FS2);
				string name2=(string)CS.Deserialize(FS2);
				FS2.Close();
				NUnit.Framework.Assertion.AssertEquals(number,number2);
				NUnit.Framework.Assertion.AssertEquals(fnumber,fnumber2);
				NUnit.Framework.Assertion.AssertEquals(name,name2);
			}
			finally
			{
				FS2.Close();
			}
	}

		/// <summary>
		/// An example depicting how, in particular situations, the use of custom mechanism
		/// of serialization can help to move around CompactFormatter limitations.
		/// In this particular example a Delegate is serialized even if CompactFormatter 
		/// can't serialize delegates.
		/// </summary>
		[Test]
		public void SerializeDelegate()
		{
			FileStream FS=new FileStream("Test.bin",FileMode.Create);
			CompactFormatter CS=new CompactFormatter();
			WriteDelegate WD=new WriteDelegate(DelegateWrapper.WriteScreen);
			DelegateWrapper DW=new DelegateWrapper(WD,DelegateTypes.WRITESCREEN);
			try
			{
				CS.Serialize(FS,DW);
			}
			finally
			{FS.Close();}
			FileStream FS2=new FileStream("Test.bin",FileMode.Open);
			try
			{
				DelegateWrapper DW2=(DelegateWrapper)CS.Deserialize(FS2);
				FS2.Close();
				DW2.Write("DelegateSerializationTest");
			}
			finally
			{
				FS2.Close();
			}			

		}

		/// <summary>
		/// A test aimed to check the correct serialization of Attributes.
		/// This method tries to serialize an attribute on a file stream.
		/// After this, it tries to re-read it from the file.
		/// </summary>
		[Test]
		public void SerializeAttributeTypes()
		{
			FileStream FS=new FileStream("Test.bin",FileMode.Create);
			CompactFormatter CS=new CompactFormatter();
			AttributeType obj=new AttributeType("TCP",1.0F);
			try
			{
				CS.Serialize(FS,obj);
			}
			finally
			{FS.Close();}
			FileStream FS2=new FileStream("Test.bin",FileMode.Open);
			try
			{
				AttributeType obj2=(AttributeType)CS.Deserialize(FS2);
				FS2.Close();
				NUnit.Framework.Assertion.AssertEquals(obj2,obj);
			}
			finally
			{
				FS2.Close();
			}
		
		}

		/// <summary>
		/// A test aimed to check the correct serialization of arrays.
		/// This method tries to serialize three arrays (An array of DateTime objects,
		///  an array of Strings and an array of Integers) on a file stream.
		/// After this, it tries to re-read them from the file.
		/// </summary>
		[Test]
		public void SerializeArrayTypes()
		{
			FileStream FS=new FileStream("Test.bin",FileMode.Create);
			CompactFormatter CS=new CompactFormatter();
			
			String[] ArTesto=new String[10];
			int[] ArNum=new int[10];
			DateTime[] ArStamp=new DateTime[10];

			ArTesto[0]="Primo Elemento";
			ArTesto[1]="Secondo Elemento";
			ArTesto[2]="Terzo Elemento";
			ArTesto[4]="$$";
			ArNum[0]=1;
			ArNum[1]=2;
			ArNum[5]=6;
			ArStamp[0]=DateTime.Now;
			ArStamp[1]=DateTime.Now;
			ArStamp[3]=DateTime.Now;
			
			
				CS.Serialize(FS,ArTesto);
				CS.Serialize(FS,ArNum);
				CS.Serialize(FS,ArStamp);
				FS.Close();
				FileStream FS2=new FileStream("Test.bin",FileMode.Open);
			try
			{
			
				String[] ArTesto2=(String[])CS.Deserialize(FS2);
				int[] ArNum2=(int[])CS.Deserialize(FS2);
				DateTime[] ArStamp2=(DateTime[])CS.Deserialize(FS2);
				for(int i=0;i<ArTesto.Length;i++)
				{
					NUnit.Framework.Assertion.AssertEquals(ArTesto[i],ArTesto2[i]);
				}
				for(int i=0;i<ArNum.Length;i++)
				{
					NUnit.Framework.Assertion.AssertEquals(ArNum[i],ArNum2[i]);
				}
				for(int i=0;i<ArStamp.Length;i++)
				{
					NUnit.Framework.Assertion.AssertEquals(ArStamp[i],ArStamp2[i]);
				}
			}
			finally
			{
			FS2.Close();
			}
			
		}
		/// <summary>
		/// A test aimed to check the correct serialization of complex types (types which 
		/// are not primitive).
		/// This method tries to serialize three complex types (A DateTime,
		/// an ArrayList and a Type object) on a file stream.
		/// After this, it tries to re-read them from the file.
		/// </summary>
		[Test]
		public void SerializeComplexTypes()
		{
			FileStream FS=new FileStream("Test.bin",FileMode.Create);
			CompactFormatter CS=new CompactFormatter();
			ArrayList AR=new ArrayList();
			AR.Add("Primo Elemento");
			AR.Add("Secondo Elemento");
			AR.Add("Terzo Elemento");
			DateTime stamp=DateTime.Now;
			Type type=typeof(System.Exception);
			try
			{
				CS.Serialize(FS,AR);
				CS.Serialize(FS,stamp);
				CS.Serialize(FS,type);
			}
			finally{FS.Close();}
			FileStream FS2=new FileStream("Test.bin",FileMode.Open);
			try{
			ArrayList AR2=(ArrayList)CS.Deserialize(FS2);
			DateTime stamp2=(DateTime)CS.Deserialize(FS2);
			Type type2=(Type)CS.Deserialize(FS2);
			NUnit.Framework.Assertion.AssertEquals(stamp,stamp2);
			for(int i=0;i<AR.Count;i++)
			{
				NUnit.Framework.Assertion.AssertEquals(AR[i],AR2[i]);
			}
			NUnit.Framework.Assertion.AssertEquals(type,type2);	
		}
		finally{FS2.Close();}
		}

		/// <summary>
		/// A test aimed to check the correct serialization of user-defined types.
		/// This method tries to serialize an object of Type ComplexType on a file stream.
		/// After this, it tries to re-read them from the file.
		/// </summary>
		[Test]
		public void SerializeComplexCustomType()
		{
			CompactFormatter CS=new CompactFormatter();
			ComplexType complex=new ComplexType(42,3.1415,"Compact Framework");
			FileStream FS=new FileStream("Test.bin",FileMode.Create);
			try
			{				
				CS.Serialize(FS,complex);
			}
			finally{
				FS.Close();}
			FileStream FS2=new FileStream("Test.bin",FileMode.Open);
			try
			{
				ComplexType complex2=(ComplexType)CS.Deserialize(FS2);
				NUnit.Framework.Assertion.AssertEquals(complex,complex2);
			}
			finally{
				FS2.Close();}
		}

		/// <summary>
		/// A test aimed to check the correct serialization of structs.
		/// This method tries to serialize a struct, defined as a StructType object,
		/// on a file stream.
		/// After this, it tries to re-read them from the file.
		/// </summary>
		[Test]
		public void SerializeStruct()
		{
			CompactFormatter CS=new CompactFormatter();
			StructType str=new StructType(2,4,3.14F,"TestStruct");
			FileStream FS=new FileStream("Test.bin",FileMode.Create);
			try
			{				
				CS.Serialize(FS,str);
			}
			finally
			{
				FS.Close();}
			FileStream FS2=new FileStream("Test.bin",FileMode.Open);
			try
			{
				StructType str2=(StructType)CS.Deserialize(FS2);
				NUnit.Framework.Assertion.AssertEquals(str,str2);
			}
			finally
			{
				FS2.Close();}

		}
		/// <summary>
		/// A test aimed to check the custom serialization feature of the CompactFormatter.
		/// This method tries to serialize an object marked with the CustomSerializable
		/// attribute on a file stream.
		/// After this, it tries to re-read them from the file.
		/// </summary>
		[Test]
		public void SerializeCustomObject()
		{
			CompactFormatter CS=new CompactFormatter();
			CustomObject custom=new CustomObject("CompactFormatter",42,3.1415F);
			FileStream FS=new FileStream("Test.bin",FileMode.Create);
			try
			{				
				CS.Serialize(FS,custom);
			}
			finally
			{
				FS.Close();}
			FileStream FS2=new FileStream("Test.bin",FileMode.Open);
			try
			{
				CustomObject custom2=(CustomObject)CS.Deserialize(FS2);
				NUnit.Framework.Assertion.AssertEquals(true,custom2.Matches("CompactFormatter",42,3.1415F));
			}
			finally
			{
				FS2.Close();
			}				
		}

		/// <summary>
		/// A test aimed to check the NotSerializable feature of the CompactFormatter.
		/// This method tries to serialize an object which contains fields marked with
		/// the NotSerializable (these fields should NOT be serialized)
		/// After this, it tries to re-read them from the file, and check that 
		/// NotSerializable fields were not serialized.
		/// </summary>
		[Test]
		public void SerializeNotSerializable()
		{
			CompactFormatter CS=new CompactFormatter();
			NotSerializableType NST=new NotSerializableType(42,3.1415,"CompactFormatter");
			FileStream FS=new FileStream("Test.bin",FileMode.Create);
			try
			{				
				CS.Serialize(FS,NST);
			}
			finally
			{
				FS.Close();}
			FileStream FS2=new FileStream("Test.bin",FileMode.Open);
			try
			{
				NotSerializableType NST2=(NotSerializableType)CS.Deserialize(FS2);
				NUnit.Framework.Assertion.AssertEquals("Expected default value 0 for the NonSerializable field number, found"+NST2.number,NST2.number,0);
				NUnit.Framework.Assertion.AssertEquals("Expected serialized value of 3.1415 for the Serializable field dnumber, found:"+NST2.dnumber,NST2.dnumber,3.1415);
			}
			finally
			{
				FS2.Close();}
		}
	}
}
