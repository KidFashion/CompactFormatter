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
using System.Reflection;
using System.Collections;
using System.Security.Permissions;
using System.IO;

namespace Serialization.Formatters
{
	/// <summary>
	/// Class used to inspect other classes at runtime. 
	/// </summary>
	public class CompactInspector
	{
		/// <summary>
		/// The InspectClass method uses reflection to extract objects
		/// from a given class.
		/// </summary>
		/// <param name="Class">The object to inspect</param>
		/// <returns>An array of objects containing all properties of the Class object
		/// </returns>
		public Array InspectClass(object Class)
		{
				ArrayList List=new ArrayList();
				List.Clear();			
				Type t=Class.GetType();
				while (t.BaseType!=null)
				{
					FieldInfo[] InnerList=(t.GetFields(BindingFlags.Public| BindingFlags.NonPublic | BindingFlags.Instance|BindingFlags.DeclaredOnly));
					for(int i=0;i<InnerList.Length;i++)
					{
						//I'm going to consider only fields not marked with the 
						//NotSerializable attribute
						if (!InnerList[i].FieldType.IsPointer && InnerList[i].GetCustomAttributes(typeof
							(Serialization.Formatters.NotSerializable),false).Length==0)
							List.Add(InnerList[i].GetValue(Class));
					}
					t=t.BaseType;
				}	
				/* *
				 * Checking the superclass of the object, if it's null (superclass of object
				 * type) i can proceed, elsewhere i've to recursively inspect the superclass
				 * */

			return List.ToArray();
		}

		/// <summary>
		/// The method SummonClass, given an object and an array of values populates the 
		/// object with values from the array.
		/// It is used by the CompactFormatter to rebuild an object in the deserialization
		/// phase.
		/// </summary>
		/// <param name="Class">the object being populated</param>
		/// <param name="Values">The array of objects used to populate the Class parameter
		/// </param>
		public void SummonClass(object Class,Array Values)
		{
			try
			{
				Type t=Class.GetType();int j=0;

				while (t.BaseType!=null)
				{
					FieldInfo[] InnerList=(t.GetFields(BindingFlags.Public| BindingFlags.NonPublic | BindingFlags.Instance|BindingFlags.DeclaredOnly));
					for(int i=0;i<InnerList.Length;i++)
					{
						if (!InnerList[i].FieldType.IsPointer && InnerList[i].GetCustomAttributes(typeof
							(Serialization.Formatters.NotSerializable),false).Length==0)
							{
							InnerList[i].SetValue(Class,Values.GetValue(j++));
							}

					}
					t=t.BaseType;
					
				}
			}
			catch(Exception err)
			{throw new SerializationException("Error while summoning class with the Compact Inspector:"
				 + err.Message);}
		}

	}
}
