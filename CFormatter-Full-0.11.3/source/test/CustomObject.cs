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
using Serialization.Formatters;
using System.IO;

namespace Serialization.Formatters.Test
{
	/// <summary>
	/// An object using a custom serialization mechanism, implemented by the two methods
	/// marked with CustomSerialize and CustomDeserialize attributes.
	/// It's used by the CompactFormatterTest class to test Custom Serialization mechanism
	/// </summary>
	[CustomSerializable]
	public class CustomObject
	{

		/// <summary>
		/// Simply a string.
		/// </summary>
		String Text;

		/// <summary>
		/// Simply an integer.
		/// </summary>
		int Integer;

		/// <summary>
		/// Simply a float.
		/// </summary>
		float Float;

		/// <summary>
		/// The Serialize method is marked with the CustomSerialize attribute, this means 
		/// that it contains the policy to serialize the instance on a stream.
		/// </summary>
		/// <param name="Wire">the Stream on which serialize the object</param>
		[CustomSerialize]
		public void Serialize(Stream Wire)
		{
			BinaryWriter BW=new BinaryWriter(Wire);
			BW.Write(Text);
			BW.Write(Integer);
			BW.Write(Float);
		}

		/// <summary>
		/// The Deserialize method is marked with the CustomDeserialize attribute, this 
		/// means that it contains the policy to deserialize the instance on a stream.
		/// </summary>
		/// <param name="Wire">the Stream from which deserialize the object</param>
		[CustomDeserialize]
		public void Deserialize(Stream Wire)
		{
			BinaryReader BR=new BinaryReader(Wire);
			Text=BR.ReadString();
			Integer=BR.ReadInt32();
			Float=BR.ReadSingle();
		}

		/// <summary>
		/// The main constructor for this test class.
		/// </summary>
		/// <param name="Text">A string used to set inner Text variable</param>
		/// <param name="Integer">an integer used to set inner Integer variable</param>
		/// <param name="Float">a float used to set inner Float variable</param>
		public CustomObject(String Text,int Integer,float Float)
		{
			this.Text=Text;
			this.Integer=Integer;
			this.Float=Float;
		}
		
		/// <summary>
		/// Parameterless constructor requested by the CompactFormatter.
		/// </summary>
		private CustomObject()
		{}

		/// <summary>
		/// A method used to check if inner variables are equals to variables passed as 
		/// parameters
		/// </summary>
		/// <param name="Text">A string to compare with inner Text variable</param>
		/// <param name="Integer">An integer to compare with inner Integer variable</param>
		/// <param name="Float">A float to compare with inner Float variable</param>
		/// <returns>true if all three inner variables are equals to parameters,
		/// false otherwise</returns>
		public bool Matches(String Text,int Integer,float Float)
		{
			return (Text==this.Text && Integer==this.Integer && Float==this.Float);
		}
	}
}
