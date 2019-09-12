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

namespace Serialization.Formatters.Test
{
	/// <summary>
	/// A Type very similar to the ComplexType, but in which one field has been marked
	/// with the NotSerializable attribute to prevent its serialization.
	/// </summary>
	[Serialization.Formatters.Serializable]
	public class NotSerializableType
	{
		/// <summary>
		/// Simply an integer, notice that it is marked with the NotSerializable attribute
		/// so it's not going to be serialized.
		/// </summary>
		[NotSerializable]
		public int number=42;
		/// <summary>
		/// Simply a double number.
		/// </summary>
		public double dnumber=3.1415;
		/// <summary>
		/// Simply a string.
		/// </summary>
		string name="Compact Formatter";

		/// <summary>
		/// Parameterless constructor required by the CompactFormatter.
		/// </summary>
		public NotSerializableType()
		{
			number=0;
			dnumber=0.0;
			name=null;
		}

		/// <summary>
		/// Main constructor
		/// </summary>
		/// <param name="number">An integer used to set the inner number variable</param>
		/// <param name="dnumber">A double used to set the inner dnumber variable</param>
		/// <param name="name">A string used to set the inner name variable</param>
		public NotSerializableType(int number,double dnumber,string name)
		{
			this.number=number;
			this.dnumber=dnumber;
			this.name=name;
		}
		/// <summary>
		/// Checks for equality
		/// </summary>
		/// <param name="obj">The object tested for equality</param>
		/// <returns>true if the NotSerializableType is equal to the object passed 
		/// parameter, false otherwise
		/// </returns>
		public override bool Equals(object obj)
		{
			if (!(obj is NotSerializableType)) return false;
			if (((NotSerializableType)obj).dnumber==this.dnumber &&
				((NotSerializableType)obj).number==this.number &&
				((NotSerializableType)obj).name==this.name)
				return true;
			else return false;
		}
	}
}
