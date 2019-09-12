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
	/// An user-defined type used to test CompactFormatter serialization.
	/// It is used by the CompactFormatterTest class
	/// </summary>
	[Serialization.Formatters.Serializable]
	public class ComplexType
	{

		/// <summary>
		/// Simply an integer.
		/// </summary>
		int number=42;
		/// <summary>
		/// Simply a double.
		/// </summary>
		double dnumber=3.1415;
		/// <summary>
		/// Simply a string.
		/// </summary>
		string name="Compact Formatter";

		/// <summary>
		/// Parameterless constructor requested by the CompactFormatter.
		/// </summary>
		public ComplexType()
		{
			number=0;
			dnumber=0.0;
			name=null;
		}

		/// <summary>
		/// Main constructor for the ComplexType object, it takes three parameters
		/// and set inner fields.
		/// </summary>
		/// <param name="number">An integer used to set number field</param>
		/// <param name="dnumber">A double used to set dnumber field</param>
		/// <param name="name">A string used to set name field</param>
		public ComplexType(int number,double dnumber,string name)
		{
			this.number=number;
			this.dnumber=dnumber;
			this.name=name;
		}

		/// <summary>
		/// Check for equality with an object passed as parameter.
		/// </summary>
		/// <param name="obj">The object to test for equality</param>
		/// <returns>true if the two objects are the same, false otherwise</returns>
		public override bool Equals(object obj)
		{
			if (!(obj is ComplexType)) return false;
			if (((ComplexType)obj).dnumber==this.dnumber &&
				((ComplexType)obj).number==this.number &&
				((ComplexType)obj).name==this.name)
			return true;
			else return false;
		}
	}
}
