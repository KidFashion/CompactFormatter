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
	/// A simple Struct object used by the CompactFormatterTest class to check
	/// Attribute serialization.
	/// Notice that since struct are already allocated on the heap there's no need of
	/// parameterless constructor.
	/// </summary>
	[Serialization.Formatters.Serializable]
	public struct StructType 
	{
		/// <summary>
		/// a couple of integers
		/// </summary>
		public int x, y;
		/// <summary>
		/// a simple float
		/// </summary>
		float r;
		/// <summary>
		/// a simple string
		/// </summary>
		string m;

		/// <summary>
		/// Main constructor
		/// </summary>
		/// <param name="p1">the first integer</param>
		/// <param name="p2">the second integer</param>
		/// <param name="r">the float</param>
		/// <param name="m">the string</param>
		public StructType(int p1, int p2,float r,string m) 
		{
			x = p1;
			y = p2;

			this.r=r;
			this.m=m;
		}
	}
}
