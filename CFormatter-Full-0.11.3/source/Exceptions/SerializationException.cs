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

namespace Serialization.Formatters
{
	/// <summary>
	/// The main exception thrown by the CompactFormatter
	/// </summary>
	public class SerializationException : Exception
	{

		/// <summary>
		/// Main constructor, it simply throws an exception with a generic error message
		/// about serialization
		/// </summary>
		public SerializationException(): base("An Exception occurred during serialization")
		{}

		/// <summary>
		/// A more specific constructor, it allows the application to customize the error
		/// message to give more information about the Exception
		/// </summary>
		/// <param name="s">the String containing the text to attach to the exception
		/// </param>
		public SerializationException(string s): base(s)
		{}
	}
}
