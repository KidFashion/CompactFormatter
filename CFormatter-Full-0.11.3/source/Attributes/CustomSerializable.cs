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
	/// The CustomSerializable attribute:
	/// Classes decorated witth this attributeare classes which can be serialized but must
	/// implement their own custom methods of serialization and deserialization.
	/// The methods implementing the serialization/deserialization mechanism must be 
	/// decorated with CustomSerialize and CustomDeserialize Methods
	/// </summary>
	[AttributeUsage(AttributeTargets.Class | AttributeTargets.Struct | AttributeTargets.Delegate)]
	public class CustomSerializable : Attribute
	{
	}
}
