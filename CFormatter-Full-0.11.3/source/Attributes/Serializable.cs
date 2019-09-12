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
	/// The Serializable Attribute:
	/// Only classes decorated with Serializable attribute can be serialized.
	/// Trying to serialize a class without this attribute or CustomSerializable one
	/// will launch a SerializationException.
	/// (Base types are serializable by default)
	/// </summary>
	[AttributeUsage(AttributeTargets.Class | AttributeTargets.Struct | AttributeTargets.Delegate)]
	public class Serializable : Attribute
	{
	}
}
