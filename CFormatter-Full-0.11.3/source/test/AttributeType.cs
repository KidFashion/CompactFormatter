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
	/// A generic Attribute type used to test attribute serialization
	/// </summary>
	[AttributeUsage(AttributeTargets.Class,AllowMultiple=false,Inherited=false)]
	[Serialization.Formatters.Serializable]
	public class AttributeType:Attribute
	{
		/// <summary>
		/// A string containing the identifier of the component decorated
		/// 
		/// </summary>
		private string type;

		/// <summary>
		/// The version of the component decorated.
		/// </summary>
		private float version;

		public string Type
		{
			get
			{
				return type;
			}
		}

		public float Version
		{
			get
			{
				return version;
			}
		}

		/// <summary>
		/// The parameterless constructor requested by the CompactFormatter.
		/// </summary>
		private AttributeType()
		{}

		/// <summary>
		/// The main constructor of the AttributeType class
		/// </summary>
		/// <param name="type">A string containing the identifier of the object decorated
		/// by this instance</param>
		/// <param name="version">A float representing the version number of the object
		/// decorated by this instance</param>
		public AttributeType(string type,float version)
		{
			this.type=type;
			this.version=version;
		}

		/// <summary>
		/// Check if the current instance is compatible (Type and Version are equals)
		/// with another AttributeType instance passed as parameter.
		/// </summary>
		/// <param name="attr">the AttributeType instance with whom testing the match
		/// </param>
		/// <returns>true if the instances match (Type and Version are equals)
		/// false otherwise</returns>
		public bool Compatible(AttributeType attr)
		{
			return (attr.Type==this.type && attr.Version==this.version);
		}
	}
}
