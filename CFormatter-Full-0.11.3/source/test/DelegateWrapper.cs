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
using System.IO;
using Serialization.Formatters;

namespace Serialization.Formatters.Test
{
	/// <summary>
	/// A simple enum enumerating all possible methods which could be used in the 
	/// building the WriteDelegate delegate
	/// </summary>
	public enum DelegateTypes {WRITESCREEN,WRITEFILE};

	/// <summary>
	/// A delegate wrapping a void(string) function signature.
	/// </summary>
	public delegate void WriteDelegate(String text);


	/// <summary>
	/// A Class wrapping the delegate, allowing it to be serialized.
	/// Notice that it declares a custom serialization mechanism.
	/// </summary>
	[CustomSerializable]
	public class DelegateWrapper
	{
		
		/// <summary>
		/// Parameterless constructor requested by the CompactFormatter
		/// </summary>
		private DelegateWrapper()
		{}

		/// <summary>
		/// One of methods which could be used in the WriteDelegate delegate.
		/// It simply prints a string on screen
		/// </summary>
		/// <param name="text">The text to print</param>
		public static void WriteScreen(String text)
		{
			Console.WriteLine(text);
		}

		/// <summary>
		/// The other method which, in this example, could be used in the WriteDelegate
		/// delegate.
		/// It should print on filesystem but, since this is just an example, it will print
		/// a string on the screen preceded by the "This should be on file:" string
		/// </summary>
		/// <param name="text">The text to print</param>
		public static void WriteFile(String text)
		{
			Console.WriteLine("This should be on file:" + text);
		}

		/// <summary>
		/// Variable used to keep track of method wrapped bythe WriteDelegate
		/// </summary>
		DelegateTypes Type;	

		/// <summary>
		/// Variable containing the WriteDelegate delegate
		/// </summary>
		public WriteDelegate Write;	
		
		/// <summary>
		/// Main constructor of the DelegateWrapper class.
		/// </summary>
		/// <param name="write">The WriteDelegate delegate wrapped by this class</param>
		/// <param name="type">The DelegateType type indicating the Method wrapped
		/// by the delegate</param>
		public DelegateWrapper(WriteDelegate write,  DelegateTypes type)
		{
			Write=write;
			Type=type;
		}

		/// <summary>
		/// Method implementing the custom serialization policy
		/// </summary>
		/// <param name="Wire">The Stream on which the object has to be serialized</param>
		[CustomSerialize]
		private void Serialize(Stream Wire)
		{
			BinaryWriter BW=new BinaryWriter(Wire);
			BW.Write((byte)Type);
		}

		/// <summary>
		/// Method implementing the custom deserialization policy
		/// </summary>
		/// <param name="Wire">The stream from which the object has to be deserialized
		/// </param>
		[CustomDeserialize]
		private void Deserialize(Stream Wire)
		{
			BinaryReader BR=new BinaryReader(Wire);
			Type=(DelegateTypes)BR.ReadByte();
			switch(Type)
			{
				case DelegateTypes.WRITESCREEN: Write=new WriteDelegate(WriteScreen);break;
				default: Write=new WriteDelegate(WriteFile);break;
			}
		}
	}

}
