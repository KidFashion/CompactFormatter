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

namespace Serialization.Formatters.Test
{
	
	delegate void MyDelegate(int i);

	/// <summary>
	/// Summary description for DelegateType.
	/// </summary>
	
	public class DelegateType
	{
		MyDelegate Scrivi;	
		
		public DelegateType()
		{
			Scrivi=new MyDelegate(ScriviInt);
		}

		public void TryDelegate()
		{
			Scrivi(12);
		}
		public static void ScriviInt(int i)
		{

			FileStream FS=new System.IO.FileStream("log.txt",System.IO.FileMode.Append);
			
			Console.WriteLine("Numero ricevuto: {0}",i);
		}
	}
}
