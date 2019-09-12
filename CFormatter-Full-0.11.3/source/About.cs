using System;

namespace CFormatter.Utils
{
	/// <summary>
	/// Class containing versioning information about the project
	/// </summary>
	public class About
	{

		/// <summary>
		/// Date of last modify at the package.
		/// </summary>
		private static DateTime Date=new DateTime(2003,12,22);

		/// <summary>
		/// Represents the codename of the project.
		/// </summary>
		private const String codename = "Monga";
		/// <summary>
		/// Major version number.
		/// </summary>
		private const Int32 Major = 0;
		
		/// <summary>
		/// Minor version number.
		/// </summary>
		private const Int32 Minor = 11;

		/// <summary>
		/// Build version number.
		/// </summary>
		private const Int32 Build = 3;

		/// <summary>
		/// String containing the name of the project
		/// </summary>
		private const String Name = "CompactFormatter";


		/// <summary>
		/// returns a string representing the Peerware Version in the format:
		/// MAJOR.MINOR.BUILD
		/// </summary>
		public static String Version
		{
			get
			{
				return Major+"."+Minor+"."+Build;
			}
		}

		/// <summary>
		/// a string containing the newline character sequence
		/// </summary>
		private const string NewLine="\r\n";

		/// <summary>
		/// Returns a string containing all information about the currently used version of Project.
		/// </summary>
		public static String AboutString
		{
			get
			{
				String about=Name+" V"+Version+NewLine+"Codename:"+codename+NewLine+"Modified:"+Date.ToString("d")+NewLine;
				return about;
			}
		}

	}
}
