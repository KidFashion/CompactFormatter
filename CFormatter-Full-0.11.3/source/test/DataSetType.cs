using System;
using System.Data;
using System.Data.SqlClient;
using System.Drawing;
using System.Windows.Forms;

namespace Serialization.Formatters.Test
{

	public class DataSetType
	{
		DataSet ds;

		public DataSet DSet
		{
			get
			{
				return ds;
			}
		}

		public DataSetType()
		{
			InitializeComponent();
		}

		void InitializeComponent()
		{
			ConnectToData();
		}

		void ConnectToData()
		{
			//Create a fake DataSet to test CompactFormatter serialization      
			DataSet ds = new  DataSet("MyTestDataSet");
			ds.Tables.Add();
			ds.Tables[0].Columns.Add("Nome");
			object[] temp={"Hello"};
			ds.Tables[0].Rows.Add(temp);
			Console.WriteLine("Done");
		}

	}
}