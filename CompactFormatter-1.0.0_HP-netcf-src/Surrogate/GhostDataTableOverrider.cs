// Decompiled with JetBrains decompiler
// Type: CompactFormatter.Surrogate.GhostDataTableOverrider
// Assembly: CompactFormatter, Version=1.0.0.0, Culture=neutral, PublicKeyToken=381bc903a79da911
// MVID: 441F1A56-E151-4D2E-A949-A5723348B8D8
// Assembly location: C:\Users\agreenbhm\Desktop\ysoserial.net-2\ysoserial\bin\Debug\CompactFormatter.dll

using CompactFormatter.Attributes;
using CompactFormatter.Interfaces;
using System;
using System.Collections;
using System.Data;
using System.IO;

namespace CompactFormatter.Surrogate
{
  [Overrider(typeof (DataTable))]
  public class GhostDataTableOverrider : IOverrider
  {
    public void Serialize(CompactFormatter parent, Stream serializationStream, object graph)
    {
      ArrayList arrayList1 = new ArrayList();
      ArrayList arrayList2 = new ArrayList();
      ArrayList arrayList3 = new ArrayList();
      DataTable dataTable = (DataTable) graph;
      foreach (DataColumn column in (InternalDataCollectionBase) dataTable.Columns)
      {
        arrayList1.Add((object) column.ColumnName);
        arrayList2.Add((object) TypeExtensions.FullName(column.DataType));
      }
      foreach (DataRow row in (InternalDataCollectionBase) dataTable.Rows)
        arrayList3.Add((object) row.ItemArray);
      parent.Serialize(serializationStream, (object) arrayList1);
      parent.Serialize(serializationStream, (object) arrayList2);
      parent.Serialize(serializationStream, (object) arrayList3);
    }

    public object Deserialize(CompactFormatter parent, Stream serializationStream)
    {
      ArrayList arrayList1 = (ArrayList) parent.Deserialize(serializationStream);
      ArrayList arrayList2 = (ArrayList) parent.Deserialize(serializationStream);
      ArrayList arrayList3 = (ArrayList) parent.Deserialize(serializationStream);
      DataTable dataTable = new DataTable();
      for (int index = 0; index < arrayList1.Count; ++index)
      {
        DataColumn column = new DataColumn(arrayList1[index].ToString(), Type.GetType(arrayList2[index].ToString()));
        dataTable.Columns.Add(column);
      }
      for (int index = 0; index < arrayList3.Count; ++index)
      {
        DataRow row = dataTable.NewRow();
        row.ItemArray = (object[]) arrayList3[index];
        dataTable.Rows.Add(row);
      }
      dataTable.AcceptChanges();
      return (object) dataTable;
    }
  }
}
