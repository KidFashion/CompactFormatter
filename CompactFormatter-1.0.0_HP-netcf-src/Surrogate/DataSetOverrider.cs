// Decompiled with JetBrains decompiler
// Type: CompactFormatter.Surrogate.DataSetOverrider
// Assembly: CompactFormatter, Version=1.0.0.0, Culture=neutral, PublicKeyToken=381bc903a79da911
// MVID: 441F1A56-E151-4D2E-A949-A5723348B8D8
// Assembly location: C:\Users\agreenbhm\Desktop\ysoserial.net-2\ysoserial\bin\Debug\CompactFormatter.dll

using CompactFormatter.Attributes;
using CompactFormatter.Interfaces;
using System.Collections;
using System.Data;
using System.IO;

namespace CompactFormatter.Surrogate
{
  [Overrider(typeof (DataSet))]
  public class DataSetOverrider : IOverrider
  {
    public void Serialize(CompactFormatter parent, Stream serializationStream, object graph)
    {
      DataSet ds = (DataSet) graph;
      parent.Serialize(serializationStream, (object) ds.DataSetName);
      parent.Serialize(serializationStream, (object) ds.Namespace);
      parent.Serialize(serializationStream, (object) ds.Prefix);
      parent.Serialize(serializationStream, (object) ds.CaseSensitive);
      parent.Serialize(serializationStream, (object) ds.EnforceConstraints);
      parent.Serialize(serializationStream, (object) (DataTable[]) new ArrayList((ICollection) ds.Tables).ToArray(typeof (DataTable)));
      parent.Serialize(serializationStream, (object) this.GetForeignKeyConstraints(ds));
      parent.Serialize(serializationStream, (object) this.GetRelations(ds));
      parent.Serialize(serializationStream, (object) new ArrayList(ds.ExtendedProperties.Keys));
      parent.Serialize(serializationStream, (object) new ArrayList(ds.ExtendedProperties.Values));
    }

    private ArrayList GetForeignKeyConstraints(DataSet ds)
    {
      ArrayList arrayList1 = new ArrayList();
      for (int index1 = 0; index1 < ds.Tables.Count; ++index1)
      {
        DataTable table = ds.Tables[index1];
        for (int index2 = 0; index2 < table.Constraints.Count; ++index2)
        {
          Constraint constraint = table.Constraints[index2];
          ForeignKeyConstraint foreignKeyConstraint = constraint as ForeignKeyConstraint;
          if (foreignKeyConstraint != null)
          {
            string constraintName = constraint.ConstraintName;
            int[] numArray1 = new int[foreignKeyConstraint.RelatedColumns.Length + 1];
            numArray1[0] = ds.Tables.IndexOf(foreignKeyConstraint.RelatedTable);
            for (int index3 = 1; index3 < numArray1.Length; ++index3)
              numArray1[index3] = foreignKeyConstraint.RelatedColumns[index3 - 1].Ordinal;
            int[] numArray2 = new int[foreignKeyConstraint.Columns.Length + 1];
            numArray2[0] = index1;
            for (int index3 = 1; index3 < numArray2.Length; ++index3)
              numArray2[index3] = foreignKeyConstraint.Columns[index3 - 1].Ordinal;
            ArrayList arrayList2 = new ArrayList();
            arrayList2.Add((object) constraintName);
            arrayList2.Add((object) numArray1);
            arrayList2.Add((object) numArray2);
            arrayList2.Add((object) new int[3]
            {
              (int) foreignKeyConstraint.AcceptRejectRule,
              (int) foreignKeyConstraint.UpdateRule,
              (int) foreignKeyConstraint.DeleteRule
            });
            Hashtable hashtable = new Hashtable();
            if (foreignKeyConstraint.ExtendedProperties.Keys.Count > 0)
            {
              foreach (object key in (IEnumerable) foreignKeyConstraint.ExtendedProperties.Keys)
                hashtable.Add(key, foreignKeyConstraint.ExtendedProperties[key]);
            }
            arrayList2.Add((object) hashtable);
            arrayList1.Add((object) arrayList2);
          }
        }
      }
      return arrayList1;
    }

    private void SetForeignKeyConstraints(DataSet ds, ArrayList constraintList)
    {
      foreach (ArrayList constraint in constraintList)
      {
        string constraintName = (string) constraint[0];
        int[] numArray1 = (int[]) constraint[1];
        int[] numArray2 = (int[]) constraint[2];
        int[] numArray3 = (int[]) constraint[3];
        Hashtable hashtable = (Hashtable) constraint[4];
        DataColumn[] parentColumns = new DataColumn[numArray1.Length - 1];
        for (int index = 0; index < parentColumns.Length; ++index)
          parentColumns[index] = ds.Tables[numArray1[0]].Columns[numArray1[index + 1]];
        DataColumn[] childColumns = new DataColumn[numArray2.Length - 1];
        for (int index = 0; index < childColumns.Length; ++index)
          childColumns[index] = ds.Tables[numArray2[0]].Columns[numArray2[index + 1]];
        ForeignKeyConstraint foreignKeyConstraint = new ForeignKeyConstraint(constraintName, parentColumns, childColumns);
        foreignKeyConstraint.AcceptRejectRule = (AcceptRejectRule) numArray3[0];
        foreignKeyConstraint.UpdateRule = (Rule) numArray3[1];
        foreignKeyConstraint.DeleteRule = (Rule) numArray3[2];
        if (hashtable.Keys.Count > 0)
        {
          foreach (object key in (IEnumerable) hashtable.Keys)
            foreignKeyConstraint.ExtendedProperties.Add(key, hashtable[key]);
        }
        ds.Tables[numArray2[0]].Constraints.Add((Constraint) foreignKeyConstraint);
      }
    }

    private ArrayList GetRelations(DataSet ds)
    {
      ArrayList arrayList1 = new ArrayList();
      foreach (DataRelation relation in (InternalDataCollectionBase) ds.Relations)
      {
        string relationName = relation.RelationName;
        int[] numArray1 = new int[relation.ParentColumns.Length + 1];
        numArray1[0] = ds.Tables.IndexOf(relation.ParentTable);
        for (int index = 1; index < numArray1.Length; ++index)
          numArray1[index] = relation.ParentColumns[index - 1].Ordinal;
        int[] numArray2 = new int[relation.ChildColumns.Length + 1];
        numArray2[0] = ds.Tables.IndexOf(relation.ChildTable);
        for (int index = 1; index < numArray2.Length; ++index)
          numArray2[index] = relation.ChildColumns[index - 1].Ordinal;
        ArrayList arrayList2 = new ArrayList();
        arrayList2.Add((object) relationName);
        arrayList2.Add((object) numArray1);
        arrayList2.Add((object) numArray2);
        arrayList2.Add((object) relation.Nested);
        Hashtable hashtable = new Hashtable();
        if (relation.ExtendedProperties.Keys.Count > 0)
        {
          foreach (object key in (IEnumerable) relation.ExtendedProperties.Keys)
            hashtable.Add(key, relation.ExtendedProperties[key]);
        }
        arrayList2.Add((object) hashtable);
        arrayList1.Add((object) arrayList2);
      }
      return arrayList1;
    }

    private void SetRelations(DataSet ds, ArrayList relationList)
    {
      foreach (ArrayList relation1 in relationList)
      {
        string relationName = (string) relation1[0];
        int[] numArray1 = (int[]) relation1[1];
        int[] numArray2 = (int[]) relation1[2];
        bool flag = (bool) relation1[3];
        Hashtable hashtable = (Hashtable) relation1[4];
        DataColumn[] parentColumns = new DataColumn[numArray1.Length - 1];
        for (int index = 0; index < parentColumns.Length; ++index)
          parentColumns[index] = ds.Tables[numArray1[0]].Columns[numArray1[index + 1]];
        DataColumn[] childColumns = new DataColumn[numArray2.Length - 1];
        for (int index = 0; index < childColumns.Length; ++index)
          childColumns[index] = ds.Tables[numArray2[0]].Columns[numArray2[index + 1]];
        DataRelation relation2 = new DataRelation(relationName, parentColumns, childColumns, false);
        relation2.Nested = flag;
        if (hashtable.Keys.Count > 0)
        {
          foreach (object key in (IEnumerable) hashtable.Keys)
            relation2.ExtendedProperties.Add(key, hashtable[key]);
        }
        ds.Relations.Add(relation2);
      }
    }

    public object Deserialize(CompactFormatter parent, Stream serializationStream)
    {
      DataSet ds = new DataSet((string) parent.Deserialize(serializationStream));
      ds.Namespace = (string) parent.Deserialize(serializationStream);
      ds.Prefix = (string) parent.Deserialize(serializationStream);
      ds.CaseSensitive = (bool) parent.Deserialize(serializationStream);
      ds.EnforceConstraints = (bool) parent.Deserialize(serializationStream);
      foreach (DataTable table in (DataTable[]) parent.Deserialize(serializationStream))
        ds.Tables.Add(table);
      ArrayList constraintList = (ArrayList) parent.Deserialize(serializationStream);
      this.SetForeignKeyConstraints(ds, constraintList);
      ArrayList relationList = (ArrayList) parent.Deserialize(serializationStream);
      this.SetRelations(ds, relationList);
      ArrayList arrayList1 = (ArrayList) parent.Deserialize(serializationStream);
      ArrayList arrayList2 = (ArrayList) parent.Deserialize(serializationStream);
      for (int index = 0; index < arrayList1.Count; ++index)
        ds.ExtendedProperties.Add(arrayList1[index], arrayList2[index]);
      return (object) ds;
    }
  }
}
