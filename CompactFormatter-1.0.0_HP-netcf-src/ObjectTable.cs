// Decompiled with JetBrains decompiler
// Type: CompactFormatter.ObjectTable
// Assembly: CompactFormatter, Version=1.0.0.0, Culture=neutral, PublicKeyToken=381bc903a79da911
// MVID: 441F1A56-E151-4D2E-A949-A5723348B8D8
// Assembly location: C:\Users\agreenbhm\Desktop\ysoserial.net-2\ysoserial\bin\Debug\CompactFormatter.dll

using System.Collections;

namespace CompactFormatter
{
  public class ObjectTable
  {
    private ArrayList mItems = new ArrayList();
    private Hashtable mItemsIndex = new Hashtable();

    public ObjectTable(int c)
    {
      this.mItems = new ArrayList(c);
      this.mItemsIndex = new Hashtable(c);
    }

    public int AddPlaceholder()
    {
      return this.mItems.Add((object) null);
    }

    public int Add(object o)
    {
      int num = this.mItems.Add(o);
      this.mItemsIndex[o] = (object) num;
      return num;
    }

    public void Clear()
    {
      this.mItems.Clear();
      this.mItemsIndex.Clear();
    }

    public int Contains(object o)
    {
      if (!this.mItemsIndex.ContainsKey(o))
        return -1;
      return (int) this.mItemsIndex[o];
    }

    public int IndexOf(object o)
    {
      if (!this.mItemsIndex.ContainsKey(o))
        return -1;
      return (int) this.mItemsIndex[o];
    }

    public object Get(int i)
    {
      return this.mItems[i];
    }

    public void AddAtPlace(int i, object o)
    {
      this.mItems[i] = o;
      this.mItemsIndex[o] = (object) i;
    }
  }
}
