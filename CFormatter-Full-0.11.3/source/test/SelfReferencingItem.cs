using System;

namespace Serialization.Formatters.Test
{
	/// <summary>
	/// Object used during test of serialization of self-referenced items.
	/// </summary>
	[Serialization.Formatters.Serializable]
	public class SelfReferencingItem
	{

		/// <summary>
		/// Reference to itself.
		/// </summary>
		SelfReferencingItem me;

		int seed;
		
		/// <summary>
		/// Parameterless constructor requested by CompactFormatter
		/// </summary>
		public SelfReferencingItem()
		{
			me=this;
			this.seed=0;
		}

		public SelfReferencingItem(int seed)
		{
			me=this;
			this.seed=seed;
		}

		public override bool Equals(Object obj)
		{
			if (obj.GetType()!=typeof(SelfReferencingItem)) return false;
			else
			{
				if(this.me==this && ((SelfReferencingItem)obj).me==((SelfReferencingItem)obj) && this.seed==((SelfReferencingItem)obj).seed) return true;
				else return false;
			}
		}
	}
}
