// Decompiled with JetBrains decompiler
// Type: CompactFormatter.Interfaces.IStreamParser
// Assembly: CompactFormatter, Version=1.0.0.0, Culture=neutral, PublicKeyToken=381bc903a79da911
// MVID: 441F1A56-E151-4D2E-A949-A5723348B8D8
// Assembly location: C:\Users\agreenbhm\Desktop\ysoserial.net-2\ysoserial\bin\Debug\CompactFormatter.dll

using System.IO;

namespace CompactFormatter.Interfaces
{
  public abstract class IStreamParser : Stream
  {
    protected Stream str;

    public override bool CanRead
    {
      get
      {
        return this.str.CanRead;
      }
    }

    public override bool CanWrite
    {
      get
      {
        return this.str.CanWrite;
      }
    }

    public override void Flush()
    {
      this.str.Flush();
    }

    public override int Read(byte[] buffer, int offset, int len)
    {
      return this.ParseInput(ref buffer, offset, len);
    }

    public override void Write(byte[] buffer, int offset, int len)
    {
      this.ParseOutput(ref buffer, offset, len);
    }

    public override bool CanSeek
    {
      get
      {
        return this.str.CanSeek;
      }
    }

    public override long Length
    {
      get
      {
        return this.str.Length;
      }
    }

    public override long Position
    {
      get
      {
        return this.str.Position;
      }
      set
      {
        this.str.Position = value;
      }
    }

    public override void SetLength(long len)
    {
      this.str.SetLength(len);
    }

    public override long Seek(long pos, SeekOrigin from)
    {
      return this.str.Seek(pos, from);
    }

    public Stream InnerStream
    {
      set
      {
        this.str = value;
      }
    }

    protected abstract void ParseOutput(ref byte[] buffer, int offset, int len);

    protected abstract int ParseInput(ref byte[] buffer, int offset, int len);
  }
}
