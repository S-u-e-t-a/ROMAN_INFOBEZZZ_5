using System.Security.Cryptography;


namespace TeaCiphers;

public class TeaCryptoTransform : ICryptoTransform
{
    private static uint delta = 0x9e3779b9;

    //key size = 128 bit, 16 bytes, 4 uint
    //block size = 64 bit, 8 bytes, 2 uint
    public TeaCryptoTransform(byte[] rgbKey, byte[]? rgbIV, bool encryption)
    {
        key = rgbKey;
        iv = rgbIV;
        _encryption = encryption;
        var k1 = BitConverter.ToUInt32(key);
        var k2 = BitConverter.ToUInt32(key,4);
        var k3 = BitConverter.ToUInt32(key,8);
        var k4 = BitConverter.ToUInt32(key,12);
        intKey = new[] {k1, k2,k3,k4};
    }

    private uint[] intKey;
    private byte[] key;
    private byte[] iv;
    private readonly bool _encryption;

    public void Dispose()
    {
        throw new NotImplementedException();
    }

    public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
    {
        var v = inputBuffer[new Range(inputOffset, inputOffset + 8)];
        var v1 = BitConverter.ToUInt32(v);
        var v2 = BitConverter.ToUInt32(v,4);
        var vInt = new uint[] {v1, v2};

        if (_encryption)
        {
            encrypt(vInt,intKey);
        }
        else
        {
            decrypt(vInt,intKey);
        }
        
        BitConverter.GetBytes(vInt[0]).CopyTo(v,0);
        BitConverter.GetBytes(vInt[1]).CopyTo(v,4);

        for (int i = 0; i < 8; i++)
        {
            outputBuffer[outputOffset + i] = v[i];
        }

        return 8;
    }

    public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
    {
        var v = inputBuffer[new Range(inputOffset, inputOffset + 8)];
        var v1 = BitConverter.ToUInt32(v);
        var v2 = BitConverter.ToUInt32(v,4);
        var vInt = new uint[] {v1, v2};
        
        if (_encryption)
        {
            encrypt(vInt,intKey);
        }
        else
        {
            decrypt(vInt,intKey);
        }
        
        BitConverter.GetBytes(vInt[0]).CopyTo(v,0);
        BitConverter.GetBytes(vInt[1]).CopyTo(v,4);

        return v;

    }

    private void encrypt(uint[] v, uint[] k)
    {
        if (v.Length != 2)
        {
            throw new ArgumentException("v length must be 2");
        }
        if (k.Length != 4)
        {
            throw new ArgumentException("k length must be 4");
        }
        var v0 = v[0];
        var v1 = v[1];
        
        uint sum = 0;

        var k0 = k[0];
        var k1 = k[1];
        var k2 = k[2];
        var k3 = k[3];
        
        for( int i = 0; i < 32; ++i )
        {
            sum += delta;
            v0 += ( ( v1 << 4 ) + k0 ) ^ ( v1 + sum ) ^ ( ( v1 >> 5 ) + k1 );
            v1 += ( ( v0 << 4 ) + k2 ) ^ ( v0 + sum ) ^ ( ( v0 >> 5 ) + k3 );
        }

        v[0] = v0;
        v[1] = v1;
    }

    private void decrypt(uint[] v, uint[] k)
    {
        if (v.Length != 2)
        {
            throw new ArgumentException("v length must be 2");
        }
        if (k.Length != 4)
        {
            throw new ArgumentException("k length must be 4");
        }
        var v0 = v[0];
        var v1 = v[1];
        
        uint sum = 0xC6EF3720;

        var k0 = k[0];
        var k1 = k[1];
        var k2 = k[2];
        var k3 = k[3];
        
        for ( int i = 0; i < 32; ++i )
        {                              
            v1 -= ( ( v0 << 4 ) + k2 ) ^ ( v0 + sum ) ^ ( ( v0 >> 5 ) + k3 );
            v0 -= ( ( v1 << 4 ) + k0 ) ^ ( v1 + sum ) ^ ( ( v1 >> 5 ) + k1 );
            sum -= delta;                                   
        }

        v[0] = v0;
        v[1] = v1;
    }
    public bool CanReuseTransform { get; }
    public bool CanTransformMultipleBlocks { get; }
    public int InputBlockSize { get; } = 8;
    public int OutputBlockSize { get; } = 8;
}
