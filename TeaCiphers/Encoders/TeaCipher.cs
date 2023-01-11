namespace TeaCiphers.Encoders;

public class TeaCipher: ICipher
{
    private static uint delta = 0x9e3779b9;

    public int Encode(byte[] key, ReadOnlySpan<byte> inputBuffer, Span<byte> outputBuffer)
    {
        var v = inputBuffer.ToArray();
        var v1 = BitConverter.ToUInt32(v);
        var v2 = BitConverter.ToUInt32(v,4);
        var vInt = new uint[] {v1, v2};
        var k1 = BitConverter.ToUInt32(key);
        var k2 = BitConverter.ToUInt32(key,4);
        var k3 = BitConverter.ToUInt32(key,8);
        var k4 = BitConverter.ToUInt32(key,12);
        var intKey = new[] {k1, k2,k3,k4};
        encrypt(vInt,intKey);
        BitConverter.GetBytes(vInt[0]).CopyTo(v,0);
        BitConverter.GetBytes(vInt[1]).CopyTo(v,4);
        for (int i = 0; i < 8; i++)
        {
            outputBuffer[i] = v[i];
        }

        return 8; 
    }

    public int Decode(byte[] key, ReadOnlySpan<byte> inputBuffer, Span<byte> outputBuffer)
    {
        var v = inputBuffer.ToArray();
        var v1 = BitConverter.ToUInt32(v);
        var v2 = BitConverter.ToUInt32(v,4);
        var vInt = new uint[] {v1, v2};
        var k1 = BitConverter.ToUInt32(key);
        var k2 = BitConverter.ToUInt32(key,4);
        var k3 = BitConverter.ToUInt32(key,8);
        var k4 = BitConverter.ToUInt32(key,12);
        var intKey = new[] {k1, k2,k3,k4};
        decrypt(vInt,intKey);
        BitConverter.GetBytes(vInt[0]).CopyTo(v,0);
        BitConverter.GetBytes(vInt[1]).CopyTo(v,4);
        for (int i = 0; i < 8; i++)
        {
            outputBuffer[i] = v[i];
        }
        return 8; 

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
}
