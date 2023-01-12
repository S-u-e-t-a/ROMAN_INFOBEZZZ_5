namespace TeaCiphers.Encoders;

public class XTEACipher:TeaCipher
{
    protected override void encrypt(uint[] v, uint[] k)
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
        
        for (int i=0; i < 64; i++) {
            v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + k[sum & 3]);
            sum += delta;
            v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + k[(sum>>11) & 3]);
        }

        v[0] = v0;
        v[1] = v1;
    }
    
    protected override void decrypt(uint[] v, uint[] k)
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
        
        uint sum = delta*64;
        
        for (int i=0; i < 64; i++) {
            v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + k[(sum>>11) & 3]);
            sum -= delta;
            v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + k[sum & 3]);
        }

        v[0] = v0;
        v[1] = v1; 
    }

}
