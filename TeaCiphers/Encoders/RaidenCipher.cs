namespace TeaCiphers.Encoders;

public class RaidenCipher: TeaCipher
{
    protected override void encrypt(uint[] v, uint[] key)
    {
        uint b0 = v[0], b1 = v[1] , sk;
        var k = new[]
            {key[0],key[1],key[2],key[3]};
        
        int i;

        
        for (i = 0; i < 16; i++)
        {
            sk  = k[i%4] = ((k[0]+k[1])+((k[2]+k[3])^(k[0]<<(int) (k[2] & 0x1F))));
            b0 += ((sk+b1)<<9) ^ ((sk-b1)^((sk+b1)>>14));
            b1 += ((sk+b0)<<9) ^ ((sk-b0)^((sk+b0)>>14));
        }
        v[0] = b0;
        v[1] = b1;
    }
    
    protected override void decrypt(uint[] v, uint[] key)
    {
        uint b0 = v[0], b1 = v[1];
        var k = new[]
            {key[0],key[1],key[2],key[3]};
        var subkeys = new uint[16];
        int i;

        for (i = 0; i < 16; i++) subkeys[i] = k[i%4] = ((k[0]+k[1])+((k[2]+k[3])^(k[0]<<(int) (k[2] & 0x1F))));

        for (i = 15; i >= 0; i--)
        {
            b1 -= ((subkeys[i]+b0)<<9) ^ ((subkeys[i]-b0)^((subkeys[i]+b0)>>14));
            b0 -= ((subkeys[i]+b1)<<9) ^ ((subkeys[i]-b1)^((subkeys[i]+b1)>>14));
        }
        v[0] = b0;
        v[1] = b1;
    }

    
}
