namespace TeaCiphers.Encoders;

public interface ICipher
{
    public byte[] Key { get; set; }
    public void Encode(byte[] inputBlock, int inputOffset, byte[] outputBlock, int outputOffset);
    public void Decode(byte[] inputBlock, int inputOffset, byte[] outputBlock, int outputOffset);
}
