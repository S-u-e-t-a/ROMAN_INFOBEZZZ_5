using TeaCiphers.Padders;


namespace TeaTests.paddings.iso10126;

[TestClass]
public class Iso10126
{
    [TestMethod]
    public void ANSIX923PAD1()
    {
        byte[] block = new byte[] {0xDD,0xDD,0xDD,0xDD};
        
        var padder = new ISO10126Padder();
        var actual = padder.Pad(block, 8);
        var expectedLast = 4;
        var expectedLen = 8;
        Assert.AreEqual(expectedLast, actual[^1]);
        Assert.AreEqual(expectedLen, actual.Length);
    }
}
