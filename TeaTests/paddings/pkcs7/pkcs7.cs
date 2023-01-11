using TeaCiphers.Padders;


namespace TeaTests.paddings.pkcs7;
[TestClass]

public class pkcs7
{
    [TestMethod]
    public void pad1()
    {
        byte[] block = new byte[] {0xDD,0xDD,0xDD,0xDD};
        
        var padder = new PKCS7Padder();
        var actual = padder.Pad(block, 8);
        byte[] expected = new byte[] {0xDD,0xDD,0xDD,0xDD,4,4,4,4};
        CollectionAssert.AreEqual(expected, actual);
    }
    [TestMethod]
    public void pad2()
    {
        byte[] block = new byte[] {0xDD,0xDD,0xDD,0xDD};
        
        var padder = new PKCS7Padder();
        var actual = padder.Pad(block, 4);
        byte[] expected = new byte[] {0xDD,0xDD,0xDD,0xDD,4,4,4,4};
        CollectionAssert.AreEqual(expected, actual);
    }
}
