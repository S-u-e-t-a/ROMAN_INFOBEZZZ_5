using TeaCiphers.Padders;


namespace TeaTests.paddings.ansix923;

[TestClass]
public class UnitTest1
{
    [TestMethod]
    public void ANSIX923PAD1()
    {
        byte[] block = new byte[] {0xDD,0xDD,0xDD,0xDD};
        
        var padder = new ANSIX923Padder();
        var actual = padder.Pad(block, 8);
        byte[] expected = new byte[] {0xDD,0xDD,0xDD,0xDD,0,0,0,4};
        CollectionAssert.AreEqual(expected, actual);
    }
    [TestMethod]
    public void ANSIX923PAD2()
    {
        byte[] block = new byte[] {0xDD,0xDD,0xDD,0xDD};
        
        var padder = new ANSIX923Padder();
        var actual = padder.Pad(block, 4);
        byte[] expected = new byte[] {0xDD,0xDD,0xDD,0xDD,0,0,0,4};
        CollectionAssert.AreEqual(expected, actual);
    }
    [TestMethod]
    public void ANSIX923Depad1()
    {
        // byte[] block = new byte[] {0xDD,0xDD,0xDD,1};
        //
        // var padder = new ANSIX923Padder();
        // var actual = padder.Depad(block);
        // byte[] expected = new byte[] {0xDD,0xDD,0xDD};
        // CollectionAssert.AreEqual(expected, actual);
    }
    [TestMethod]
    public void ANSIX923Depad2()
    {
        // byte[] block = new byte[] {0,0,0,4};
        //
        // var padder = new ANSIX923Padder();
        // var actual = padder.Depad(block);
        // byte[] expected = null;
        // CollectionAssert.AreEqual(expected, actual);
    }
    [TestMethod]
    public void ANSIX923Depad3()
    {
        // byte[] block = new byte[] {1,1,0,2};
        //
        // var padder = new ANSIX923Padder();
        // var actual = padder.Depad(block);
        // byte[] expected = new byte[] {1,1};
        // CollectionAssert.AreEqual(expected, actual);
    }
}
