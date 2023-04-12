using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class TripleDES : ICryptographicTechnique<string, List<string>>
    {
        DES obj_tocallmethod = new DES();
        public string Decrypt(string cipherText, List<string> key)
        {
            string output1_Enc = obj_tocallmethod.Decrypt(cipherText, key[0]);
            string output2_Dec = obj_tocallmethod.Encrypt(output1_Enc, key[1]);
            string output3_final = obj_tocallmethod.Decrypt(output2_Dec, key[1]);


            return output3_final;
        }

        public string Encrypt(string plainText, List<string> key)
        {

            string output1_Enc = obj_tocallmethod.Encrypt(plainText, key[0]);
            string output2_Dec = obj_tocallmethod.Decrypt(output1_Enc, key[1]);
            string output3_final = obj_tocallmethod.Encrypt(output2_Dec, key[1]);

            return output3_final;
        }

        public List<string> Analyse(string plainText, string cipherText)
        {
            throw new NotSupportedException();
        }

    }
}
