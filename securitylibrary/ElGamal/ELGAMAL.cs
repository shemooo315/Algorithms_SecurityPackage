using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.ElGamal
{
    public class ElGamal
    {
        /// <summary>
        /// Encryption
        /// </summary>
        /// <param name="alpha"></param>
        /// <param name="q"></param>
        /// <param name="y"></param>
        /// <param name="k"></param>
        /// <returns>list[0] = C1, List[1] = C2</returns>
        public int power(int Base, int power, int mod)
        {
            int rst = 1;
            for (int i = 0; i < power; i++)
            {
                rst = (rst * Base) % mod;

            }
            return rst;
        }

        public List<long> Encrypt(int q, int alpha, int y, int k, int m)
        {
            List<long> cipherText = new List<long>();

            // result = y ^ k % q;
            // c1 =alpha^k %q;
            // c2 =result*m%q;
            int result = power(y, k, q);
            int c1 = power(alpha, k, q);
            int c2 = (result * m) % q;
            cipherText.Add(c1);
            cipherText.Add(c2);
            return cipherText;
        }
        public int Decrypt(int c1, int c2, int x, int q)
        {
            int k = 1, M=1 ;
            for (int i = 0; i < x; i++)
            {
                k = (k * c1)%q;
            }
            for (int i = 1; i <= q; i++)
            {
                if (((k * i) % q) == 1)
                {
                    M = i;
                }
            }
            M = (c2 * M) % q;
            return M;
        }
    }
}
