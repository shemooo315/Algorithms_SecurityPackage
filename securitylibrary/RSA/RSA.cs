using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.RSA
{
    public class RSA
    {
        int multiplicative_inverse(int number, int Base)
        {
            int A1 = 1, A2 = 0, A3 = Base;
            int B1 = 0, B2 = 1, B3 = number;

            while (B3 != 1)
            {
                int x = (A3 / B3);
                int K = A1 - (x * B1); int L = A2 - (x * B2);
                int M = A3 - (x * B3);

                A1 = B1;
                A2 = B2;
                A3 = B3;
                B1 = K;
                B2 = L;
                B3 = M;
            }
            if (B3 == 1)
            {
                B2 = B2 < -1 ? B2 + Base : B2;
            }

            return B2;
        }
        public int Encrypt(int p, int q, int M, int e)
        {
            int CT;
            int n = p * q;
            int result = 1;
            for (int i = 0; i < e; i++)
            {
                result = ((result * M) % n);
            }
            CT = (result % n);
            return CT;
        }

        public int Decrypt(int p, int q, int C, int e)
        {
            int PT;
            int n = p * q;
            int euler = (p - 1) * (q - 1);
            //int d = ((1 / e)%euler);
            int result = 1;
            e = multiplicative_inverse(e, euler);
            for (int i = 0; i < e; i++)
            {
                result = ((result * C) % n);
            }
            PT = (result % n);
            return PT;
        }
    }
}

