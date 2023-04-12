using System;
using System.Collections.Generic;

namespace SecurityLibrary.DiffieHellman
{
    public class DiffieHellman
    {   // No Need Only trying
        public List<int> numbersprimefactorization(int power)
        {

            int counter1 = 0;
            List<int> arr_factoriesnumber = new List<int>();

            while (power % 2 == 0)
            {
                power = power / 2;

            }
            for (int num = 0; num <= Math.Sqrt(power); num = num + 2)
            {
                while (power % num == 0)
                {
                    arr_factoriesnumber[counter1] = num;
                    power = power / num;
                    counter1++;
                }
            }
            if (power > 2)
            {
                arr_factoriesnumber[counter1] = power;
            }
            return arr_factoriesnumber;
        }
        public List<int> GetKeys(int q, int alpha, int xa, int xb)
        {

            List<int> Key_listforhillman = new List<int>();

            int Y_AUser = 1;
            int Y_BUser = 1;
            int finalkey1 = 1;
            int finalkey2 = 1;
            // List<int> arr1_factoriesnumber = numbersprimefactorization(xa);
            // List<int> arr2_factoriesnumber = numbersprimefactorization(xb);
            int num_loop1 = 0;
            int num_loop2 = 0;
            while (num_loop1 < xa)
            {
                Y_AUser = (Y_AUser * alpha) % q;
                num_loop1 = num_loop1 + 1;


            }
            while (num_loop2 < xb)
            {
                Y_BUser = (Y_BUser * alpha) % q;
                num_loop2 = num_loop2 + 1;


            }

            // Y_BUser = (Y_BUser * alpha) % q;

            for (int i = 0; i < xa; i++)
            {
                finalkey1 = (finalkey1 * Y_BUser) % q;

            }
            Key_listforhillman.Add(finalkey1);

            for (int i = 0; i < xb; i++)
            {
                finalkey2 = (finalkey2 * Y_AUser) % q;


            }
            Key_listforhillman.Add(finalkey2);


            return Key_listforhillman;
            throw new NotImplementedException();
        }
    }
}