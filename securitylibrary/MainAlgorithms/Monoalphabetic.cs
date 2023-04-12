using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {
        string alphabetic = "abcdefghijklmnopqrstuvwxyz";


        public string Analyse(string plainText, string cipherText)
        {
            string Key = "";

            int PTlength = plainText.Length;
            int alphalength=alphabetic.Length;
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();

            Dictionary<char, bool> alphabetic_list = new Dictionary<char, bool>();
            SortedDictionary<char,char> permutation_table= new SortedDictionary<char, char>();
            


            for (int i=0;i<PTlength;i++)
            {
                for (int j = 0; j < alphalength; j++)
                {
                    if(!permutation_table.ContainsKey(plainText[i]))
                    {
                        permutation_table.Add(plainText[i],cipherText[i]);
                        alphabetic_list.Add(cipherText[i], true);
                    }
                }
            }

            if(permutation_table.Count !=26)
            {
                for(int i=0;i<26;i++)
                {
                    if(!permutation_table.ContainsKey(alphabetic[i]))
                    {
                        for (int k = 0; k < 26; k++)
                        {
                            if (!alphabetic_list.ContainsKey(alphabetic[k]))
                            {
                                permutation_table.Add(alphabetic[i], alphabetic[k]);
                                alphabetic_list.Add( alphabetic[k], true);
                                k = 26;
                            }
                        }
                    }
                }
            }
            foreach (var element in permutation_table)
            {
                Key += element.Value;
            }
            return Key;
        }




        public string Decrypt(string cipherText, string key)
        {
            cipherText = cipherText.ToLower();
            int CTlength = cipherText.Length;
            int keylenght = key.Length;
            string PT = "";

            for (int j = 0; j < CTlength; j++)
            {
                for (int i = 0; i < keylenght; i++)
                {
                    if (cipherText[j] == key[i])
                    {
                        PT += alphabetic[i];
                    }
                }
            }
            return PT;

        }

        public string Encrypt(string plainText, string key)
        {
            int PTlength = plainText.Length;
            int alphLenght = alphabetic.Length;
            string CT = "";

            for (int j = 0; j < PTlength; j++)
            {
                for (int i = 0; i < alphLenght; i++)
                {
                    if (plainText[j] == alphabetic[i])
                    {
                        CT += key[i];
                    }
                }
            }
            return CT.ToUpper();

        }

        /// <summary>
        /// Frequency Information:
        /// E   12.51%
        /// T	9.25
        /// A	8.04
        /// O	7.60
        /// I	7.26
        /// N	7.09
        /// S	6.54
        /// R	6.12
        /// H	5.49
        /// L	4.14
        /// D	3.99
        /// C	3.06
        /// U	2.71
        /// M	2.53
        /// F	2.30
        /// P	2.00
        /// G	1.96
        /// W	1.92
        /// Y	1.73
        /// B	1.54
        /// V	0.99
        /// K	0.67
        /// X	0.19
        /// J	0.16
        /// Q	0.11
        /// Z	0.09
        /// </summary>
        /// <param name="cipher"></param>
        /// <returns>Plain text</returns>
        public string AnalyseUsingCharFrequency(string cipher)
        {
           int c = 0;
            cipher = cipher.ToLower();
            string keyyy = "";
            Dictionary<char, int> frequencyAlphabiticsDic = new Dictionary<char, int>();
            SortedDictionary<char, char> keydictionary = new SortedDictionary<char, char>();
            string frequencyalphabitics = "ETAOINSRHLDCUMFPGWYBVKXJQZ".ToLower();
            int j = 0;
            while (j< cipher.Length) {

                if (frequencyAlphabiticsDic.ContainsKey(cipher[j]))
                 {
                    frequencyAlphabiticsDic[cipher[j]]++;

                }
                else {

                    frequencyAlphabiticsDic.Add(cipher[j], 0);

                }

                j++;
            }
            frequencyAlphabiticsDic = frequencyAlphabiticsDic.OrderBy(x => x.Value).Reverse().ToDictionary(x => x.Key, x => x.Value);

            foreach (var item in frequencyAlphabiticsDic)
            {
                keydictionary.Add(item.Key, frequencyalphabitics[c]);
                c++;
            }

            int i = 0;
            while (i<cipher.Length)
            {
                keyyy = keyyy + keydictionary[cipher[i]];

                i++;
            }
            return keyyy;
        }
    }
}
