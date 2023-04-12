using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class AutokeyVigenere : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {

            cipherText = cipherText.ToLower();
            plainText = plainText.ToLower();
            string key = "";
            int cipherLength = cipherText.Length;
            char[,] matrixalpha = { {' ','a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y','z'},
                                    {'a', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y','z'},
                                    { 'b','b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z','a'},
                                    { 'c', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z','a','b'},
                                    { 'd', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z','a','b','c'},
                                    { 'e','e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z','a','b','c','d'},
                                    { 'f','f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z','a','b','c','d','e'},
                                    {'g','g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z','a','b','c','d','e','f'},
                                    { 'h','h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z','a','b','c','d','e','f','g'},
                                    { 'i','i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z','a','b','c','d','e','f','g','h'},
                                    {  'j', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z','a','b','c','d','e','f','g','h','i'},
                                    { 'k','k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z','a','b','c','d','e','f','g','h','i','j'},
                                    {'l','l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z','a','b','c','d','e','f','g','h','i', 'j', 'k'},
                                    { 'm','m', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z','a','b','c','d','e','f','g','h','i', 'j', 'k','l'},
                                    {'n','n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z','a','b','c','d','e','f','g','h','i', 'j', 'k', 'l', 'm'},
                                    {'o', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z','a','b','c','d','e','f','g','h','i', 'j', 'k','l', 'm', 'n'},
                                    {'p', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z','a','b','c','d','e','f','g','h','i', 'j', 'k','l', 'm', 'n', 'o'},
                                    {'q', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z','a','b','c','d','e','f','g','h','i', 'j', 'k','l', 'm', 'n','o', 'p'},
                                    {  'r', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z','a','b','c','d','e','f','g','h','i', 'j', 'k','l', 'm', 'n', 'o', 'p', 'q'},
                                    {'s','s', 't', 'u', 'v', 'w', 'x', 'y', 'z','a','b','c','d','e','f','g','h','i', 'j', 'k','l', 'm', 'n', 'o', 'p', 'q','r'},
                                    {'t', 't', 'u', 'v', 'w', 'x', 'y', 'z','a','b','c','d','e','f','g','h','i', 'j', 'k','l', 'm', 'n', 'o', 'p', 'q', 'r', 's'},
                                    { 'u',  'u', 'v', 'w', 'x', 'y', 'z','a','b','c','d','e','f','g','h','i', 'j', 'k','l', 'm', 'n', 'o', 'p', 'q','r', 's', 't'},
                                    { 'v','v', 'w', 'x', 'y', 'z','a','b','c','d','e','f','g','h','i', 'j', 'k','l', 'm', 'n', 'o', 'p', 'q','r', 's', 't', 'u'},
                                    {'w', 'w', 'x', 'y', 'z','a','b','c','d','e','f','g','h','i', 'j', 'k','l', 'm', 'n', 'o', 'p', 'q','r', 's', 't','u', 'v'},
                                    { 'x','x', 'y', 'z','a','b','c','d','e','f','g','h','i', 'j', 'k','l', 'm', 'n', 'o', 'p', 'q','r', 's', 't','u', 'v', 'w'},
                                     {'y', 'y', 'z','a','b','c','d','e','f','g','h','i', 'j', 'k','l', 'm', 'n', 'o', 'p', 'q','r', 's', 't','u', 'v', 'w','x'},
                                    {'z','z','a','b','c','d','e','f','g','h','i', 'j', 'k','l', 'm', 'n', 'o', 'p', 'q','r', 's', 't','u', 'v', 'w','x', 'y'},

            };

            int count = 0;
            while (count < cipherLength)
            {
                int indexcol = 0, row = 0;
                for (int i = 1; i < 27; i++)
                {
                    if (matrixalpha[i, 0] == plainText[count])
                    {
                        row = i;
                        break;
                    }

                }
                for (int i = 1; i < 27; i++)
                {

                    if (matrixalpha[i, row] == cipherText[count])
                    {
                        indexcol = i;
                        break;
                    }
                }

                key += matrixalpha[indexcol, 0];
                count++;
            }
            string finalkey = "";
            char[] key2 = new char[key.Length];


            for (int i = 0; i < key.Length; i++)
            {
                if (i < 3)
                {
                    key2[i] = key[i];

                }
                else
                {
                    int j = 0;
                    if (plainText[j].Equals(key[i]))
                    {
                        if (plainText[j + 1].Equals(key[i + 1]) && plainText[j + 2].Equals(key[i + 2]))
                        {
                            break;
                        }
                        else
                        {
                            key2[i] = key[i];
                        }

                    }
                    else
                    {
                        key2[i] = key[i];
                    }

                }

            }
            for (int O = 0; O < key2.Length; O++)
            {
                if (key2[O] != '\0')
                {
                    finalkey += key2[O];
                }
            }
            return finalkey;
            throw new NotImplementedException();
        }

        public string Decrypt(string cipherText, string key)
        {
            cipherText = cipherText.ToLower();
            string plain = "";
            int cipherLength = cipherText.Length;
            // int lenkey = key.Length;
            char[,] matrixalpha = { {' ','a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y','z'},
                                    {'a', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y','z'},
                                    { 'b','b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z','a'},
                                    { 'c', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z','a','b'},
                                    { 'd', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z','a','b','c'},
                                    { 'e','e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z','a','b','c','d'},
                                    { 'f','f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z','a','b','c','d','e'},
                                    {'g','g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z','a','b','c','d','e','f'},
                                    { 'h','h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z','a','b','c','d','e','f','g'},
                                    { 'i','i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z','a','b','c','d','e','f','g','h'},
                                    {  'j', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z','a','b','c','d','e','f','g','h','i'},
                                    { 'k','k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z','a','b','c','d','e','f','g','h','i','j'},
                                    {'l','l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z','a','b','c','d','e','f','g','h','i', 'j', 'k'},
                                    { 'm','m', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z','a','b','c','d','e','f','g','h','i', 'j', 'k','l'},
                                    {'n','n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z','a','b','c','d','e','f','g','h','i', 'j', 'k', 'l', 'm'},
                                    {'o', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z','a','b','c','d','e','f','g','h','i', 'j', 'k','l', 'm', 'n'},
                                    {'p', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z','a','b','c','d','e','f','g','h','i', 'j', 'k','l', 'm', 'n', 'o'},
                                    {'q', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z','a','b','c','d','e','f','g','h','i', 'j', 'k','l', 'm', 'n','o', 'p'},
                                    {  'r', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z','a','b','c','d','e','f','g','h','i', 'j', 'k','l', 'm', 'n', 'o', 'p', 'q'},
                                    {'s','s', 't', 'u', 'v', 'w', 'x', 'y', 'z','a','b','c','d','e','f','g','h','i', 'j', 'k','l', 'm', 'n', 'o', 'p', 'q','r'},
                                    {'t', 't', 'u', 'v', 'w', 'x', 'y', 'z','a','b','c','d','e','f','g','h','i', 'j', 'k','l', 'm', 'n', 'o', 'p', 'q', 'r', 's'},
                                    { 'u',  'u', 'v', 'w', 'x', 'y', 'z','a','b','c','d','e','f','g','h','i', 'j', 'k','l', 'm', 'n', 'o', 'p', 'q','r', 's', 't'},
                                    { 'v','v', 'w', 'x', 'y', 'z','a','b','c','d','e','f','g','h','i', 'j', 'k','l', 'm', 'n', 'o', 'p', 'q','r', 's', 't', 'u'},
                                    {'w', 'w', 'x', 'y', 'z','a','b','c','d','e','f','g','h','i', 'j', 'k','l', 'm', 'n', 'o', 'p', 'q','r', 's', 't','u', 'v'},
                                    { 'x','x', 'y', 'z','a','b','c','d','e','f','g','h','i', 'j', 'k','l', 'm', 'n', 'o', 'p', 'q','r', 's', 't','u', 'v', 'w'},
                                     {'y', 'y', 'z','a','b','c','d','e','f','g','h','i', 'j', 'k','l', 'm', 'n', 'o', 'p', 'q','r', 's', 't','u', 'v', 'w','x'},
                                    {'z','z','a','b','c','d','e','f','g','h','i', 'j', 'k','l', 'm', 'n', 'o', 'p', 'q','r', 's', 't','u', 'v', 'w','x', 'y'},

            };

            int nump = 0;
            int count = 0;
            while (count < cipherLength)
            {
                int index = 0, col = 0;
                for (int i = 1; i < 27; i++)
                {
                    if (matrixalpha[0, i] == key[count])
                    {
                        col = i;
                        break;
                    }

                }
                for (int i = 1; i < 27; i++)
                {

                    if (matrixalpha[col, i] == cipherText[count])
                    {
                        index = i;
                        break;
                    }
                }

                plain += matrixalpha[0, index];
                count++;

                if (key.Length < cipherLength)
                {
                    key += plain[nump];
                    nump++;

                }





            }


            return plain;
            throw new NotImplementedException();
        }

        public string Encrypt(string plainText, string key)
        {
            string cipher = "";
            int plainlength = plainText.Length;
            int keylength = key.Length;
            char[,] matrixalpha = { {' ','a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y','z'},
                                    {'a', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y','z'},
                                    { 'b','b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z','a'},
                                    { 'c', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z','a','b'},
                                    { 'd', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z','a','b','c'},
                                    { 'e','e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z','a','b','c','d'},
                                    { 'f','f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z','a','b','c','d','e'},
                                    {'g','g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z','a','b','c','d','e','f'},
                                    { 'h','h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z','a','b','c','d','e','f','g'},
                                    { 'i','i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z','a','b','c','d','e','f','g','h'},
                                    {  'j', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z','a','b','c','d','e','f','g','h','i'},
                                    { 'k','k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z','a','b','c','d','e','f','g','h','i','j'},
                                    {'l','l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z','a','b','c','d','e','f','g','h','i', 'j', 'k'},
                                    { 'm','m', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z','a','b','c','d','e','f','g','h','i', 'j', 'k','l'},
                                    {'n','n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z','a','b','c','d','e','f','g','h','i', 'j', 'k', 'l', 'm'},
                                    {'o', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z','a','b','c','d','e','f','g','h','i', 'j', 'k','l', 'm', 'n'},
                                    {'p', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z','a','b','c','d','e','f','g','h','i', 'j', 'k','l', 'm', 'n', 'o'},
                                    {'q', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z','a','b','c','d','e','f','g','h','i', 'j', 'k','l', 'm', 'n','o', 'p'},
                                    {  'r', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z','a','b','c','d','e','f','g','h','i', 'j', 'k','l', 'm', 'n', 'o', 'p', 'q'},
                                    {'s','s', 't', 'u', 'v', 'w', 'x', 'y', 'z','a','b','c','d','e','f','g','h','i', 'j', 'k','l', 'm', 'n', 'o', 'p', 'q','r'},
                                    {'t', 't', 'u', 'v', 'w', 'x', 'y', 'z','a','b','c','d','e','f','g','h','i', 'j', 'k','l', 'm', 'n', 'o', 'p', 'q', 'r', 's'},
                                    { 'u',  'u', 'v', 'w', 'x', 'y', 'z','a','b','c','d','e','f','g','h','i', 'j', 'k','l', 'm', 'n', 'o', 'p', 'q','r', 's', 't'},
                                    { 'v','v', 'w', 'x', 'y', 'z','a','b','c','d','e','f','g','h','i', 'j', 'k','l', 'm', 'n', 'o', 'p', 'q','r', 's', 't', 'u'},
                                    {'w', 'w', 'x', 'y', 'z','a','b','c','d','e','f','g','h','i', 'j', 'k','l', 'm', 'n', 'o', 'p', 'q','r', 's', 't','u', 'v'},
                                    { 'x','x', 'y', 'z','a','b','c','d','e','f','g','h','i', 'j', 'k','l', 'm', 'n', 'o', 'p', 'q','r', 's', 't','u', 'v', 'w'},
                                     {'y', 'y', 'z','a','b','c','d','e','f','g','h','i', 'j', 'k','l', 'm', 'n', 'o', 'p', 'q','r', 's', 't','u', 'v', 'w','x'},
                                    {'z','z','a','b','c','d','e','f','g','h','i', 'j', 'k','l', 'm', 'n', 'o', 'p', 'q','r', 's', 't','u', 'v', 'w','x', 'y'},

            };




            if (keylength < plainlength)
            {
                int numrepeatalphapitics = plainlength - keylength;
                int sizenewkey = numrepeatalphapitics + keylength;
                char[] newkeychar = new char[sizenewkey];

                for (int i = 0; i < numrepeatalphapitics; i++)
                {

                    key += plainText[i];
                }

            }
            int count = 0;
            while (count < plainlength)
            {
                int row = 0, col = 0;
                for (int i = 1; i < 27; i++)
                {
                    if (matrixalpha[0, i] == key[count])
                    {
                        col = i;
                        break;
                    }

                }
                for (int i = 1; i < 27; i++)
                {

                    if (matrixalpha[i, 0] == plainText[count])
                    {
                        row = i;
                        break;
                    }

                }
                cipher += matrixalpha[row, col];
                count++;
            }
            return cipher;
        }
    }
}

