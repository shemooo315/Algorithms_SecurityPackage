using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Ceaser : ICryptographicTechnique<string, int>
    {
        string alphabetic = "abcdefghijklmnopqrstuvwxyz";
        public int Letter_Index(char letter)
        {
            for(int i=0;i<alphabetic.Length;i++)
            {
                if (letter == alphabetic[i])
                    return i;
            }
            return 0;
        }
        public string Encrypt(string plainText, int key)
        {
           char[] characters = new char[] { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z' };
            int sizeofplaintext = plainText.Length;
            char[] charsofplaintext = new char[sizeofplaintext];
            char[] charsofciphertext = new char[sizeofplaintext];
            for (int k = 0; k < sizeofplaintext; k++)
            {
                charsofplaintext[k] = plainText[k];
            }
            int i = 0;
            while (  i < sizeofplaintext)
            {
              var temp =  charsofplaintext[i];

                int bit = Array.IndexOf(characters, temp);
                int newbit = (key + bit) % 26;
                char newchar = characters[newbit];


                charsofciphertext[i] = newchar;

                i++;

            }
            string cipherMessage = String.Join("", charsofciphertext);
            return cipherMessage;
        }

        public string Decrypt(string cipherText, int key)
        {
            cipherText = cipherText.ToLower();
            char[] characters = new char[] { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z' };
            int sizeofciphertext = cipherText.Length;
            char[] charsofplaintext = new char[sizeofciphertext];
            char[] charsofciphertext = new char[sizeofciphertext];
            for (int k = 0; k < sizeofciphertext; k++)
            {
                charsofciphertext[k] = cipherText[k];
            }
            int i = 0;
            while (i < sizeofciphertext)
            {
                var temp = charsofciphertext[i];

                int bit = Array.IndexOf(characters, temp);
                int newbit = (bit - key) % 26;
                if (newbit < 0)
                {
                    newbit += 26;
                }
                char newchar = characters[newbit];


                charsofplaintext[i] = newchar;
                i++;


            }
            string plain = String.Join("", charsofplaintext);
            return plain;
        }

        public int Analyse(string plainText, string cipherText)
        {
        
            int plaintxt_letter = Letter_Index(plainText[0]);
            int ciphertxt_letter = Letter_Index(char.ToLower(cipherText[0]));
            int key=(ciphertxt_letter-plaintxt_letter);
            if (key < 0)
            {
                key = key +26;
            }
            else
            {
                key = key % 26;
            }
            

            return key;

        }
    }
}
