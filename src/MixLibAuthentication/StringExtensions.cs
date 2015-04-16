using System;
using System.Collections.Generic;

namespace MixLibAuthentication
{
    public static class StringExtensions
    {
        public static IEnumerable<string> Split(this string str, int chunkSize)
        {
            for (var i = 0; i < str.Length; i += chunkSize)
                yield return str.Substring(i, Math.Min(chunkSize, str.Length - i));
        }
    }
}
