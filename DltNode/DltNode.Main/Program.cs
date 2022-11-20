using System;
using System.Text;
using DltNode.Hash;

namespace DltNode.Main
{
	class Program
	{
		static void Main(string[] args)
		{
			PureHash keccak = new PureHash();
			byte[] input= Encoding.UTF8.GetBytes("hello, world");
			var qwe = keccak.ComputeHash(input);
			Console.WriteLine(BitConverter.ToString(qwe));
		}
	}
}
