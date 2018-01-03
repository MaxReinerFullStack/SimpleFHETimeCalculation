#include "FHE.h"
#include <time.h>

int main(int argc, char **argv)
{
	/*** BEGIN INITIALIZATION ***/
	long m = 0;                   // Specific modulus
	long p = 1021;                // Plaintext base [default=2], should be a prime number
	long r = 1;                   // Lifting [default=1]
	long L = 16;                  // Number of levels in the modulus chain [default=heuristic]
	long c = 3;                   // Number of columns in key-switching matrix [default=2]
	long w = 32;                  // Hamming weight of secret key
	long d = 0;                   // Degree of the field extension [default=1]
	long k = 128;                 // Security parameter [default=80] 
	long s = 0;                   // Minimum number of slots [default=0]
	string output;

	std::cout << "Finding m... " << std::flush;
	m = FindM(k, L, c, p, d, s, 0);                            // Find a value for m given the specified values
	std::cout << "m = " << m << std::endl;
	
	std::cout << "Initializing context... " << std::flush;
	FHEcontext context(m, p, r); 	                        // Initialize context
	buildModChain(context, L, c);                           // Modify the context, adding primes to the modulus chain
	std::cout << "OK!" << std::endl;

	std::cout << "Creating polynomial... " << std::flush;
	ZZX G =  context.alMod.getFactorsOverZZ()[0];                // Creates the polynomial used to encrypt the data
	std::cout << "OK!" << std::endl;

	std::cout << "Generating keys... " << std::flush;
	FHESecKey secretKey(context);                           // Construct a secret key structure
	const FHEPubKey& publicKey = secretKey;                 // An "upcast": FHESecKey is a subclass of FHEPubKey
	secretKey.GenSecKey(w);                                 // Actually generate a secret key with Hamming weight w
	std::cout << "OK!" << std::endl;
	/*** END INITIALIZATION ***/
	
	Ctxt ctx1(publicKey);                // Initialize the first ciphertext (ctx1) using publicKey
	Ctxt ctx2(publicKey);                // Initialize the first ciphertext (ctx2) using publicKey
	Ctxt ctx3(publicKey); 
	Ctxt ctx4(publicKey); 

	int sumvalue = 4;
	int multiplicator = 5;
	publicKey.Encrypt(ctx1, to_ZZX(multiplicator));  // Encrypt the value 5
	publicKey.Encrypt(ctx2, to_ZZX(sumvalue)); 
	publicKey.Encrypt(ctx3, to_ZZX(sumvalue));
	publicKey.Encrypt(ctx4, to_ZZX(sumvalue));


	Ctxt ctSum = ctx1;                   // Create a ciphertext to hold the sum and initialize it with Enc(2)
	ZZX ptSum;                           // Create a plaintext to hold the plaintext of the sum


	output = to_string(multiplicator)+" * (";
	for (int i= 0;i<5;i++)
	{
		clock_t tStart = clock();
		ctSum = ctx1;

		ctSum *= ctx3;                       // Perform Enc(5) * Enc(4+4+4+...)
		ctx3+=ctx2;
		if (i>0) output+= " + ";
		output += to_string(sumvalue);
		std::cout << output << ") "<< std::endl;
		printf("Time taken: %.2fs\n", (double)(clock() - tStart)/CLOCKS_PER_SEC);
	        secretKey.Decrypt(ptSum, ctSum);         // Decrypt the ciphertext ctSum into the plaintext ptSum using secretKey
        	std::cout << "Result: " << ptSum[0] << std::endl;
	}

	ctSum = ctx1; 
	ctx3 = ctx4;

	output = to_string(multiplicator)+" * ";
        for (int i= 0;i<3;i++)
        {
                clock_t tStart = clock();
                ctSum = ctx1;

                ctSum *= ctx3;                       // Perform Enc(5) * Enc(4) * Enc(4) * ..
                ctx3*=ctx4;

                if (i>0) output+= " * ";
                output += to_string(sumvalue);
                std::cout << output << " "<< std::endl;
                printf("Time taken: %.2fs\n", (double)(clock() - tStart)/CLOCKS_PER_SEC);
                secretKey.Decrypt(ptSum, ctSum);         // Decrypt the ciphertext ctSum into the plaintext ptSum using secretKey
                std::cout << "Result: " << ptSum[0] << std::endl;
        }


	return 0;
}
