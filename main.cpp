#include "FHE.h"
#include <time.h>
#include "EncryptedArray.h"

int main(int argc, char **argv)
{
	/*** BEGIN INITIALIZATION ***/
	clock_t tStart = clock();
	long m = 0;                   // Specific modulus
	long p = 1021;                // Plaintext base [default=2], should be a prime number
	long r = 1;                   // Lifting [default=1]
	long L = 16;                  // Number of levels in the modulus chain [default=heuristic]
	long c = 3;                   // Number of columns in key-switching matrix [default=2]
	long w = 64;                  // Hamming weight of secret key
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
	
	printf("Time taken for initialization: %.2fs\n", (double)(clock() - tStart)/CLOCKS_PER_SEC);
	tStart = clock();

	Ctxt ctx1(publicKey);                // Initialize the first ciphertext (ctx1) using publicKey
	Ctxt ctx2(publicKey);                // Initialize the first ciphertext (ctx2) using publicKey
	Ctxt ctx3(publicKey); 
	Ctxt ctx4(publicKey); 

	int sumvalue = 4;
	int multiplicator = 5;
	publicKey.Encrypt(ctx1, to_ZZX(multiplicator));  // Encrypt the value 5
	publicKey.Encrypt(ctx2, to_ZZX(sumvalue));       // Encrypt the value 4
	publicKey.Encrypt(ctx3, to_ZZX(sumvalue));
	publicKey.Encrypt(ctx4, to_ZZX(sumvalue));


	Ctxt ctSum = ctx1;                   // Create a ciphertext to hold the sum and initialize it with Enc(2)
	ZZX ptSum;                           // Create a plaintext to hold the plaintext of the sum

	printf("Time taken for creating ciphertext: %.2fs\n", (double)(clock() - tStart)/CLOCKS_PER_SEC);

	output = to_string(multiplicator)+" * (";
	for (int i= 0;i<5;i++)
	{
		tStart = clock();
		ctSum = ctx1;

		ctSum *= ctx3;                       // Perform Enc(5) * (Enc(4) + Enc(4) + Enc(4) + ...)
		ctx3+=ctx2;
		if (i>0) output+= " + ";
		output += to_string(sumvalue);
		std::cout << "Perform Enc(5) * (Enc(4) + Enc(4) + Enc(4) + ...) => " << output << ") "<< std::endl;
		printf("Time taken: %.2fs\n", (double)(clock() - tStart)/CLOCKS_PER_SEC);
	        secretKey.Decrypt(ptSum, ctSum);         // Decrypt the ciphertext ctSum into the plaintext ptSum using secretKey
        	std::cout << "Result: " << ptSum[0] << std::endl;
	}

	ctSum = ctx1; 
	ctx3 = ctx4;

	output = to_string(multiplicator)+" * ";
        for (int i= 0;i<3;i++)
        {
                tStart = clock();
                ctSum = ctx1;

                ctSum *= ctx3;                       // Perform Enc(5) * Enc(4) * Enc(4) * ..
                ctx3*=ctx4;

                if (i>0) output+= " * ";
                output += to_string(sumvalue);
                std::cout << "Perform Enc(5) * Enc(4) * Enc(4) * ...=> " << output << " "<< std::endl;
                printf("Time taken: %.2fs\n", (double)(clock() - tStart)/CLOCKS_PER_SEC);
                secretKey.Decrypt(ptSum, ctSum);         // Decrypt the ciphertext ctSum into the plaintext ptSum using secretKey
                std::cout << "Result: " << ptSum[0] << std::endl;
        }
	ctSum = ctx1; 
        ctx3 = ctx4;

        output = "Using multByConstant "+ to_string(multiplicator)+" * ";
        for (int i= 0;i<3;i++)
        {
                tStart = clock();
                ctSum = ctx1;

                ctSum *= ctx3;
                ctx3.multByConstant(to_ZZX(4));		// Perform Enc(5) * Enc(4) * Enc(4) * ...


                if (i>0) output+= " * ";
                output += to_string(sumvalue);
                std::cout << output << " "<< std::endl;
                printf("Time taken: %.2fs\n", (double)(clock() - tStart)/CLOCKS_PER_SEC);
                secretKey.Decrypt(ptSum, ctSum);         // Decrypt the ciphertext ctSum into the plaintext ptSum using secretKey
                std::cout << "Result: " << ptSum[0] << std::endl;
        }



	ctSum = ctx1;
        ctx3 = ctx4;

	// using reLineration
	output = "Using relineration "+ to_string(multiplicator)+" * ";
	for (int i= 0;i<3;i++)
        {
                tStart = clock();
                ctSum = ctx1;

                ctSum.multiplyBy(ctx3);

                ctx3.multiplyBy(ctx4);

                if (i>0) output+= " * ";
                output += to_string(sumvalue);
                std::cout << output << " "<< std::endl;
                printf("Time taken: %.2fs\n", (double)(clock() - tStart)/CLOCKS_PER_SEC);
                secretKey.Decrypt(ptSum, ctSum);         // Decrypt the ciphertext ctSum into the plaintext ptSum using secretKey
                std::cout << "Result: " << ptSum[0] << std::endl;
        }

	// Sample code: Pack into coefficients

	tStart = clock();
	long v[4] = {1,2,3,4};
	long u[4] = {1,2,3,4};
	ZZX V, U;
	V.SetLength(4);
	U.SetLength(4);
	for (int i = 0; i<4;i++) {
		SetCoeff(V, i, v[i]);
		SetCoeff(U, 3 - i, u[i]);
	}
	// V = 1 + 2x + 3x^2 + 4x^3
	// U = 4 + 3x + 2x^3 + 1x^3
	printf("\nPack into coefficients.\nV = 1 + 2x + 3x^2 + 4x^3\nU = 4 + 3x + 2x^3 + 1x^3\n" );
	Ctxt encV(publicKey), encU(publicKey);

	publicKey.Encrypt(encV, V);
	publicKey.Encrypt(encU, U);
	// encV * encU;
	printf("Pack into coefficients. Time taken for encryption: %.2fs\n", (double)(clock() - tStart)/CLOCKS_PER_SEC);

	encV.multiplyBy(encU);
	ZZX result;
	printf("Pack into coefficients. Time taken for calculation:\nencV * encU: %.2fs\n", (double)(clock() - tStart)/CLOCKS_PER_SEC);

	secretKey.Decrypt(result,encV);
	printf("Pack into coefficients. Time taken for decryption: %.2fs\n", (double)(clock() - tStart)/CLOCKS_PER_SEC);
	cout << "Result " << result[2]  << std::endl; // 3rd coeff, 30 mod p^r

	// Codes for CRT-packing

	std::vector<long> u1 = {1, 2, 3, 4};
	std::vector<long> v1 = {4, 3, 2, 1};
	//ZZX F = context.alMod.getFactorsOverZZ()[0];

	EncryptedArray ea(context, G);

	//Ctxt encvU(publicKey);
	//ZZX  ZV, ZU;
	//ea.encode (ZV, v1); ea.encode(ZU, u1);
	// V = ??, U = ??
	//publicKey.Encrypt(encV, Z); publicKey.Encrypt(encU, Z);
	//ea.encrypt(encV, publicKey, v1); ea.encrypt(encU, publicKey, u1);
	tStart = clock();
	encV *= encU;
	printf("CRT packing. Time taken for calculation:\nencV * encU: %.2fs\n", (double)(clock() - tStart)/CLOCKS_PER_SEC);
	//ZZX result;
	secretKey.Decrypt(result, encV); // result = ??
	std::vector<long> decoded;
	ea.decode(decoded, result); // decoded = {4, 6, 6, 4};
	//ea.decode(ea, decoded, secretKey, encV);
	cout << "Result: " << decoded  << std::endl; 

	// Sample codes for other HELib routines

	//Ctxt encU(publicKey);
/**	
	ea.encrypt(encU, publicKey, u1);
	ea.rotate(encU, 1);
	ea.rotate(encU, -2);
	ea.shift(encU, 1);

	runningSums(ea, encU);
	totalSums(ea, encU);**/

	return 0;
}
