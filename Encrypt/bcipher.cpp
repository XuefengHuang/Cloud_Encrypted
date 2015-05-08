#include <sstream>
#include <fstream>
#include <iostream>
#include <iomanip>
#include <stdio.h>
#include <string>
#include "cryptopp/osrng.h"
#include "cryptopp/modes.h"
#include "cryptopp/aes.h"
#include "cryptopp/filters.h"
#include "cryptopp/rsa.h"
#include "cryptopp/pssr.h"
#include <cryptopp/base64.h>
#include "bcipher.h"
#include "hexa.h"
#include "hashmac.h"
#include "sha256.h"
#include <cryptopp/files.h>

using namespace CryptoPP;

void BCipher::encrypt(std::string keyfile,std::string filename,std::string savefilename){
	AutoSeededRandomPool rnd;

	// Generate a random key
	byte key[AES::MAX_KEYLENGTH];
	memset( key, 0x00, CryptoPP::AES::MAX_KEYLENGTH );
	rnd.GenerateBlock(key, AES::MAX_KEYLENGTH);

	// Generate a random IV
	byte iv[AES::BLOCKSIZE];
	memset( iv, 0x00, CryptoPP::AES::BLOCKSIZE );
	rnd.GenerateBlock(iv, AES::BLOCKSIZE);

	Hexa b;
	std::string plaintext = b.hex_to_string_decoder(filename);
	unsigned char *ciphertext= new unsigned char[plaintext.size()+1];
	ciphertext[plaintext.size()]='\0';

	// Convert the key to hex and save it to key.txt file
	std::ofstream outkey(keyfile.c_str());
	outkey << b.byte_to_hex_encoder(key,AES::MAX_KEYLENGTH);

	// Convert the iv to hex and save it to key.txt file
	outkey << b.byte_to_hex_encoder(iv,AES::BLOCKSIZE);
	outkey.close();

        std::cout<<"Encrypt file using AES256 CFB mode..."<<std::endl;

	// Run AES encryption in CFB Mode
	CFB_Mode<AES>::Encryption cfbEncryption(key, AES::MAX_KEYLENGTH, iv);
	cfbEncryption.ProcessData(ciphertext,(unsigned char*)(plaintext.c_str()),plaintext.size()+1);

	// Save the encrypted contents to file
	std::ofstream out(savefilename.c_str());
	out << b.byte_to_hex_encoder(ciphertext,plaintext.size());
	out.close();

	std::cout<<"Performing HMAC using SHA256 on file:"<<savefilename<<std::endl;
	HashMac h;
	h.generate_hmac(keyfile,savefilename,"hmac_"+savefilename);
}

// Perform SHA256 and store to file
void BCipher::sha256_pre(std::string filename,std::string savefilename){
        std::cout<<"Performing SHA256 on filename:"<<savefilename<<std::endl;
	std::ifstream in(filename.c_str());
	std::stringstream ss;
	ss<< in.rdbuf();
	std::string input = ss.str();
	in.close();

        SHA256_new sha256;
	std::string myHash = sha256(input);
	std::ofstream out(savefilename.c_str());
	out << myHash;
	out.close();
}

// Signature and append to file.txt
void BCipher::signature(std::string content,std::string filename){
        std::ofstream outfile(filename.c_str(), std::ios_base::app);
        outfile << content;
        outfile.close();
}

void BCipher::generateRSAkeys(){
	std::cout<<"Generating RSA keys for sender..."<<std::endl;
	// Generate keys
	AutoSeededRandomPool rng;

	InvertibleRSAFunction params;
	params.GenerateRandomWithKeySize(rng, 3072);

	RSA::PrivateKey privateKey(params);
	RSA::PublicKey publicKey(params);
{
        FileSink output("sender_private.dat");
        privateKey.DEREncode(output);
}
{
        FileSink output("sender_public.dat");
        publicKey.DEREncode(output);
}
        std::cout<<"Produce sender_private.dat and sender_public.dat" <<std::endl;
}


