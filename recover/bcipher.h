#ifndef __BCIPHER_H_INCLUDED_
#define __BCIPHER_H_INCLUDED_

class BCipher{
public:
	void decrypt(std::string fkfile,std::string filename, std::string encryptedfile,std::string decryptedfile,std::string content,std::string signature);
        void generateRSAkeys();
        void sha256_pre(std::string filename,std::string savefilename);
        void authorize(std::string filename);
        std::string signature(std::string content);
        void verify_signature(std::string content,std::string signature);
};
#endif
