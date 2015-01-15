/*
 * PreProcess.cpp
 *
 *  Created on: Dec 2, 2014
 *      Author: hps
 */


#include <stdlib.h>
#include <stdio.h>
#include <iostream>
#include <functional>
#include <string>
#include <fstream>
#include <sstream>
#include <stdlib.h>
#include <string.h>
#include "aes256.h"
#include "sha256.h"

using namespace std;


union
{
    unsigned long integer;
    unsigned char byte[8];
} keyForEncrypt;


#ifndef BUFSIZE
#define BUFSIZE 1024
#endif

int totalLen = 0, newLen = 0;

int i = 0;


void preprocess ();

#define DUMP(s, i, buf, sz)  {printf(s);                   \
                              for (i = 0; i < (sz);i++)    \
                                  printf("%02x ", buf[i]); \
                              printf("\n");}

//char *KeyFileName = "Password";
char *Key;
char *FileNameOriginal;
char *FileNameShared;

int main (int argc, char *argv[])
{
//	cout << ">>>>>>>>>>>>>>>>>>>>" << endl;
//	cout << "Pre Processing" << endl;

	if(argc != 3) {
		cout << "Usage: PreProcess <filename> <passkey>\n";
	}

	FileNameOriginal = argv[1];
	Key = argv[2];
	//KeyFileName = Key;

	preprocess();

    return 0;
} /* main */

/*
./preprocess    key.txt   file.txt   filename.txt   (returning files efile.txt and efilename.txt)
./authorize    key.txt    filename.txt   (returning files fkey.txt  and sfilename.txt)
./recover    efile.txt   efilename.txt  fkey.txt  (returning file sfile.txt)

*/


char *ReadFile(char *filename) {
    ifstream infile;
    //cout << "Reading " << filename << endl;
    infile.open(filename, ifstream::binary);

    infile.seekg (0,infile.end);
	totalLen = infile.tellg();
	infile.seekg (0);


	// allocate memory for file content
	char* buffer = new char[totalLen];
	// read content of infile
	infile.read (buffer,totalLen);

	infile.close();

//    printf("total_length: %ld\n",total_len);

    return buffer;
}


// returns FileNameEncrypted.txt and FileNameEncrypted
void preprocess () {

	hash <string> strHash;
	unsigned char fileKey[32];
	const char *fileKeyString;
	string keyPart;
	char *buf;
    unsigned char *newbuf, *inputptr;
    aes256_context ctx;
    ofstream outfile;
    int padding = 0;
    SHA256 sha256;

    //string key = KeyFileName;
    string FileIn = FileNameOriginal;

    char *FileOut = (char *)sha256(FileNameOriginal).c_str();

    fileKeyString = sha256(Key+FileIn).c_str();

    for (i=0; i<32; i++) {
    	fileKey[i] = *fileKeyString;
    	fileKeyString = fileKeyString+2;
    }

	buf = ReadFile(FileNameOriginal);

	padding = 16 - (totalLen %16);
	//cout << "Padding: " << padding << endl;
	newbuf = (unsigned char *) malloc(totalLen + padding);

	for(i = 0; i< totalLen; i++) {
		newbuf[i] = buf[i];
	}

	for(i=0; i< padding; i++) {
		newbuf[totalLen + i] = padding;
	}

	inputptr = newbuf;

	aes256_init(&ctx, fileKey);

	//DUMP("txt: ", i, inputptr, totalLen + padding);

	for(i=0; i< totalLen + padding;) {
		aes256_encrypt_ecb(&ctx, newbuf);
		i = i + 16;
		newbuf = newbuf + 16;
	}

	//DUMP("enc: ", i, inputptr, totalLen + padding);
	//DUMP("key: ", i, fileKey, sizeof(fileKey));
	//cout <<"Encrypted: "<< inputptr << endl;

	newbuf = inputptr;

	FileNameShared = FileOut;
	outfile.open(FileOut, ofstream::binary);
	outfile.write ((char *)newbuf,totalLen+ padding);
	outfile.close();

	cout << "Encrypted File created with file name: " << FileNameShared << endl;
	cout << "Please share the Original Filename ("<<FileNameOriginal << ") \nand Passkey(" << Key << ") with your friends.\n";
	//cout << "Ask them to download the encrypted file: " << FileNameShared << " from the cloud\n";

	/*
	aes256_init(&ctx, fileKey);

	cout << "Total Length: " << totalLen + padding << endl;

	for(int i=0;i<totalLen + padding;) {
		aes256_decrypt_ecb(&ctx, newbuf);
		newbuf = newbuf + 16;
		i = i + 16;
	}

	newbuf = inputptr;

	DUMP("dec: ", i, inputptr, totalLen + padding);

	cout <<"Decrypted: "<< inputptr << endl;
	*/
	aes256_done(&ctx);

}


