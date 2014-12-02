/*  
*   Byte-oriented AES-256 implementation.
*   All lookup tables replaced with 'on the fly' calculations. 
*
*   Copyright (c) 2007 Ilya O. Levin, http://www.literatecode.com
*
*   Permission to use, copy, modify, and distribute this software for any
*   purpose with or without fee is hereby granted, provided that the above
*   copyright notice and this permission notice appear in all copies.
*
*   THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
*   WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
*   MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
*   ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
*   WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
*   ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
*   OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
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


void preprocess (char *KeyFileName, char *FileNameOriginal);
void authorize (char *SharedKeyFileName, char *FileNameShared);
void recover (char *FileNameFromCloud, char *FileNameShared, char *SharedFileKeyFileName);
void recover2 (char *FileNameFromCloud, char *FileNameShared, char *SharedFileKeyFileName);

#define DUMP(s, i, buf, sz)  {printf(s);                   \
                              for (i = 0; i < (sz);i++)    \
                                  printf("%02x ", buf[i]); \
                              printf("\n");}

char *KeyFileName = "Password";
char *FileNameOriginal = "Original.txt";
char *FileNameShared = "Shared.txt";

int main (int argc, char *argv[])
{

	cout << "Pre Processing" << endl;
    preprocess(KeyFileName,FileNameOriginal);

    cout << ">>>>>>>>>>>>>>>>>>>>" << endl;
    cout << "Recovering" << endl;
    recover2(FileNameShared, FileNameShared, KeyFileName);
    return 0;
} /* main */

/*
./preprocess    key.txt   file.txt   filename.txt   (returning files efile.txt and efilename.txt)
./authorize    key.txt    filename.txt   (returning files fkey.txt  and sfilename.txt)
./recover    efile.txt   efilename.txt  fkey.txt  (returning file sfile.txt)

*/


char *ReadFile(char *filename) {
    ifstream infile;
    cout << "Reading " << filename << endl;
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
void preprocess (char *KeyFileName, char *FileNameOriginal) {

	hash <string> strHash;
	unsigned char fileKey[32];
	const char *fileKeyString;
	string keyPart;
	char *buf;
    unsigned char *newbuf, *inputptr;
    aes256_context ctx;
    ofstream outfile;
    int padding = 0;

    /*
	keyForEncrypt.integer = strHash(KeyFileName);
	keyPart = to_string(keyForEncrypt.integer);

	cout << "Size of Key (int): " << sizeof(keyForEncrypt.integer) << endl;
	cout << "Size of Key (byte): " << sizeof(keyForEncrypt.byte) << endl;
	cout << "Size of fileKey: " << sizeof(fileKey) << endl;
	cout << "Size of Key Part: " << sizeof(keyPart) << endl;
	cout << "Size of an element in Key Part array: " << sizeof(keyPart[0]) << endl;

	cout << "Key Part Bytes:\n";
	for (int i = 0; i < 24;i++) {
		//printf("%02x ", keyPart[i]);
		fileKey[i] = keyPart[i];

	}

	for (int i=0; i<8; i++) {
		fileKey[i+24] = keyForEncrypt.byte[i];
	}

    */
	/*
	unsigned int numBytes = 8;
	unsigned char bytes[numBytes];
	for (int i=0;i<numBytes; i++) {
		bytes[i] = (keyForEncrypt.integer >> i) & 0xFF;
	}

	cout << "Key For Encryption: " << keyForEncrypt.integer << endl;
	cout << "Key Part: " << keyPart << endl;
	*/

    SHA256 sha256;
    fileKeyString = sha256(KeyFileName).c_str();

    cout << strlen(fileKeyString) << endl;

    cout << *fileKeyString << *(fileKeyString +1)<< endl;

    string newstring = sha256(KeyFileName);
    cout << "newstring: " << newstring << endl;
    string oneHex = newstring.substr(0,2);
    cout << "oneHex: " << oneHex << endl;
    unsigned char hexV;
	stringstream ss1;
	//string byte = *fileKeyString + *(fileKeyString+1);

	ss1 << std::dec << oneHex;
	ss1 >> hexV;

	printf("Test =======>hexV: %02x\n", hexV);

    //string chr = to_string((char)*fileKeyString);
    //cout << chr << endl;
    //cout << "str to int: " << stoi(chr) << endl;

    const char *keyptr = fileKeyString;
    char hex[2];

    printf("size of filekey[i]: %d\n", sizeof(fileKey[0]));
    printf("size of *fileKeyString: %d\n", sizeof(*fileKeyString));

    /*
    char str[2];
    strcpy (str,(const char*) *fileKeyString);
    strcat (str,(const char*) *(fileKeyString+1));

    cout << str << endl;
    unsigned char x;
	stringstream ss;
	//string byte = *fileKeyString + *(fileKeyString+1);

	ss << std::hex << str;
	ss >> x;
	printf("Test =======> %02x", x);




	for (int i = 0; i < 32;i++) {
		fileKey[i] = 0;

		//itoa(10,hex,16);
		//printf(";%02x ", hex);
		fileKey[i] = *fileKeyString;
		printf("%c ", fileKey[i]);
		fileKey[i] = fileKey[i] >> 4;
		printf("%02x ", fileKey[i]);
		fileKey[i] = fileKey[i] || *(fileKeyString+1);
		printf("%02x; ", fileKey[i]);
		fileKeyString = fileKeyString + 2;
	}

	cout << endl;

     */

    for (i=0; i<32; i++) {
    	fileKey[i] = *fileKeyString;
    	fileKeyString = fileKeyString+2;
    }


	fileKeyString = keyptr;


    //cout << "int to str: " << to_string(stoi(fileKeyString)) << endl;
    cout << "hash: " << fileKeyString << endl;
/*
    for (i=0; i<32; i++) {
    	fileKey[i] = fileKeyString[i];
    	fileKeyString = fileKeyString+2;
    }

*/

	buf = ReadFile(FileNameOriginal);

	padding = 16 - (totalLen %16);
	newbuf = (unsigned char *) malloc(totalLen + padding);

	for(i = 0; i< totalLen; i++) {
		newbuf[i] = buf[i];
	}

	for(i=0; i< padding; i++) {
		newbuf[totalLen + padding] = padding;
	}


	inputptr = newbuf;
	cout << ">>>>>>" << inputptr << ">>>>>>" << endl;
	aes256_init(&ctx, fileKey);

	for(i=0; i< totalLen + padding;) {
		aes256_encrypt_ecb(&ctx, newbuf);
		i = i + 16;
		newbuf = newbuf + 16;

	}
	cout << ">>>>>>" << inputptr << ">>>>>>" << endl;

	DUMP("enc: ", i, inputptr, totalLen + padding);
	DUMP("key: ", i, fileKey, sizeof(fileKey));
	newbuf = inputptr;

/*
	for (size_t i = 0; i < totalLen + padding; ++i)
	{
		cout << bitset<8>(newbuf[i]);
	}
*/

	outfile.open(FileNameShared, ofstream::binary);
	outfile.write ((char *)newbuf,totalLen+ padding);
	outfile.close();

	aes256_init(&ctx, fileKey);

	cout << "Total Length: " << totalLen + padding << endl;

	for(int i=0;i<totalLen + padding;) {
		aes256_decrypt_ecb(&ctx, newbuf);
		newbuf = newbuf + 16;
		i = i + 16;
	}

	newbuf = inputptr;
	cout << ">>>>>>" << inputptr << ">>>>>>" << endl;

	DUMP("dec: ", i, inputptr, totalLen + padding);

	cout <<"Decrypted: "<< inputptr << endl;
	aes256_done(&ctx);

}

// returns SharedFileKey.txt, FileNameEncrypted
void authorize (char *SharedKeyFileName, char *FileNameShared) {



}

void recover2(char *FileNameFromCloud, char *FileNameShared, char *SharedFileKeyFileName) {

	hash <string> strHash;
	unsigned char fileKey[32];
	const char *fileKeyString;
	string keyPart;
	char *buf;
    unsigned char *newbuf, *inputptr;
    aes256_context ctx;
    ofstream outfile;

    SHA256 sha256;

    fileKeyString = sha256(KeyFileName).c_str();


    for (i=0; i<32; i++) {
    	fileKey[i] = *fileKeyString;
    	fileKeyString = fileKeyString+2;
    }

    /*
	keyForEncrypt.integer = strHash(KeyFileName);
	keyPart = to_string(keyForEncrypt.integer);

	cout << "Size of Key (int): " << sizeof(keyForEncrypt.integer) << endl;
	cout << "Size of Key (byte): " << sizeof(keyForEncrypt.byte) << endl;
	cout << "Size of fileKey: " << sizeof(fileKey) << endl;
	cout << "Size of Key Part: " << sizeof(keyPart) << endl;
	cout << "Size of an element in Key Part array: " << sizeof(keyPart[0]) << endl;

	cout << "Key Part Bytes:\n";
	for (int i = 0; i < 24;i++) {
		//printf("%02x ", keyPart[i]);
		fileKey[i] = keyPart[i];

	}

	for (int i=0; i<8; i++) {
		fileKey[i+24] = keyForEncrypt.byte[i];
	}

	cout << "Key For Encryption: " << keyForEncrypt.integer << endl;

    */

	buf = ReadFile(FileNameShared);
	newbuf = (unsigned char *) malloc(totalLen);

	for(i = 0; i< totalLen; i++) {
		newbuf[i] = buf[i];
	}

	cout << "Total Length: " << totalLen << endl;

	DUMP("txt: ", i, newbuf, totalLen);
	DUMP("key: ", i, fileKey, sizeof(fileKey));

	inputptr = newbuf;

	cout << ">>>>>>" << inputptr << ">>>>>>" << endl;

	aes256_init(&ctx, fileKey);

	for(int i=0;i<totalLen;) {
		aes256_decrypt_ecb(&ctx, newbuf);
		newbuf = newbuf + 16;
		i = i + 16;
	}

	newbuf = inputptr;

	cout << ">>>>>>" << inputptr << ">>>>>>" << endl;

	DUMP("dec: ", i, inputptr, totalLen);

	cout <<"Decrypted: "<< inputptr << endl;
	aes256_done(&ctx);

}

// returns FileNameOriginal.txt
void recover (char *FileNameFromCloud, char *FileNameShared, char *SharedFileKeyFileName) {

	hash <string> strHash;
	unsigned char fileKey[32];
	string keyPart;
	char *buf;
	unsigned char *newbuf, *inputptr;

    aes256_context ctx;
	FILE *outfile;

	keyForEncrypt.integer = strHash(KeyFileName);
	keyPart = to_string(keyForEncrypt.integer);

	cout << "Key Part Bytes:\n";
	for (int i = 0; i < 24;i++) {
		//printf("%02x ", keyPart[i]);
		fileKey[i] = keyPart[i];

	}

	for (int i=0; i<8; i++) {
		fileKey[i+24] = keyForEncrypt.byte[i];
	}

	//cout << "Key For Decryption: " << keyForEncrypt.integer << endl;
	//cout << "Key Part: " << keyPart << endl;

	buf = ReadFile(FileNameShared);
	newbuf = (unsigned char *) malloc(totalLen);

	for(i = 0; i< totalLen; i++) {
			newbuf[i] = buf[i];
	}
	inputptr = newbuf;

	DUMP("txt: ", i, newbuf, totalLen);
	DUMP("key: ", i, fileKey, sizeof(fileKey));

	cout << "Encrypted: " << newbuf << endl;

	aes256_init(&ctx, fileKey);

	cout << "Total File Length: " << totalLen << endl;
	for(int i=0;i<totalLen;) {
		aes256_decrypt_ecb(&ctx, newbuf);
		newbuf = newbuf + 16;
		i = i + 16;
	}

	DUMP("dec: ", i, inputptr, totalLen);

	cout <<"Decrypted: "<< inputptr << endl;
	aes256_done(&ctx);

}
