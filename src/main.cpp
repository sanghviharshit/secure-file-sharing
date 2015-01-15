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


void preprocess ();
void authorize ();
void recover ();

#define DUMP(s, i, buf, sz)  {printf(s);                   \
                              for (i = 0; i < (sz);i++)    \
                                  printf("%02x ", buf[i]); \
                              printf("\n");}

char *KeyFileName = "Password";
char *FileNameOriginal = "Original.txt";
char *FileNameShared = "Shared.txt";

int main (int argc, char *argv[])
{
	cout << ">>>>>>>>>>>>>>>>>>>>" << endl;
	cout << "Pre Processing" << endl;
    preprocess();

    cout << ">>>>>>>>>>>>>>>>>>>>" << endl;
    cout <<"Authorizing" << endl;;
    authorize();

    cout << ">>>>>>>>>>>>>>>>>>>>" << endl;
    cout << "Recovering" << endl;
    recover();

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

    string key = KeyFileName;
    string FileIn = FileNameOriginal;

    char *FileOut = (char *)sha256(FileNameOriginal).c_str();

    fileKeyString = sha256(key+FileIn).c_str();

    for (i=0; i<32; i++) {
    	fileKey[i] = *fileKeyString;
    	fileKeyString = fileKeyString+2;
    }

	buf = ReadFile(FileNameOriginal);

	padding = 16 - (totalLen %16);
	cout << "Padding: " << padding << endl;
	newbuf = (unsigned char *) malloc(totalLen + padding);

	for(i = 0; i< totalLen; i++) {
		newbuf[i] = buf[i];
	}

	for(i=0; i< padding; i++) {
		newbuf[totalLen + i] = padding;
	}

	inputptr = newbuf;

	aes256_init(&ctx, fileKey);

	DUMP("txt: ", i, inputptr, totalLen + padding);

	for(i=0; i< totalLen + padding;) {
		aes256_encrypt_ecb(&ctx, newbuf);
		i = i + 16;
		newbuf = newbuf + 16;
	}

	DUMP("enc: ", i, inputptr, totalLen + padding);
	DUMP("key: ", i, fileKey, sizeof(fileKey));
	cout <<"Encrypted: "<< inputptr << endl;

	newbuf = inputptr;

	FileNameShared = FileOut;
	outfile.open(FileOut, ofstream::binary);
	outfile.write ((char *)newbuf,totalLen+ padding);
	outfile.close();

	cout << "File Encrypted: " << FileNameShared << endl;

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
	aes256_done(&ctx);

}

// returns SharedFileKey.txt, FileNameEncrypted
void authorize () {

	unsigned char fileKey[32];
	const char *fileKeyString;
	string keyPart;
	char *buf;
    unsigned char *newbuf, *inputptr;
    aes256_context ctx;
    ofstream outfile;
    SHA256 sha256;

    string key = KeyFileName;
    string FileName = FileNameOriginal;
	string FileIn = FileNameOriginal;

	char *FileOut = (char *)sha256(FileNameOriginal).c_str();

    fileKeyString = sha256(key+FileName).c_str();

    for (i=0; i<32; i++) {
    	fileKey[i] = *fileKeyString;
    	fileKeyString = fileKeyString+2;
    }

    cout << "File Name in the cloud: " << FileOut << endl;
    cout << "Decryption Key: ";
    DUMP("key: ", i, fileKey, sizeof(fileKey));
    cout << endl;


}

// returns FileNameOriginal.txt
void recover() {

	hash <string> strHash;
	unsigned char fileKey[32];
	const char *fileKeyString;
	string keyPart;
	char *buf;
    unsigned char *newbuf, *inputptr;
    aes256_context ctx;
    ofstream outfile;
    SHA256 sha256;
    int padding;
    string key = KeyFileName;
    string FileName = FileNameOriginal;

    fileKeyString = sha256(key+FileName).c_str();

    for (i=0; i<32; i++) {
    	fileKey[i] = *fileKeyString;
    	fileKeyString = fileKeyString+2;
    }


	buf = ReadFile(FileNameShared);
	newbuf = (unsigned char *) malloc(totalLen);

	for(i = 0; i< totalLen; i++) {
		newbuf[i] = buf[i];
	}

	cout << "Total Length: " << totalLen << endl;

	DUMP("txt: ", i, newbuf, totalLen);
	DUMP("key: ", i, fileKey, sizeof(fileKey));

	inputptr = newbuf;

	aes256_init(&ctx, fileKey);

	for(int i=0;i<totalLen;) {
		aes256_decrypt_ecb(&ctx, newbuf);
		newbuf = newbuf + 16;
		i = i + 16;
	}
	DUMP("dec: ", i, inputptr, totalLen);

	newbuf = inputptr;

	padding = newbuf[totalLen - 1];
	cout << "Padding: " << padding << endl;
	totalLen = totalLen - padding;

	DUMP("dec: ", i, inputptr, totalLen);
	cout <<"Decrypted: "<< inputptr << endl;
	aes256_done(&ctx);

}


