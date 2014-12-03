/*
 * Authorize.cpp
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

void authorize ();

#define DUMP(s, i, buf, sz)  {printf(s);                   \
                              for (i = 0; i < (sz);i++)    \
                                  printf("%02x ", buf[i]); \
                              printf("\n");}

char *KeyFileName = "KeyFile.txt";
char *Key;
char *FileNameOriginal;
char *FileNameShared;

int main (int argc, char *argv[])
{

//    cout << ">>>>>>>>>>>>>>>>>>>>" << endl;
//    cout <<"Authorizing" << endl;;
	if(argc != 3) {
		cout << "Usage: Authorize <filename> <passkey>\n";
	}

	FileNameOriginal = argv[1];
	Key = argv[2];
	//KeyFileName = Key;

	authorize();

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


    string FileName = FileNameOriginal;
	string FileIn = FileNameOriginal;

	char *FileOut = (char *)sha256(FileNameOriginal).c_str();

    fileKeyString = sha256(Key+FileName).c_str();

    for (i=0; i<32; i++) {
    	fileKey[i] = *fileKeyString;
    	fileKeyString = fileKeyString+2;
    }

    cout << "File Name in the cloud: " << FileOut << endl;
    //cout << "Decryption Key: ";
    //DUMP("key: ", i, fileKey, sizeof(fileKey));
    //cout << endl;

    /*
	outfile.open(KeyFileName, ofstream::binary);
	for(i=0;i<32;i++) {
		outfile.write ("%c", fileKey[i]);
	}
	outfile.close();
    */


}




