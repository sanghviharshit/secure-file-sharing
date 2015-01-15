# MC_Project2_EncryptForCloud
A method to pre-process a file before storing it on a cloud storage server so that the server cannot read the file content but a desired peer can.

# Project Description
The project consists of a software implementation of a method to pre-process a file before storing it on a cloud storage server so that the server cannot read the file content but a desired peer can. 

More precisely, you need to build a triple of algorithms:
* PreProcess: on input a key k, and a file f1 with filename fn1, returns a related file f2 with a related filename fn2 
* Authorize: on input a key k and a filename fn1, returns a string fk and a filename fn3 
* Recover: on input a file f2 with filename fn2, and string fk, returns a file f3 such that the following requirements hold:
	* Correctness:
		* For any file f with filename fn1, after randomly choosing key k, and obtaining fn2=PreProcess(k,f1,fn1), (fk,fn3)=Authorize(k,fn1), and f3=Recover(f2,fn2,fk), it holds that f3=f1 and fn3=fn2; 
	* Privacy against cloud storage server: 
		* the pair (f2,fn2) leaks no more information about f1 than the filename fn1 and the length of f1.
	* Integrity against cloud storage server: 
		* detection of file modification by the cloud storage server

Note that defining your method so that fn3=fn2=fn1 will not violate the requirements, but you are encouraged to try more interesting approaches.

# Rationale
Rationale behind the design of the three algorithms PreProcess, Authorize and Recover goes as follows:
* With Preprocess, you (the file owner) want to encrypt the file before posting it on the storage server; encrypting the file and leaving the same name may not be a good idea (from a privacy point of view) since file names sometimes reveal the file content; accordingly, in Preprocess you have a chance to assign a new name fn2 to the encrypted file; make sure you compute fn2 judiciously; moreover, encrypting all files with the same key is not a good idea as later you want to selectively authorize decryption of some but not all of the files; accordingly, you generate an encryption key fk for each file as a function of the key k and the original file name fn1.
* After Preprocess is run, you can post the encrypted file with the new name into the storage server (this part does not need to be implemented, but you should show it in your presentation).
* At this point, others could download or copy the encrypted file, but only those you choose can decrypt it; thus, you run Authorize to regenerate fk from k and fn1 just as done in Preprocess, and generate fn3 just as you generated fn2 in Preprocess (thus, fn3=fn2). Now you could send fk to your desired peer (this part does not need to be implemented).
* Your peer can use fk received from you and the encrypted file downloaded from the storage server (even this part does not need to be implemented but it would be nice to show it in your presentation), to run Recover and successfully decrypt the file; so far, we only talked about encryption, but a similar reasoning can be done to let your peer check that the file was not modified before decrypting.
* You have to implement the three algorithms PreProcess, Authorize and Recover using a suitable set of cryptographic primitives (e.g., block ciphers, block cipher modes of operation) and cryptographic schemes (i.e., symmetric encryption schemes, asymmetric encryption schemes, message authentication codes, signature schemes, etc.). 

# Resources
* The implementation has to be in C or C++; examples of usable programming environments include Visual Studio Express and Eclipse, which are freely available from the Internet. 
* You will be allowed and encouraged to use software libraries from the Internet (e.g., Open SSL, Crypto++, etc.) whenever possible, and will have to produce a powerpoint presentation detailing implementation approach, software documentation, property satisfaction and execution demo. 
* The project should be realized by single students or a team of 2 students, and comes with a minimal assignment; any additional work you perform will be considered extra credit work. 
* Teams are supposed to split the amount of work more or less equally among the team members. If a team splits the work in a way that is too unbalanced, the score given to team members may be suitably unbalanced.

# Expectation
Your executable files PreProcess, Authorize and Recover should be able to run, for instance, with command line inputs as follow:
* ./preprocess    key.txt   file.txt   filename.txt   (returning files efile.txt and efilename.txt)  
* ./authorize    key.txt    filename.txt   (returning files fkey.txt  and sfilename.txt)  
* ./recover    efile.txt   efilename.txt  fkey.txt  (returning file sfile.txt)  

To empirically test whether your software programs satisfy correctness, you could run a diff command on file.txt and sfile.txt. Note that the above convention is, for simplicity, representing the key and the filename as a string in another file. If you would rather change this or some of the other conventions, while still meeting the above requirements, you should clarify your changes in your presentation.

All files you use (when representing keys, filenames, plain files and encrypted files) should be in one of two formats: binary (i.e., all symbols from {0,1}) or exadecimal (i.e., all symbols from {0,1,...,9,A,B,...,E,F}); let us know which one you picked both in the code and in the presentation.
 
These programs should make, whenever possible, calls to software taken from libraries freely available on the internet (e.g., OpenSSL, Crypto++ and/or others). In addition to producing your software (both source code and executable), you have to produce a powerpoint presentation at least including the following sections:
* A brief introductory section describing the set of primitives or schemes that you have chosen, the list of project tasks performed by each student in the team, and a detailed explanation of how to run all programs
* A justification of why your produced software satisfies the properties of correctness and privacy against the cloud server
* A demonstration of how your software was executed with a cloud storage server (of your choice) on the internet and how the execution satisfied correctness
* A discussion of any extra credit work performed

# Extensions 
Preferred extensions (to be considered as extra credit) include the following:
* giving a ~10-minutes powerpoint presentation of your project (possibly with demonstration of your software functionality using a real-life Internet cloud storage server) on the week before the Finals; email the instructor to book a time slot;
* a method to generate file names that satisfies additional interesting privacy properties;
* a section on cloud storage servers available on the internet, and their different capabilities;
* modifying your software so that, in addition to requirements 1,2,3, it also satisfies the following requirement 4: "detection of file modification by the cloud storage server can be done by anyone, not just your peer"
* anything else you want to add.

Your submission should be a zip file containing at least the following files: 
* project presentation (a pdf file generated from a ppt file), 
* source and executable files. 

Please name your zip file as <last-name>-cs6903f14project2 and your contained files as <last-name>-presentation, <last-name>-preprocess, <last-name>-authorize, and <last-name>-recover. Please include all files that allow us to run or compile them. In case of a team, include both team members' last names.

# Grading Criteria
Your submission will be judged based on the following project grading criteria:
* technical correctness (i.e., if your software, after inspection of the presentation demonstration and perhaps some amount of testing, seems to satisfy correctness)
* software usability (i.e., if you followed all of the above instructions, especially on how to run the programs, and if software is easy to use)
* valid choice of primitive/scheme speeds (i.e., if your implemented primitive/scheme are good choices in terms of security and efficiency)
* demonstration/presentation quality (i.e., if the demonstration and the entire presentation are well written).

# Documentation and Project Report
Project report is available in `doc/`.
