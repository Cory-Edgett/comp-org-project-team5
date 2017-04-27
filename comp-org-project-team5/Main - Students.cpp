// Main.cpp
//
#define _CRT_SECURE_NO_WARNINGS 
#include <windows.h>
#include <stdio.h>
#include <io.h>

//#define TEST_CODE

// Global Variables
unsigned char gkey[65537];
unsigned char *gptrKey = gkey;			// used for inline assembly routines, need to access this way for Visual Studio
char gPassword[256] = "password";
unsigned char gPasswordHash[32];
unsigned char *gptrPasswordHash = gPasswordHash;	// used for inline assembly routines, need to access this way for Visual Studio

FILE *gfptrIn = NULL;
FILE *gfptrOut = NULL;
FILE *gfptrKey = NULL;
char gInFileName[256];
char gOutFileName[256];
char gKeyFileName[256];
int gOp = 0;			// 1 = encrypt, 2 = decrypt
int gNumRounds = 1;


// Prototypes
int sha256(char *fileName, char *dataBuffer, DWORD dataLength, unsigned char sha256sum[32]);

// assembly language to count the number of ASCII letters in a data array
//	numC = number of capital letters
//	numL = number of lowercase letters
//	numO = number of characters that are not a letter
void exCountLetters( char *data, int dataLength, int *numC, int *numL, int *numO )
{
	__asm {
		cld;					// 
		push esi;				// 
		push ecx;				// 
		push ebx;
		mov esi,data;			// 
		mov ecx, dataLength;	// 

LOOP_X1:
		lodsb;					// 
		mov bl,al				// 
		push eax;				// 
		call isLetter;			// function returns a 1 in al if the character passed in is a letter, otherwise al = 0
		add esp,4				// 
		test al,al;				// 
		je lbl_OTHER;			// 

		mov al,bl				// 
		and al,0x20;			// already know it's a letter, if al == 0, then CAP
		je lbl_CAP;
		
		mov	ebx,numL;			// 
		add [ebx],1;			// 
		jmp lbl_NEXT;			// 

lbl_CAP:
		mov ebx,numC;			// 
		add [ebx],1;			// 
		jmp lbl_NEXT;			// 

lbl_OTHER:
		mov ebx,numO			// 
		add [ebx],1				// 
lbl_NEXT:
		dec ecx;				// 
		jne LOOP_X1;			// 

		pop ebx;				// 
		pop ecx;				// 
		pop esi;				// 
		jmp EXIT_C_EXAMPLE;		// let C handle whatever it did upon entering this function

isLetter:
		push ebp;				// 
		mov ebp,esp;			// 
		mov al,[ebp+8];			// 
		cmp al,0x40;			// 
		ja lbl_CHK_ZU;			// check Uppercase 'Z'

lbl_RET_FALSE:
		xor eax,eax;			// 
lbl_RET:
		mov esp,ebp;			// 
		pop ebp;				// 
		ret;					// 

lbl_RET_TRUE:
		mov eax,1;				// 
		jmp lbl_RET;			// 

lbl_CHK_ZU:
		cmp al,0x5B;			// 
		jb lbl_RET_TRUE;		// 

		cmp al,0x61;			// 
		jb lbl_RET_FALSE;		// check lowercase 'z'

		cmp al,0x7A;			// 
		jbe lbl_RET_TRUE;		// 
		jmp lbl_RET_FALSE;		// 

	} // end assembly block

EXIT_C_EXAMPLE:					// 
	return;
} // exCountLetters

//////////////////////////////////////////////////////////////////////////////////////////////////
// code to encrypt the data as specified by the project assignment
void encryptData(char *data, int _length)
{
	// you can not declare any local variables in C, set up the stack frame and 
	// assign them in assembly
	__asm {

		// you will need to reference these global variables
		// gptrPasswordHash, gptrKey

		// Preserve data and _length
		mov  eax, data
		mov  ebx, _length

		/* POINT INSERTION FOR ENCRYPTION
		 *
		 * data            = [ebp-0x24]
		 * _length         = [ebp-0x20]
		 * #ROUNDS         = [ebp-0x1C]
		 * Starting_point1 = [ebp-0x18]
		 * Starting_point2 = [ebp-0x14]
		 * hop_count1      = [ebp-0x10]
		 * hop_count2      = [ebp-0x0C]
		 * index1          = [ebp-0x08]
		 * index2          = [ebp-0x04]
		 *
		 */
		push ebp
		mov  ebp, esp
		sub  esp, 0x24

		// data
		mov  [ebp-0x24], eax

		// _length
		mov  [ebp-0x20], ebx

		// set #rounds, gNumRounds as [ebp-0x18]
		mov  eax, gNumRounds
		mov  [ebp-0x1C], eax // number of rounds

		mov  [ebp-0x18], 0	// Starting_Point1
		mov  [ebp-0x14], 0  // Starting_Point2
		mov  [ebp-0x10], 0  // hop_count1
		mov  [ebp-0x0C], 0  // hop_count2


/*----------------------------------
 * FOR LOOP START - GRAB NEW KEY
 */
		mov  ecx, 0

ROUND_ENCRYPT:

		push ecx

		// Starting_point1[round] = gPasswordHash[0+round*4] * 256 + gPasswordHash[1+round*4]
		mov  ebx, gptrPasswordHash[0+ecx*4]
		mov  eax, 256
		mul  ebx
		add  eax, gptrPasswordHash[1+ecx*4]
		mov  ebx, [ebp-0x18]
		//mov  [ebx+ecx], eax
		mov  ebx, eax
		mov  [ebp-0x18], ebx

		// Starting_point2[round] = gPasswordHash[16+round*4] * 256 + gPasswordHash[17+round*4]
		mov  ebx, gptrPasswordHash[16+ecx*4]
		mov  eax, 256
		mul  ebx
		add  eax, gptrPasswordHash[17+ecx*4]
		mov  ebx, [ebp-0x14]
		//mov  [ebx+ecx], eax
		mov  ebx, eax
		mov  [ebp-0x14], ebx
		
		// hop_count1[round] = gPasswordHash[2+round*4] * 256 + gPasswordHash[3+round*4]
		mov  ebx, gptrPasswordHash[2+ecx*4]
		mov  eax, 256
		mul  ebx
		add  eax, gptrPasswordHash[3+ecx*4]
		mov  ebx, [ebp-0x10]
		//mov  [ebx+ecx], eax
		mov  ebx, eax
		mov  [ebp-0x10], ebx

		// hop_count2[round] = gPasswordHash[18+round*4] * 256 + gPasswordHash[19+round*4]
		mov  ebx, gptrPasswordHash[18+ecx*4]
		mov  eax, 256
		mul  ebx
		add  eax, gptrPasswordHash[19+ecx*4]
		mov  ebx, [ebp-0x0C]
		//mov  [ebx+ecx], eax
		mov  ebx, eax
		mov  [ebp-0x0C], ebx

		// index1 = starting_point1[round]
		mov  eax, [ebp-0x18]
		mov  eax, eax
		mov  [ebp-0x8], eax
		mov  [ebp-0x4], 0
		jnz   NOT_INDEX1_FAILURE

INDEX1_FAILURE:
		mov  [ebp-0x4], 0xFFFF

NOT_INDEX1_FAILURE:

		// index2 = starting_point2[round]
		mov  eax, [ebp-0x14]
		mov  ebx, eax
		mov  [ebp-0x4], eax
		mov  [ebp-0x4], 0
		jnz   NOT_INDEX2_FAILURE

INDEX2_FAILURE:
		mov  [ebp-0x4], 0xFFFF

NOT_INDEX2_FAILURE:

/*---------------------------------------------
 * FOR LOOP START - ENCRYPT EACH PORTION
 */
		// x = 0
		mov  ecx, 0

NEXT_FOR_LOOP:
        push ecx

        // file[x] = file[x] ^ gKey[index1]
        mov  esi, gptrKey
        mov  edi, [ebp - 0x24]
        mov  al, byte ptr [edi + ecx]
        mov  bl, byte ptr[esi + ebx - 0x08]
        xor  al, bl
        mov [edi + ecx], al

		// index1 += hop_count1
		mov  eax, [ebp-0x08]
		add  eax, [ebp-0x10]
		mov  [ebp-0x08], eax

		// if(index >= 65537)
		cmp  [ebp-0x08], 0x10001
		jl   ENCRYPT_BIT

		// index1 -= 65537
ADJUST_INDEX1:
		mov  eax, [ebp-0x08]
		sub  eax, 0x10001
		mov  [ebp-0x08], eax

ENCRYPT_BIT:
		// do the encryption here
		xor eax, eax
		mov al, byte ptr [edi+ecx]
		ror al, 1 //rotate 1-bit right
		mov ah, al
		and ah, 0x0f
		shl ah, 4
		and al, 0xf0
		shr al, 4
		or al, ah	//swap nibbles
		xor ecx, ecx
		mov ecx, 7
		xor ah, ah
E_REV:
		mov bl, al
		and bl, 0x01
		or ah, bl
		cmp ecx, 0
		je E_EXIT
		dec ecx
		shr al, 1
		shl ah, 1
		jmp E_REV
E_EXIT:
		mov al, ah
		mov ah, al
		and ah, 0x33
		shl ah, 2
		and al, 0xcc
		shr al, 2
		or al, ah // swap half nibbles
		rol al, 1 // rotate 1 bit to left

		pop  ecx

		mov byte ptr [edi+ecx], al

		inc  ecx
		mov  eax, [ebp-0x20]
		cmp  ecx, eax
		jb   NEXT_FOR_LOOP
/*
 * FOR LOOP END - ENCRYPT EACH PORTION
 -------------------------------------------*/
		pop  ecx
		inc  ecx
		//cmp  ecx, [ebp-0x1B]
		cmp  ecx, gNumRounds
		jl   ROUND_ENCRYPT	

/*
 * FOR LOOP END - GRAB NEW KEY
 -------------------------------------------*/
		mov  esp, ebp
		pop  ebp
	}

EXIT_C_ENCRYPT_DATA:
	return;
} // encryptData

// code to read the file to encrypt
int encryptFile(FILE *fptrIn, FILE *fptrOut)
{
	char *buffer;
	unsigned int filesize;

	filesize = _filelength(_fileno(fptrIn));	// Linux???
	if(filesize > 0x1000000)					// 16 MB, file too large
	{
		fprintf(stderr, "Error - Input file too large.\n\n");
		return -1;
	}

	// use the password hash to encrypt
	buffer = (char *) malloc(filesize);
	if(buffer == NULL)
	{
		fprintf(stderr, "Error - Could not allocate %d bytes of memory on the heap.\n\n", filesize);
		return -1;
	}

	fread(buffer, 1, filesize, fptrIn);	// read entire file
	encryptData(buffer, filesize);
	fwrite(buffer, 1, filesize, fptrOut);
	free(buffer);

	return 0;
} // encryptFile

//////////////////////////////////////////////////////////////////////////////////////////////////
// code to decrypt the data as specified by the project assignment
void decryptData(char *data, int _length)
{
	// you can not declare any local variables in C, set up the stack frame and 
	// assign them in assembly
	__asm {

		// you will need to reference these global variables
		// gptrPasswordHash, gptrKey

		// Preserve data and _length
		mov  eax, data
		mov  ebx, _length

		/* POINT INSERTION FOR ENCRYPTION
		 *
		 * data            = [ebp-0x24]
		 * _length         = [ebp-0x20]
		 * #ROUNDS         = [ebp-0x1C]
		 * Starting_point1 = [ebp-0x18]
		 * Starting_point2 = [ebp-0x14]
		 * hop_count1      = [ebp-0x10]
		 * hop_count2      = [ebp-0x0C]
		 * index1          = [ebp-0x08]
		 * index2          = [ebp-0x04]
		 *
		 */
		push ebp
		mov  ebp, esp
		sub  esp, 0x24

		// data
		mov  [ebp-0x24], eax

		// _length
		mov  [ebp-0x20], ebx

		// set #rounds, gNumRounds as [ebp-0x18]
		mov  eax, gNumRounds
		mov  [ebp-0x1C], eax // number of rounds

		mov  [ebp-0x18], 0	// Starting_Point1
		mov  [ebp-0x14], 0  // Starting_Point2
		mov  [ebp-0x10], 0  // hop_count1
		mov  [ebp-0x0C], 0  // hop_count2


/*----------------------------------
 * FOR LOOP START - GRAB NEW KEY
 */
		mov  ecx, 0

ROUND_ENCRYPT:

		push ecx

		// Starting_point1[round] = gPasswordHash[0+round*4] * 256 + gPasswordHash[1+round*4]
		mov  ebx, gptrPasswordHash[0+ecx*4]
		mov  eax, 256
		mul  ebx
		add  eax, gptrPasswordHash[1+ecx*4]
		mov  ebx, [ebp-0x18]
		//mov  [ebx+ecx], eax
		mov  ebx, eax
		mov  [ebp-0x18], ebx

		// Starting_point2[round] = gPasswordHash[16+round*4] * 256 + gPasswordHash[17+round*4]
		mov  ebx, gptrPasswordHash[16+ecx*4]
		mov  eax, 256
		mul  ebx
		add  eax, gptrPasswordHash[17+ecx*4]
		mov  ebx, [ebp-0x14]
		//mov  [ebx+ecx], eax
		mov  ebx, eax
		mov  [ebp-0x14], ebx
		
		// hop_count1[round] = gPasswordHash[2+round*4] * 256 + gPasswordHash[3+round*4]
		mov  ebx, gptrPasswordHash[2+ecx*4]
		mov  eax, 256
		mul  ebx
		add  eax, gptrPasswordHash[3+ecx*4]
		mov  ebx, [ebp-0x10]
		//mov  [ebx+ecx], eax
		mov  ebx, eax
		mov  [ebp-0x10], ebx

		// hop_count2[round] = gPasswordHash[18+round*4] * 256 + gPasswordHash[19+round*4]
		mov  ebx, gptrPasswordHash[18+ecx*4]
		mov  eax, 256
		mul  ebx
		add  eax, gptrPasswordHash[19+ecx*4]
		mov  ebx, [ebp-0x0C]
		//mov  [ebx+ecx], eax
		mov  ebx, eax
		mov  [ebp-0x0C], ebx

		// index1 = starting_point1[round]
		mov  eax, [ebp-0x18]
		mov  eax, eax
		mov  [ebp-0x8], eax
		mov  [ebp-0x4], 0
		jnz   NOT_INDEX1_FAILURE

INDEX1_FAILURE:
		// hop_count1 = 0xFFFF
		mov  [ebp-0x4], 0xFFFF

NOT_INDEX1_FAILURE:

		// index2 = starting_point2[round]
		mov  eax, [ebp-0x14]
		mov  ebx, eax
		mov  [ebp-0x4], eax
		mov  [ebp-0x4], 0
		jnz   NOT_INDEX2_FAILURE

INDEX2_FAILURE:
		// hop_count2 = 0xFFFF
		mov  [ebp-0x4], 0xFFFF

NOT_INDEX2_FAILURE:

/*---------------------------------------------
 * FOR LOOP START - ENCRYPT EACH PORTION
 */
		// x = 0
		mov  ecx, 0

NEXT_FOR_LOOP:
		push ecx

		// file[x] = file[x] ^ gKey[index1]
		mov  esi, gptrKey
		mov  edi, [ebp-0x24]
		mov  al, byte ptr [edi+ecx]
		mov  bl, byte ptr [esi+ebx-0x08]
		xor  al, bl
		mov  [edi+ecx], al

		// index1 += hop_count1
		mov  eax, [ebp-0x08]
		add  eax, [ebp-0x10]
		mov  [ebp-0x08], eax

		// if(index >= 65537)
		cmp  [ebp-0x08], 0x10001
		jl   ENCRYPT_BIT

		// index1 -= 65537
ADJUST_INDEX1:
		mov  eax, [ebp-0x08]
		sub  eax, 0x10001
		mov  [ebp-0x08], eax
//*
ENCRYPT_BIT:
		// do the encryption here
		xor eax, eax
		mov al, byte ptr [edi+ecx]

		ror al, 1; //rotate 1-bit right :0xC3 -> 0xE1	
		mov ah, al;
		and ah, 0x33;
		shl ah, 2;
		and al, 0xcc;
		shr al, 2;
		or al, ah;// swap half nibbles: 0xE1 -> 0xB4
		xor ecx, ecx;
		mov ecx, 7;
		xor ah, ah;
  //*/
REVERSE:
		mov bl, al;
		and bl, 0x01;
		or ah, bl;
		cmp ecx, 0;
		je REV_EXIT;
		dec ecx;
		shr al, 1;
		shl ah, 1;
		jmp REVERSE;

REV_EXIT:
		mov al, ah;	// reverse order: 0xB4 -> 0x2D
		mov ah, al;
		and ah, 0x0f;
		shl ah, 4;
		and al, 0xf0;
		shr al, 4;
		or al, ah;	//swap nibbles: 0x2D -> 0xD2		
		rol al, 1;// rotate 1 bit to left 0xD2 -> 0xA5

		pop  ecx

		mov [edi+ecx], al

		inc  ecx
		mov  eax, [ebp-0x20]
		cmp  ecx, eax
		jb   NEXT_FOR_LOOP
/*
 * FOR LOOP END - ENCRYPT EACH PORTION
 -------------------------------------------*/
		pop  ecx
		inc  ecx
		cmp  ecx, gNumRounds
		jl   ROUND_ENCRYPT	

/*
 * FOR LOOP END - GRAB NEW KEY
 -------------------------------------------*/


		// Kill stackframe for asm
		mov  esp, ebp
		pop  ebp


	}

EXIT_C_DECRYPT_DATA:
	return;
} // decryptData

// code to read in file and prepare for decryption
int decryptFile(FILE *fptrIn, FILE *fptrOut)
{
	char *buffer;
	unsigned int filesize;

	filesize = _filelength(_fileno(fptrIn));	// Linux???
	if(filesize > 0x1000000)					// 16 MB, file too large
	{
		fprintf(stderr, "Error - Input file too large.\n\n");
		return -1;
	}

	// use the password hash to encrypt
	buffer = (char *) malloc(filesize);
	if(buffer == NULL)
	{
		fprintf(stderr, "Error - Could not allocate %d bytes of memory on the heap.\n\n", filesize);
		return -1;
	}

	fread(buffer, 1, filesize, fptrIn);	// read entire file
	decryptData(buffer, filesize);
	fwrite(buffer, 1, filesize, fptrOut);
	free(buffer);

	return 0;
} // decryptFile

//////////////////////////////////////////////////////////////////////////////////////////////////
FILE *openInputFile(char *filename)
{
	FILE *fptr;

	fptr = fopen(filename, "rb");
	if(fptr == NULL)
	{
		fprintf(stderr, "\n\nError - Could not open input file %s!\n\n", filename);
		exit(-1);
	}
	return fptr;
} // openInputFile

FILE *openOutputFile(char *filename)
{
	FILE *fptr;

	fptr = fopen(filename, "wb+");
	if(fptr == NULL)
	{
		fprintf(stderr, "\n\nError - Could not open output file %s!\n\n", filename);
		exit(-1);
	}
	return fptr;
} // openOutputFile


void usage(char *argv[])	//   cryptor.exe -e -i <input file> –k <keyfile> -p <password> [–r <#rounds>]
{
	printf("\n\nUsage:\n\n");
	printf("%s -<e=encrypt or d=decrypt> -i <message_filename> -k <keyfile> -p <password> [-r <#rounds>]\n\n", argv[0]);
	printf("-e				:encrypt the specified file\n");
	printf("-d				:decrypt the specified file\n");
	printf("-i filename		:the name of the file to encrypt or decrypt\n");
	printf("-p password		:the password to be used for encryption [default='password']\n");
	printf("-r <#rounds>	:number of encryption rounds (1 - 3)  [default = 1]\n");
	printf("-o filename		:name of the output file [default='encrypted.txt' or 'decrypted.txt'\n\n");
	exit(0);
} // usage

void parseCommandLine(int argc, char *argv[])
{
	int cnt;
	char ch;
	bool i_flag, o_flag, k_flag, p_flag, err_flag;

	i_flag = k_flag = false;				// these must be true in order to exit this function
	err_flag = p_flag = o_flag = false;		// these will generate different actions

	cnt = 1;	// skip program name
	while(cnt < argc)
	{
		ch = *argv[cnt];
		if(ch != '-')
		{
			fprintf(stderr, "All options must be preceeded by a dash '-'\n\n");
			usage(argv);
		}

		ch = *(argv[cnt]+1);
		if(0)
		{
		}

		else if(ch == 'e' || ch == 'E')
		{
			if(gOp != 0)
			{
				fprintf(stderr, "Error! Already specified encrypt or decrypt.\n\n");
				usage(argv);
			}
			gOp = 1;	// encrypt
		}

		else if(ch == 'd' || ch == 'D')
		{
			if(gOp != 0)
			{
				fprintf(stderr, "Error! Already specified encrypt or decrypt.\n\n");
				usage(argv);
			}
			gOp = 2;	// decrypt
		}

		else if(ch == 'i' || ch == 'I')
		{
			if(i_flag == true)
			{
				fprintf(stderr, "Error! Already specifed an input file.\n\n");
				usage(argv);
			}
			i_flag = true;
			cnt++;
			if(cnt >= argc)
			{
				fprintf(stderr, "Error! Must specify a filename after '-i'\n\n");
				usage(argv);
			}
			strncpy(gInFileName, argv[cnt], 256);
		}

		else if(ch == 'o' || ch == 'O')
		{
			if(o_flag == true)
			{
				fprintf(stderr, "Error! Already specifed an output file.\n\n");
				usage(argv);
			}
			o_flag = true;
			cnt++;
			if(cnt >= argc)
			{
				fprintf(stderr, "Error! Must specify a filename after '-o'\n\n");
				usage(argv);
			}
			strncpy(gOutFileName, argv[cnt], 256);
		}

		else if(ch == 'k' || ch == 'K')
		{
			if(k_flag == true)
			{
				fprintf(stderr, "Error! Already specifed a key file.\n\n");
				usage(argv);
			}
			k_flag = true;
			cnt++;
			if(cnt >= argc)
			{
				fprintf(stderr, "Error! Must specify a filename after '-k'\n\n");
				usage(argv);
			}
			strncpy(gKeyFileName, argv[cnt], 256);
		}

		else if(ch == 'p' || ch == 'P')
		{
			if(p_flag == true)
			{
				fprintf(stderr, "Error! Already specifed a password.\n\n");
				usage(argv);
			}
			p_flag = true;
			cnt++;
			if(cnt >= argc)
			{
				fprintf(stderr, "Error! Must enter a password after '-p'\n\n");
				usage(argv);
			}
			strncpy(gPassword, argv[cnt], 256);
		}

		else if(ch == 'r' || ch == 'R')
		{
			int x;

			cnt++;
			if(cnt >= argc)
			{
				fprintf(stderr, "Error! Must enter number between 1 and 3 after '-r'\n\n");
				usage(argv);
			}
			x = atoi(argv[cnt]);
			if(x < 1 || x > 3)
			{
				fprintf(stderr, "Warning! Entered bad value for number of rounds. Setting it to one.\n\n");
				x = 1;
			}
			gNumRounds = x;
		}

		else
		{
			fprintf(stderr, "Error! Illegal option in argument. %s\n\n", argv[cnt]);
			usage(argv);
		}

		cnt++;
	} // end while

	if(gOp == 0)
	{
		fprintf(stderr, "Error! Encrypt or Decrypt must be specified.\n\n");
		err_flag = true;
	}

	if(i_flag == false)
	{
		fprintf(stderr, "Error! No input file specified.\n\n");
		err_flag = true;
	}

	if(k_flag == false)
	{
		fprintf(stderr, "Error! No key file specified.\n\n");
		err_flag = true;
	}

	if(p_flag == false)
	{
		fprintf(stderr, "Warning! Using default 'password'.\n\n");
	}

	if(o_flag == false && err_flag == false)	// no need to do this if we have errors
	{
		strcpy(gOutFileName, gInFileName);
		if(gOp == 1)	// encrypt
		{
			strcat(gOutFileName, ".enc");
		}
		if(gOp == 2)	// decrypt
		{
			strcat(gOutFileName, ".dec");
		}
	}

	if(err_flag)
	{
		usage(argv);
	}
	return;
} // parseCommandLine


void main(int argc, char *argv[])
{


	int length, resulti;

	// parse command line parameters
	parseCommandLine(argc, argv);		// sets global variables, checks input options for errors

	// open the input and output files
	gfptrIn = openInputFile(gInFileName);
	gfptrKey = openInputFile(gKeyFileName);
	gfptrOut = openOutputFile(gOutFileName);

	length = (size_t) strlen(gPassword);

	resulti = sha256(NULL, gPassword, length, gPasswordHash);		// get sha-256 hash of password
	if(resulti != 0)
	{
		fprintf(stderr, "Error! Password not hashed correctly.\n\n");
		exit(-1);
	}

	length = fread(gkey, 1, 65537, gfptrKey);
	if(length != 65537)
	{
		fprintf(stderr, "Error! Length of key file is not at least 65537.\n\n");
		exit(-1);
	}
	fclose(gfptrKey);
	gfptrKey = NULL;

	if(gOp == 1)	// encrypt
	{
		encryptFile(gfptrIn, gfptrOut);
	}
	else
	{
		decryptFile(gfptrIn, gfptrOut);
	}

	fclose(gfptrIn);
	fclose(gfptrOut);
	return;
} // main