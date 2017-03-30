
/**
 * WARNING: THIS FILE MAY MODIFY THE CONTENTS OF YOUR HARD DRIVE IN
 * UNSUSPECTED WAYS. BE CAREFUL TO MAKE REALLY SURE YOU KNOW WHAT
 * YOU ARE DOING, OR USE A VIRTUAL MACHINE.
 */

/**
 ----------------------------------
 Information
 ----------------------------------

 Compile this file with "gcc -Wall acmerld.c -o acmerld". 
 This file has been tested on debian linux x86_64 with gcc.
 While it may need some adaptations to work in other platforms,
 all its vulnerabilities are platform independent.

 ----------------------------------
 File format description
 ----------------------------------

 A run-length-encoded file is just a sequence of RLE commands.
 Each command is composed by a "repeat" 8-bit field and a 
 8-bit "value" field. 

 To decompress a compressed file do as follows:

  1 - Read one RLE command.

  2 - Write to the output file the 8-bits contained in "value", as many times as it 
      is indicated in the "repeat" field.

  3 - If there are more commands in the input file, go to step 1.

 See https://en.wikipedia.org/wiki/Run-length_encoding to learn more about RLE.

*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>

#define MAX_BUFFER_LENGTH 1024
#define MAX_CHUNK 1024
#define DECODING_SUFFIX ".decoded"

void copyFile(char *src, char *dst)
{
	FILE *file1 = fopen(src, "r");
	FILE *file2 = fopen(dst, "w");

	if (!file1 || !file2) {
		perror(__FILE__);
		return;
	}

	while (!feof(file1)) {
		char buffer[256];
		int r;

		r = fread(buffer, 1, sizeof(buffer), file1);
		fwrite(buffer, 1, r, file2);
	}

	fclose(file1);
	fclose(file2);
}

void putToFile(char *buffer, int items, FILE * file)
{
	size_t r = fwrite(buffer, items, 1, file);

	if (r < 1) {
		perror(__FILE__);
		return;
	}
}

struct settings_t {
	char *inputFileName;
	char *outputFileName;
	FILE *inputFile;
	FILE *tempFile;
};

void decode(struct settings_t *settings)
{
	/* Decoder state */

	struct {
		char buffer[MAX_BUFFER_LENGTH];
		char temporaryName[128];
		int bufferUsed;
	} decoderState;

	/* Create a temporary file where to put the result. */

	strcpy(decoderState.temporaryName, "/tmp/acmevgrXXXXXX");

	int tmpfd = mkstemp(decoderState.temporaryName);

	if (!tmpfd) {
		perror(__FILE__);
		exit(EXIT_FAILURE);
	}

	settings->tempFile = fdopen(tmpfd, "w");

	if (!settings->tempFile) {
		perror(__FILE__);
		exit(EXIT_FAILURE);
	}

	/* Open the input file. */

	settings->inputFile = fopen(settings->inputFileName, "r");

	if (!settings->inputFile) {
		perror(__FILE__);
		exit(EXIT_FAILURE);
	}

	/* The run-length decoder. */
	{
		decoderState.bufferUsed = 0;

		while (1) {

			struct {
				uint8_t repeat;
				char value;
			} rle_command;

			int i;

			if (fread(&rle_command.repeat, sizeof(uint8_t), 1, settings->inputFile) < 1) {
				if (feof(settings->inputFile)) {
					break;
				}

				perror(__FILE__);
				exit(EXIT_FAILURE);
			}

			if (fread(&rle_command.value, sizeof(char), 1, settings->inputFile) < 1) {
				perror(__FILE__);
				exit(EXIT_FAILURE);
			}

			/* Repeat the value as many times as specified by repeat. */
			for (i = 0; i < rle_command.repeat; i++) {
				decoderState.buffer[decoderState.bufferUsed] = rle_command.value;
				decoderState.bufferUsed++;
			}

			/* If the buffer is full, save to temporary file. */
			if (decoderState.bufferUsed == MAX_BUFFER_LENGTH) {
				putToFile(decoderState.buffer, MAX_BUFFER_LENGTH, settings->tempFile);
				decoderState.bufferUsed = 0;
			}

		}

		putToFile(decoderState.buffer, decoderState.bufferUsed, settings->tempFile);

	}

	fclose(settings->tempFile);

	/* Everything went OK, copy into final file. */

	copyFile(decoderState.temporaryName, settings->outputFileName);

	unlink(decoderState.temporaryName);
}

int main(int argc, char **argv)
{

	puts("       ___       _______  __    __       _______              ");
	puts("      /   |     / _____/ /  |  /  |     / _____/              ");
	puts("     / /| |    / /      /   | /   |    / /____   __       __  ");
	puts("    / /_| |   / /      / /| |/ /| |   / _____/  | _| |   |  \\ ");
	puts("   / ___  |  / /____  / / |___/ | |  / /____    |\\   |   |   |");
	puts("  /_/   |_| /______/ /_/        |_| /______/    | \\  |__ |__/ ");
	puts("                                     [RUN-LENGTH DECODER]\n");

	/* Read input parameters and process them. */

	if (argc != 2) {
		puts("Usage is: acmerld inputFile\n");
		exit(EXIT_FAILURE);
	}

	struct settings_t settings;

	settings.inputFileName = argv[1];

	settings.outputFileName = (char *) malloc(strlen(settings.inputFileName)
					 + strlen(DECODING_SUFFIX));

	strcpy(settings.outputFileName, settings.inputFileName);
	strcat(settings.outputFileName, DECODING_SUFFIX);

	decode(&settings);

	free(settings.outputFileName);

	return 0;
}
