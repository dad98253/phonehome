/*
 * base64.c
 *
 *  Created on: Nov 25, 2025
 *      Author: dad
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Base64 character set
static const char *base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// Function to encode 3 bytes into 4 Base64 characters
void encode_block(unsigned char in[3], unsigned char out[4], int len) {
    out[0] = base64_chars[(in[0] & 0xFC) >> 2];
    out[1] = base64_chars[((in[0] & 0x03) << 4) | ((in[1] & 0xF0) >> 4)];
    out[2] = (unsigned char) (len > 1 ? base64_chars[((in[1] & 0x0F) << 2) | ((in[2] & 0xC0) >> 6)] : '=');
    out[3] = (unsigned char) (len > 2 ? base64_chars[in[2] & 0x3F] : '=');
}

// Main encoding logic (simplified)
char *base64_encode_file(const char *filepath, size_t *output_len) {
	char *CRLF = "\r\n";
	FILE *fp = fopen(filepath, "rb");
	if (!fp) {
		perror("Error opening file");
		return NULL;
	}
	// Determine file size
	fseek(fp, 0, SEEK_END);
	long file_size = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	// Calculate required output buffer size
	size_t numEncodedBytes = (file_size + 2) / 3 * 4; // (max)
	size_t numLines = (file_size + 3) / 3 * 4 / 76 + 1;
	size_t padding = 20;
	size_t encoded_buffer_size = numEncodedBytes + numLines * 2 + padding;
	char *encoded_data = (char *)calloc(encoded_buffer_size, 1);
	if (!encoded_data) {
		perror("Error allocating memory");
		fclose(fp);
		return NULL;
	}
	unsigned char in_buffer[3];
	unsigned char out_buffer[4];
	int bytes_read;
	size_t current_out_pos = 0;
	unsigned long long int numlines = 0;
#ifdef DEBUGBASE64
	unsigned long long int lastloc = 0;
	unsigned long long int linelen = 0;
#endif	// DEBUGBASE64
	while ((bytes_read = fread(in_buffer, 1, 3, fp)) > 0) {
		if ( bytes_read < 0 || bytes_read > 3 ) {
			perror("bad number of bytes returned while reading tar file");
			fclose(fp);
			return NULL;
		}
		if ( (current_out_pos % 78) == 0) {
			memcpy(encoded_data + current_out_pos, CRLF, 2);
			current_out_pos += 2;
			numlines++;
#ifdef DEBUGBASE64
			linelen = current_out_pos - lastloc;
			printf("linelen,numlines = %lld,%lld\n",linelen,numlines);
			lastloc = current_out_pos;
#endif	// DEBUGBASE64
		}
		encode_block(in_buffer, out_buffer, bytes_read);
		memcpy(encoded_data + current_out_pos, out_buffer, 4);
		current_out_pos += 4;
		if ( bytes_read < 3 ) {
			if ( feof(fp) ) {
				printf("EOF reading tar file");
				break;
			}
			if ( ferror(fp) ) {
				perror("Error reading tar file");
				break;
			}
		}
	}
	encoded_data[current_out_pos] = '\0'; // Null-terminate
	*output_len = current_out_pos;

	fclose(fp);
	return encoded_data;
}

void testBase64 (char * attachment_path) {
	size_t output_len;
	char * string = base64_encode_file(attachment_path, &output_len);
	printf("--- testBase64 test file %s ---\n",attachment_path);
	printf("%s\n", string);
	printf("--- End of test file --- (output length is %ld Bytes\n",output_len);
	free(string);
	return;
}

