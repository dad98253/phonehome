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
	// (file_size / 3) * 4 + potential padding + null terminator
	size_t encoded_buffer_size = (file_size + 2) / 3 * 4 + file_size / 76 * 2
			+ 20;
	char *encoded_data = calloc(encoded_buffer_size, 1);
	if (!encoded_data) {
		perror("Error allocating memory");
		fclose(fp);
		return NULL;
	}

	unsigned char in_buffer[3];
	unsigned char out_buffer[4];
	int bytes_read;
	size_t current_out_pos = 0;

	while ((bytes_read = fread(in_buffer, 1, 3, fp)) > 0) {
		if ( (current_out_pos % 78) == 0) {
			memcpy(encoded_data + current_out_pos, CRLF, 2);
			current_out_pos += 2;
		}
		encode_block(in_buffer, out_buffer, bytes_read);
		memcpy(encoded_data + current_out_pos, out_buffer, 4);
		current_out_pos += 4;
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

