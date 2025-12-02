/*
 * parse_words.c
 *
 *  Created on: Dec 1, 2025
 *      Author: dad, ChatGPT
 */

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

static void skip_whitespace(const char **p) {
    while (**p && isspace((unsigned char)**p)) {
        (*p)++;
    }
}

int parse_words(const char *buf, char ***args) {
    *args = NULL;

    if (!buf) return -1;

    const char *p = buf;
    int count = 0;
    if ( *buf == '#' ) return 0;

    // -------------------------------------------------------------
    // FIRST PASS — COUNT TOKENS
    // -------------------------------------------------------------
    while (1) {
        skip_whitespace(&p);
        if (!*p) break;

        count++;

        if (*p == '"') {
            // Quoted substring
            p++;  // Skip opening "
            while (*p) {
                if (*p == '\\') {
                    // skip escaped char
                    p++;
                    if (*p) p++;
                } else if (*p == '"') {
                    p++;  // closing "
                    break;
                } else {
                    p++;
                }
            }
        } else {
            // Unquoted word
            while (*p && !isspace((unsigned char)*p)) {
                if (*p == '\\') {
                    p++;
                    if (*p) p++;
                } else {
                    p++;
                }
            }
        }
    }

    if (count == 0) return 0;

    // -------------------------------------------------------------
    // Allocate args array
    // -------------------------------------------------------------
    char **array = malloc(count * sizeof(char *));
    if (!array) return -2;

    // -------------------------------------------------------------
    // SECOND PASS — EXTRACT TOKENS, ALLOCATE STRINGS
    // -------------------------------------------------------------
    p = buf;
    int idx = 0;

    while (idx < count) {
        skip_whitespace(&p);
        if (!*p) break;

        int in_quotes = 0;

        if (*p == '"') {
            in_quotes = 1;
            p++;   // skip opening "
        }

        // First: determine decoded length
        size_t decoded_len = 0;
        const char *q = p;

        if (in_quotes) {
            while (*q) {
                if (*q == '\\') {
                    q++;
                    if (*q) {
                        decoded_len += 1;
                        q++;
                    }
                } else if (*q == '"') {
                    break;   // end of quoted region
                } else {
                    decoded_len++;
                    q++;
                }
            }
        } else {
            while (*q && !isspace((unsigned char)*q)) {
                if (*q == '\\') {
                    q++;
                    if (*q) {
                        decoded_len += 1;
                        q++;
                    }
                } else {
                    decoded_len++;
                    q++;
                }
            }
        }

        // Allocate space for token
        char *word = malloc(decoded_len + 1);
        if (!word) {
            for (int i = 0; i < idx; i++) free(array[i]);
            free(array);
            return -3;
        }

        // Now extract & decode characters
        size_t w = 0;
        while (*p) {
            if (in_quotes) {
                if (*p == '\\') {
                    p++;
                    if (*p) {
                        word[w++] = *p++;
                    }
                } else if (*p == '"') {
                    p++;  // consume closing quote
                    break;
                } else {
                    word[w++] = *p++;
                }
            } else {
                if (isspace((unsigned char)*p))
                    break;

                if (*p == '\\') {
                    p++;
                    if (*p) {
                        word[w++] = *p++;
                    }
                } else {
                    word[w++] = *p++;
                }
            }
        }

        word[w] = '\0';
        array[idx++] = word;

        // If quoted, p now points after closing "
        // If unquoted, p is at whitespace or end
    }

    *args = array;
    return count;
}



