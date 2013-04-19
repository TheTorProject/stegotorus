#include "jpgSteg.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int jpg_steg::read_file(const char *file_name, void* buffer, int bs)
{
	FILE *fp = fopen(file_name, "rb");
	if (!fp) return 0;
	fseek(fp, 0, SEEK_END);
	int fs = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	int r = 0;
	if (fs < bs) {
		r = fread(buffer, sizeof(char), fs, fp);
	} else {
		LOG("Error: Buffer not large enough\n")
	}
	fclose(fp);
	return r;
}

int jpg_steg::modify_huffman_table(char *raw_data, int len)
{
	int i;
	int counter = 0;
	unsigned char *raw = (unsigned char *) raw_data;
	for (int i = 0; i < len-1; i++) {
		if (raw[i] == FRAME && raw[i+1] == FRAME_HUFFMAN) {
			short *s = (short *) (raw+i+2);
			unsigned short len = SWAP(*s);
			short codes = len - 3 - 16;
			LOG("Huffman Table Codes: %hd\n", codes)
			int j;
			for (j = 0; j < codes; j++) {
				raw[i+5+j+16] = 1;
			}
			counter++;
		}
	}
	return counter;
}

int jpg_steg::corrupt_reset_interval(char *raw_data, int len)
{
	int i;
	int counter = 0;
	unsigned char *raw = (unsigned char *) raw_data;
	for (i = 0; i < len-1; i++) {
		if (raw[i] == FRAME && raw[i+1] == FRAME_RST) {
			short *ri = (short *) (raw+i + 2);
			*ri = 0xFFFF;
			counter++;
		}
	}
	return counter;
}

int jpg_steg::starting_point(const char *raw_data, int len)
{
	int i;
	int lm; // Last Marker
	//long lf; // Last Frame
	unsigned char *raw = (unsigned char *) raw_data;
	for (i = 0; i < len-1; i++) {
		if (raw[i] == FRAME && raw[i+1] == FRAME_SCAN) {
			lm = i;
			LOG("0xFFDA at %06X\n", i)
		} else if (raw[i] == FRAME && raw[i+1] == FRAME_RST) {
			LOG("0xFFDD at %06X\n", i)
		} else if (raw[i] == FRAME && raw[i+1] == FRAME_RST0) {
			LOG("0xFFD0 at %06X\n", i)
		}
	}
	const unsigned short *flen = (const unsigned short *)(raw+lm+2); // Frame length
	unsigned short swapped = SWAP(*flen);
	LOG("Size of the last DA frame: %hhu at %06X\n", swapped, lm)

	// TODO: Ignore RSTn bytes (Restart Interval)	
	/*
	long lf2;
	for (i = lm+*flen; i < len-1; i++) {
		if (raw[i] == 0xFF && raw[i+1] != 0x00) {
			printf("nooo FF%hhX\n", raw[i+1]);
			lf2 = i;
			//break;
		}
	}
	*/
	//int c = lf - lm - *flen - 2;

	return lm + 2 + *flen; // 2 for FFDA, and skip the header
}

int jpg_steg::capacity(const char *raw, int len)
{
	int from = starting_point(raw, len);
	return len - from - 2 - sizeof(int); // 2 for FFD9, 4 for len
}

int jpg_steg::encode(char *raw, int blen, const char *data, int dlen)
{
	int from = starting_point(raw, blen);
	int c = capacity(raw, blen);
	memcpy(raw+from, &dlen, sizeof(dlen));
	memcpy(raw+from+sizeof(dlen), data, dlen);
	return 0;
}

int jpg_steg::decode(const char *raw, int blen, char *data)
{
	// TODO: There may be FFDA in the data
	int from = starting_point(raw, blen);
	int s = (int)*(raw+from);
	memcpy(data, raw+from+sizeof(int), s);
	return s;
}

int jpg_steg::test(char file_name[])
{
	char buffer[MAX_BUFFER];
	int len;
	if (!(len = read_file(file_name, buffer, MAX_BUFFER))) {
		printf("Cannot open the file. Aborting ...\n");
		return 1;
	}
	printf("size: %d\n", len);
	
	modify_huffman_table(buffer, len);

	corrupt_reset_interval(buffer, len);

	int c = capacity(buffer, len);
	printf("Capacity: %d\n", c);

	LOG ("Encoding ...\n")
	encode(buffer, len, (char *) "abcdefghijklmnopqrstuvwxyz1234567890", 37);

	LOG("Decoding ...\n")
	char data[100];
	int l = decode(buffer, len, data);
	printf("Size: %d\nData: %s\n", l, data);
	return 0;
}

int jpg_steg::http_server_transmit(payloads& pl, struct evbuffer *source, conn_t *conn)
{
	evbuffer* dest = conn_t->outbound();
	if (!get_payload(pl, HTTP_CONTENT_JPEG, -1, &resp, &resp_len)) {
		log_warn("jpgSteg: no suitable payload found\n");
		return -1;
	}
        // put source into resp
}

int jpg_steg::http_client_receive(steg_t *s, conn_t *conn, evbuffer *dest, evbuffer *source)
{
	
}

int main2(int argc, char *argv[])
{
	char file_name[MAX_FILENAME];
	if (argc > 1)
		strcpy(file_name, argv[1]);
	else
		strcpy(file_name, DEFAULT_FILE);
	
	jpg_steg jsteg;
	
	jsteg.test(file_name);
	return 0;
}
