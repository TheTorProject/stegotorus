#include "file_steg.h"
#include "jpgSteg.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int JPGSteg::modify_huffman_table(char *raw_data, int len)
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

int JPGSteg::corrupt_reset_interval(char *raw_data, int len)
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

int JPGSteg::starting_point(const char *raw_data, int len)
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

int JPGSteg::capacity(const char *raw, int len)
{
	int from = starting_point(raw, len);
	return len - from - 2 - sizeof(int); // 2 for FFD9, 4 for len
}

int JPGStegMod::(char* data, size_t data_len, char *cover_payload, size_t cover_len)
{
	int from = starting_point(raw, cover_len);
	int c = capacity(cover_payload, cover_len);
	memcpy(raw+from, &dlen, sizeof(dlen));
	memcpy(raw+from+sizeof(dlen), data, dlen);
	return 0;

}

int JPGSteg::decode(const char *cover_payload, int cover_len, char** data)
{
	// TODO: There may be FFDA in the data
	int from = starting_point(cover_payload, cover_len);
	int s = (int)*(raw+from);

    //We need to allocate data here cause it is when we know the data size
    data = new char[s];
	memcpy(data, raw+from+sizeof(int), s);
	return s;

}

