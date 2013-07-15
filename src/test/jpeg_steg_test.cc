//Vmon: I just moved all function that Parsaa included for testing jpeg steg here,
// later these should be re-arranged into unit-test class

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
