#ifndef __JPG_STEG_H
#define __JPG_STEG_H


//#define DEBUG ON



#define MAX_BUFFER 4*1024*1024
#define MAX_FILENAME 100
#define DEFAULT_FILE "temp.jpg"

#define FRAME 0xFF
#define FRAME_SCAN 0xDA
#define FRAME_RST 0XDD
#define FRAME_RST0 0xD0
#define FRAME_RST7 0xD7
#define FRAME_HUFFMAN 0xC4
#define FRAME_SKIP 0x00

#define SWAP(X) ( (((X) & 0xFF) << 8) + (((X) & 0xFF00) >> 8 ) )

#ifdef DEBUG
#define LOG(X,...) printf(X, ##__VA_ARGS__);
#else
#define LOG(X,...) 
#endif

class JPGSteg : public FileStegMod
{
public: 
	static int capacity(const char *buffer, int len);

	int http_server_transmit(payloads &pl, struct evbuffer *source, conn_t *conn);

	int http_client_receive(steg_t *s, conn_t *conn, struct evbuffer *dest, 
					struct evbuffer *source);

	int test(char file_name[]);

protected:
	int read_file(const char *file_name, void *buffer, int buffer_size);

	static int starting_point(const char *raw, int len);

	int modify_huffman_table(char *raw, int len);

	int corrupt_reset_interval(char *raw, int len);

    virtual int encode(char* data, size_t data_len, char *cover_payload, size_t cover_len);
    
	virtual int decode(const char *cover_payload, int cover_len, char** data);

};

#endif // __JPG_STEG_H
