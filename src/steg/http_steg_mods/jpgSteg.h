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
protected:
 	static int starting_point(const uint8_t *raw, int len);

	int modify_huffman_table(uint8_t *raw, int len);

	int corrupt_reset_interval(uint8_t *raw, int len);

public:

    /**
       returns the capacity of the data you can store in jpeg response
       given the jpeg file content in 

       @param buffer: the buffer containing the payload
       @param len: the buffer's length

       @return the capacity that the buffer can cover or < 0 in case of error
     */
	virtual ssize_t capacity(const uint8_t *buffer, size_t len);
	static unsigned int static_capacity(char *buffer, int len);

    /**
       constructor just to call parent constructor
    */
    JPGSteg(PayloadServer* payload_provider, double noise2signal = 0);

    virtual int encode(uint8_t* data, size_t data_len, uint8_t* cover_payload, size_t cover_len);
    
	virtual ssize_t decode(const uint8_t* cover_payload, size_t cover_len, uint8_t* data);

};

#endif // __JPG_STEG_H
