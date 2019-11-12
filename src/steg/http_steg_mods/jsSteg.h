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
  int starting_point(const uint8_t *raw, int len);

public:
    /**
       compute the capcaity of the cover by getting a pointer to the
       beginig of the body in the response

       @param cover_body pointer to the begiing of the body
       @param body_length the total length of message body
    */
    virtual ssize_t headless_capacity(const std::vector<uint8_t>& cover_body);

    /**
       constructor just to call parent constructor
    */
    JPGSteg(PayloadServer& payload_provider, double noise2signal = 0);

    virtual ssize_t encode(const std::vector<uint8_t>& data, std::vector<uint8_t>& cover_payload);
    
	virtual ssize_t decode(const std::vector<uint8_t>& cover_payload, std::vector<uint8_t>& data);

};

#endif // __JPG_STEG_H
