/* Copyright 2012 vmon
   See LICENSE for other credits and copying information
*/

#include <algorithm> //removing quotes from path
#include <fstream> 
#include <string>
#include <sstream> 
#include <stdio.h>

using namespace std;

#include "util.h"
#include "crypt.h"
#include "payload_server.h"
#include "curl_util.h"
#include "http_steg_mods/file_steg.h"
#include "http_steg_mods/jpgSteg.h"
#include "http_steg_mods/pngSteg.h"
#include "http_steg_mods/gifSteg.h"
#include "http_steg_mods/swfSteg.h"
#include "http_steg_mods/pdfSteg.h"
#include "http_steg_mods/htmlSteg.h"

#include "payload_scraper.h"
#include "base64.h"

#include "protocol/chop_blk.h" //We need this to no what's the minimum 

#if HAVE_BOOST == 1
#include <boost/filesystem.hpp>
#endif
//acceptable capacity

#define TEMP_MOUNT_DIR "/tmp/remote_www"
/** We read the /etc/httpd/conf/httpd.conf (this need to be more dynamic)
    but I'm testing it on my system which is running arch) find
    the DocumentRoot. Then it will check the directory recursively and
    gather the name of all files of pdf, swf and js type and store them
    in a database file.
*/

/**
   Computes the capacity and length of a filename indicated by a url as well as the  hash of the url.

   @param cur_url url to the resource
   @param cur_steg pointer to the steg_type object corresponding to the type 
          of the url
          
   @return space separated string of hash, capacity, length
*/
const string
PayloadScraper::scrape_url(const string& cur_url, steg_type* cur_steg, bool absolute_url)
{
  char url_hash[20];
  char url_hash64[40];

  string rel_url = absolute_url ? relativize_url(cur_url) : cur_url;

  sha256((const unsigned char *)(rel_url.c_str()), rel_url.length(), (unsigned char*)url_hash);
  base64::encoder url_hash_encoder;
  url_hash_encoder.encode(url_hash, 20, url_hash64);
                        
  pair<unsigned long, unsigned long> fileinfo = compute_capacity(cur_url, cur_steg, absolute_url);
  unsigned long cur_filelength = fileinfo.first;
  unsigned long capacity = fileinfo.second;

  log_debug("capacity %lu:", capacity);
  
  //if the file is too big then we don't will not be able to fit in HTTP_MSG_BUF
  if (cur_filelength > HTTP_PAYLOAD_BUF_SIZE)
    return "";
        
  if (capacity < chop_blk::MIN_BLOCK_SIZE) return ""; //This is not the 
  //what you want, I think chop should be changed so the steg be allowed
  //to ignore totally corrupted package and chop should be allowed to send
  //package with 0 room.

  //We are not going to transfer more than one block size per
  //payload so If capacity is bigger than chop_blk::MAX_BLOCK_SIZE
  //we set it back at that
  if (capacity > chop_blk::MAX_BLOCK_SIZE) 
    capacity = chop_blk::MAX_BLOCK_SIZE;

  stringstream scraped_entry;
  scraped_entry << url_hash64 << " " << capacity << " " << cur_filelength;

  return scraped_entry.str();

}

/**
   Scrapes current directory, recursively. it uses a boost library.
   returns number of payload if successful -1 if it fails.

   @param cur_dir the name of the dir to be scraped
*/
int 
PayloadScraper::scrape_dir(const string dir_string_path)
{
  long int total_file_count = 0;

#if HAVE_BOOST == 1
  using namespace boost::filesystem;

  path dir_path(dir_string_path);

  if ( !exists( dir_path ) ) 
      return -1;

  recursive_directory_iterator end_itr; // default construction yields past-the-end
   for ( recursive_directory_iterator itr( dir_path );
        itr != end_itr;
        ++itr, total_file_count++)
    {
      for(steg_type* cur_steg = _available_stegs; cur_steg->type!= 0; cur_steg++)
        if (cur_steg->extension == itr->path().extension().string())
          {
            string cur_filename(itr->path().generic_string());
            log_debug("checking %s for capacity...", cur_filename.c_str());
            string cur_url(cur_filename.substr(_apache_doc_root.length(), cur_filename.length() -  _apache_doc_root.length()));

            string scrape_result = scrape_url(cur_url, cur_steg);
            if (!scrape_result.empty())
              _payload_db << total_file_count << " " << cur_steg->type << " " << scrape_result  << " " << cur_url << " " << 0 << " " << cur_url << "\n"; //absolute_url false
          }
    }

#else
   (void) dir_string_path;
   log_abort("unable to scrape dir when made without boost");
#endif
  return total_file_count; 

}

/**
   Scrapes list of urls of cover filename

   @param list_filename the name of the file that contains the list of urls

   @return number of payload if successful -1 if it fails.
*/
int 
PayloadScraper::scrape_url_list(const string list_filename)
{
  long int total_file_count = 0;
  std::map<std::string, bool> scraped_tracker; //keeping track of url repetition

  if ( !file_exists_with_name( list_filename ) ) {
    log_warn("cover list file does not exsits.");
    return -1;
  }

  std::ifstream url_list_stream(list_filename);
  if (!url_list_stream.is_open()) {
    log_warn("Cannot open url list file.");
    return -1;
  }
  
  string file_url, cur_url_ext;
  unsigned long total_processed_items = 0;
  while (url_list_stream >> file_url) {
    total_processed_items++;
    if (scraped_tracker.find(file_url) != scraped_tracker.end()) {
      //make sure it is not a repetition of a url we already have
      //scraped
      log_warn("already have scraped %s", file_url.c_str());
      continue;
    }
    
    total_file_count++;
    size_t last_slash = file_url.rfind("/");
    if (last_slash == string::npos) //AFAIK url needs one slash
      continue; //bad url

    string filename = file_url.substr(last_slash+1);
    size_t last_dot = filename.rfind(".");
    if (last_dot == string::npos) 
      cur_url_ext = ".html"; //no filename assume html
    else
      cur_url_ext = filename.substr(last_dot);

    for(steg_type* cur_steg = _available_stegs; cur_steg->type!= 0; cur_steg++) {
      if (cur_steg->extension == cur_url_ext) {
        string scrape_result = scrape_url(file_url, cur_steg, true);
        if (!scrape_result.empty()) {
            _payload_db << total_file_count << " " << cur_steg->type << " " << scrape_result  << " " << relativize_url(file_url) << " " << 1 << " " << file_url << "\n"; //absolute_url = true
        }
        
      }
    }

    scraped_tracker[file_url] = true;
    log_debug("processed: %ld, scraped: %ld", total_processed_items, total_file_count);

  }

  return total_file_count; 

}

/** 
    The constructor, calls the scraper by default
    
    @param database_filename the name of the file to store the payload list   
*/
PayloadScraper::PayloadScraper(string  database_filename, string cover_server,const string& cover_list, string apache_conf)
  : _available_stegs(),
    _available_file_stegs(), 
   _cover_list(cover_list),
   capacity_handle(curl_easy_init())
{
  /* curl initiation */
  log_assert(capacity_handle);
  curl_easy_setopt(capacity_handle, CURLOPT_HEADER, 1L);
  curl_easy_setopt(capacity_handle, CURLOPT_HTTP_CONTENT_DECODING, 0L);
  curl_easy_setopt(capacity_handle, CURLOPT_HTTP_TRANSFER_DECODING, 0L);
  curl_easy_setopt(capacity_handle, CURLOPT_WRITEFUNCTION, curl_read_data_cb);
  
  _database_filename = database_filename;
  _cover_server = cover_server;
  _apache_conf_filename  = apache_conf;

  /** This is hard coded */
  _available_stegs = new steg_type[c_no_of_steg_protocol+1]; //one to be zero
  //memset(_available_file_stegs[0], (int)NULL, sizeof(FileStegMod*)*(c_no_of_steg_protocol+1)); 

  _available_file_stegs[HTTP_CONTENT_JAVASCRIPT] = new JSSteg(NULL);
  _available_stegs[0].type = HTTP_CONTENT_JAVASCRIPT; _available_stegs[0].extension = ".js";  _available_stegs[0].capacity_function = JSSteg::static_capacity; //Temp measure, later we don't need to do such acrobat

  _available_file_stegs[HTTP_CONTENT_PDF] = new PDFSteg(NULL);
  _available_stegs[1].type = HTTP_CONTENT_PDF; _available_stegs[1].extension = ".pdf"; _available_stegs[1].capacity_function = PDFSteg::static_capacity;

 _available_file_stegs[HTTP_CONTENT_SWF] = new SWFSteg(NULL);
  _available_stegs[2].type = HTTP_CONTENT_SWF; _available_stegs[2].extension = ".swf";  _available_stegs[2].capacity_function = SWFSteg::static_capacity;  //Temp measure, later we don't need to do such acrobatics

  _available_file_stegs[HTTP_CONTENT_HTML] = new HTMLSteg(NULL); 
  _available_stegs[3].type = HTTP_CONTENT_HTML; _available_stegs[3].extension = ".html";  _available_stegs[3].capacity_function = HTMLSteg::static_capacity;

  //in new model, extensions are stored in list so one type can have more ext.
  
  _available_stegs[4].type = HTTP_CONTENT_HTML; _available_stegs[4].extension = ".htm";  _available_stegs[4].capacity_function = JSSteg::static_capacity;

  _available_file_stegs[HTTP_CONTENT_JPEG] = new JPGSteg(NULL); //We are only using the capacity function so we don't need a payload server
  _available_stegs[5].type = HTTP_CONTENT_JPEG; _available_stegs[5].extension = ".jpg"; _available_stegs[5].capacity_function = JPGSteg::static_capacity; //Temp measure, later we don't need to do such acrobat

  _available_file_stegs[HTTP_CONTENT_PNG] = new PNGSteg(NULL); //We are only using the capacity function so we don't need a payload server
  _available_stegs[6].type = HTTP_CONTENT_PNG; _available_stegs[6].extension = ".png"; _available_stegs[6].capacity_function = PNGSteg::static_capacity; //Temp measure, later we don't need to do such acrobat

  _available_file_stegs[HTTP_CONTENT_GIF] = new GIFSteg(NULL); //We are only using the capacity function so we don't need a payload server
  _available_stegs[7].type = HTTP_CONTENT_GIF; _available_stegs[7].extension = ".gif"; _available_stegs[7].capacity_function = GIFSteg::static_capacity; //Temp measure, later we don't need to do such acrobat

  _available_stegs[8].type = 0;

}

/** 
    reads all the files in the Doc root and classifies them. return the number of payload file founds. -1 if it fails
*/
int PayloadScraper::scrape()
{
  bool scrape_succeed = false;
  /* open the database file for write this will delete the
     current content */
  _payload_db.open(_database_filename.c_str());

  if (!_payload_db.is_open())
    {
      log_warn("error opening the payload database file: %s",strerror(errno));
      return -1;
    }

  if (!_cover_list.empty()) {//If user gave us a cover list then we should
    //use it for scraping
    if (scrape_url_list(_cover_list) < 0)
    {
      log_warn("error in retrieving payload urls: %s",strerror(errno));
      //fail to next scraping strategy
    }
    else {
      scrape_succeed = true;
    }
    
  }

#if HAVE_BOOST == 1
  if (!scrape_succeed) { //no url list is given, try to scrape file system only if we have
      //boost
    // looking for doc root dir...
    // If the http server is localhost, then try read localy...
    bool remote_mount = false; //true if the doc_root is mounted from remote host
    string ftp_unmount_command_string = "fusermount -u ";
    ftp_unmount_command_string += TEMP_MOUNT_DIR;
    
    if (_cover_server == "127.0.0.1")
      if (apache_conf_parser())
        log_warn("error in retrieving apache doc root: %s",strerror(errno));
    
    if (_apache_doc_root.empty()) {
      // if the http server is remote or we failed to retrieve the 
      //   doc_root then try to connect to the server through ftp
      //   and mount the www dir
      
      // we need to make directory to mount the remote www dir
      boost::filesystem::path mount_dir(TEMP_MOUNT_DIR);  
      if (!(boost::filesystem::exists(mount_dir) ||
            boost::filesystem::create_directory(mount_dir))) {
        log_warn("Failed to create a temp dir to mount remote filesystem");
        _payload_db.close();
        return -1;
      }
      
      //just try to unmount in case it is already mounted
      int res = system(ftp_unmount_command_string.c_str());
      if (res)
        log_warn("error while trying to unmount ftp folder");

      
      string ftp_mount_command_string = "curlftpfs ftp://";
      ftp_mount_command_string += _cover_server + " " + TEMP_MOUNT_DIR;
      
      int mount_result = system(ftp_mount_command_string.c_str());
      if (mount_result) {
        log_abort("Failed to mount the remote filesystem");
        _payload_db.close();
        return -1;
      }
      
      remote_mount = true;
      _apache_doc_root = TEMP_MOUNT_DIR;
      
    }
    
    /* now all we need to do is to call scrape */
    if (scrape_dir(_apache_doc_root) < 0)
      {
        log_warn("error in retrieving payload dir: %s",strerror(errno));
        _payload_db.close();
        return -1;
      }
    else
      scrape_succeed = true;
    
    if (remote_mount) {
      int res = system(ftp_unmount_command_string.c_str());
      if (res)
        log_warn("error while trying to unmount ftp folder");
    }
  }
#else
  (void) scrape_succeed;
#endif

  _payload_db.close();
  return 0;
  
}

/** 
    open the apache configuration file, search for DocumentRoot
    and set the 

*/
int PayloadScraper::apache_conf_parser()
{
  /* open the apache config file to find the doc root dir*/
  FILE* apache_conf;

  apache_conf = fopen(_apache_conf_filename.c_str(), "rb");
  if (apache_conf == NULL)
    {
      log_warn("error in opening apache config file: %s",strerror(errno));
      return 0;
    }

  char* cur_line = NULL;
  size_t line_length;
  while(~feof(apache_conf))
    {
      xgetline(&cur_line, &line_length, apache_conf);
      /*pass the comment*/
      if ((line_length > 0) && ( cur_line[0] == '#')) continue;

      if (!strncmp(cur_line,"DocumentRoot", strlen("DocumentRoot")))
        {
           _apache_doc_root =  cur_line + strlen("DocumentRoot ");
          _apache_doc_root.erase(remove( _apache_doc_root.begin(), _apache_doc_root.end(), '\"' ), _apache_doc_root.end());
          _apache_doc_root.erase(std::remove( _apache_doc_root.begin(), _apache_doc_root.end(), '\n' ), _apache_doc_root.end());
          if (_apache_doc_root[_apache_doc_root.length()-1] != '/')
            _apache_doc_root.push_back('/');

          return 0;
        }
    }

  /* no suitable tag in apache config file
     I should probably return a defult dir in this case
     but we return error for now
  */
  log_warn("DocumentRoot isn't specified in apache config file");
  return -1;

}

pair<unsigned long, unsigned long> PayloadScraper::compute_capacity(string payload_url, steg_type* cur_steg, bool absolute_url)
{
  unsigned long test_cur_filelength;
  stringstream  payload_buf;

  string url_to_retreive = absolute_url ? payload_url : "http://" + _cover_server +"/" + payload_url;

  unsigned long apache_size = fetch_url_raw(capacity_handle, url_to_retreive, payload_buf);
  
  if (apache_size <= 0) //just invalidate the url
    return pair<unsigned long, unsigned long>(0, 0);
    
  char* buf = new char[apache_size];
  payload_buf.read(buf, apache_size);

  //compute the size
  const char* hend = strstr(buf, "\r\n\r\n");
  if (hend == NULL || (hend - buf + 4) > (ssize_t)apache_size) {
    log_warn("unable to find end of header in the HTTP template");
    delete [] buf;
    return pair<unsigned long, unsigned long>(0, 0);
  }
  
  unsigned long cur_filelength = apache_size - (hend - buf + 4);
  if (cur_filelength == 0) {
    log_warn("The HTTP body seems to be empty");
    delete [] buf;
    return pair<unsigned long, unsigned long>(0, 0);
  }

  if (!absolute_url) {
    test_cur_filelength = file_size(_apache_doc_root + payload_url);
    assert(test_cur_filelength == cur_filelength);
  }
  
  long capacity = cur_steg->capacity_function(buf, apache_size);
  log_debug("capacity: %lu", capacity);
  if (capacity < 0){ 
    log_warn("error occurd during capacity computation");
    capacity = 0;//zero capacity files are dropped
  }

  //no delete need for buf because new is overloaded to handle that
  //TODO:or is it? i see a relative huge memory consumption when the payload 
  //scraperneeds to recompute the db
  delete[] buf; //needs further investigation
  buf = NULL;
  return pair<unsigned long, unsigned long>(cur_filelength, capacity);

}
