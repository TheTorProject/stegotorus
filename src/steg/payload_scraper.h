/* Copyright 2012 vmon
   See LICENSE for other credits and copying information
*/
#ifndef PAYLOADSCRAPER_H
#define PAYLOADSCRAPER_H


//TODO: This structure should be depricated as the FileSteg as
//parent type should replace it
struct steg_type
{
   int type;
   string  extension;
   unsigned int (*capacity_function)(char* payload, int len);

};

/**
    We read the /etc/httpd/conf/httpd.conf (this need to be more dynamic)
    but I'm testing it on my system which is running arch) find
    the DocumentRoot. Then it will check the directory recursively and
    gather the name of all files of pdf, swf and js type and store them
    in a database file.
*/

class PayloadScraper
{
protected:
    string _database_filename;
    ofstream _payload_db;
    steg_type* _available_stegs;
    FileStegMod* _available_file_stegs[c_no_of_steg_protocol+1]; //Later when all stegs
               //were converted to this
               //we don't need _available_stegs type. At the moment I have to 
               //actually instantiate because the capacity function is virtual
               //from this
                                      
    
    string _apache_conf_filename;
    string _apache_doc_root; /* the directory that apache serve where
                               the html doc*/

    CURL* capacity_handle;    /* We use this auxiliary curl handle
                               in task of computing the capacity of the 
                               payloads */

    /**
       Scrapes current directory, recursively calls itself for
       for subdirs, return number of payload if successful -1 
       if it fails.

       @param cur_dir the name of the dir to be scraped
     */
    int scrape_dir(const path cur_dir);

   /**
       open the apache configuration file, search for DocumentRoot
       and set the 
   */
   int apache_conf_parser();

   /**
       Use curl to get the payload in the way that Apache is going to serve
       it and compute it's capacity. return the pair (length of the payload,
       capacity of the payload) otherwise (0,0) if not successful
       
       @param payload_url The relative (to the apache_root) filename of the 
                          payload
   */
   pair<unsigned long, unsigned long>  compute_capacity(string payload_url, steg_type* cur_steg);
   
public:
   /**
      The constructor, calls the scraper by default

      @param database_filename the name of the file to store the payload list   
    */
   PayloadScraper(string database_filename,  const string apache_conf = "/etc/httpd/conf/httpd.conf");

   /**
      reads all the files in the Doc root and classifies them. return the number of payload file founds. -1 if it fails
   */
   int scrape();

};
#endif
