/* Copyright 2012 vmon
   See LICENSE for other credits and copying information
*/
#ifndef PAYLOADSCRAPER_H
#define PAYLOADSCRAPER_H

#include <map>

#include "file_steg.h"

class PayloadScraperTest;
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
  std::string _database_filename;
  std::ofstream _payload_db;

  DummyPayloadServer dummy_payload_server; //needed for instantiating 

  std::map<size_t, FileStegMod*> _available_file_stegs;
                                      
  std::string _cover_server;
  std::string _cover_list;  //List of url of the covers on _cover_server
  std::string _apache_conf_filename;
  std::string _apache_doc_root; /* the directory that apache serve where
                               the html doc*/
    
    CURL* capacity_handle;    /* We use this auxiliary curl handle
                               in task of computing the capacity of the 
                               payloads */

    /**
       Computes the capacity and length of a filename indicated by a url as well as the  hash of the url.

       @param cur_url url to the resource
       @param cur_steg pointer to the steg_type object corresponding to the 
              type of the url
       
       @return space separated string of hash, capacity, length
    */
    const std::string scrape_url(const std::string& cur_url, size_t cur_steg, bool absolute_url = false);

    /**
       Scrapes list of urls of cover filename
       
       @param list_filename the name of the file that contains the list of urls

       @return number of payload if successful -1 if it fails.
    */
    int scrape_url_list(const std::string list_filename);

    /**
       Scrapes a directory, recursively calls itself for
       for subdirs, return number of payload if successful -1 
       if it fails.

       @param cur_dir the name of the dir to be scraped
     */
    int scrape_dir(const std::string cur_dir);

   /**
       open the apache configuration file, search for DocumentRoot
       and set the 
   */
   int apache_conf_parser();

   
public:
   /**
       Use curl to get the payload in the way that Apache is going to serve
       it and compute it's capacity. return the pair (length of the payload,
       capacity of the payload) otherwise (0,0) if not successful
       
       @param payload_url The relative (to the apache_root) filename of the 
                          payload
       @param cur_steg    The steg mode correspond to the type of the file to 
                          to compute the capacity
       @param absolute_url true if the url has the scheme and the server name
                          false if it is just an address on the server
   */
   pair<unsigned long, unsigned long>  compute_capacity(std::string payload_url, FileStegMod* cur_steg, bool absolute_url = false);

   /**
      The constructor, calls the scraper by default

      @param database_filename the name of the file to store the payload list   
      @param cover_list a list of potential cover on the cover server to avoid ftp access
    */
   PayloadScraper(std::string database_filename,  std::string cover_server, const std::string& cover_list = "", const std::string apache_conf = "/etc/httpd/conf/httpd.conf");

   /**
      reads all the files in the Doc root and classifies them. return the number of payload file founds. -1 if it fails
   */
   int scrape();

   // virtual ~PayloadScraper()
   //   {
   //   }
     

};
#endif
