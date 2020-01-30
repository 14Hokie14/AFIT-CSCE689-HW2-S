#include <argon2.h>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <algorithm>
#include <cstring>
#include <list>
#include <fstream>
#include <sstream>
#include "PasswdMgr.h"
#include "FileDesc.h"
#include "strfuncts.h"

const int hashlen = 32;
const int saltlen = 16;

PasswdMgr::PasswdMgr(const char *pwd_file):_pwd_file(pwd_file) {

}


PasswdMgr::~PasswdMgr() {

}

/*******************************************************************************************
 * checkUser - Checks the password file to see if the given user is listed
 *
 *    Throws: pwfile_error if there were unanticipated problems opening the password file for
 *            reading
 *******************************************************************************************/

bool PasswdMgr::checkUser(const char *name) {
   // Variable set up
   std::ifstream pwfile("passwd");
   std::string line; 

   // First see if file is empty
   if(pwfile.peek() == EOF){ return false; }
   
   // Iterate over each line looking for the user name
   while (std::getline(pwfile, line)){
      clrNewlines(line); // remove the \r \n if there
      if(line == name){
         return true; 
      }
   }

   return false;  
}

/*******************************************************************************************
 * checkPasswd - Checks the password for a given user to see if it matches the password
 *               in the passwd file
 *
 *    Params:  name - username string to check (case insensitive)
 *             passwd - password string to hash and compare (case sensitive)
 *    
 *    Returns: true if correct password was given, false otherwise
 *
 *    Throws: pwfile_error if there were unanticipated problems opening the password file for
 *            reading
 *******************************************************************************************/

bool PasswdMgr::checkPasswd(const char *name, const char *passwd) {
   std::vector<uint8_t> userhash; // hash from the password file
   std::vector<uint8_t> passhash; // hash derived from the parameter passwd
   std::vector<uint8_t> salt;

   // Check if the user exists and get the passwd string
   if (!findUser(name, userhash, salt))
      return false;

   hashArgon2(passhash, salt, passwd, &salt);

   if (userhash == passhash)
      return true;

   return false;
}


/*******************************************************************************************
 * changePasswd - Changes the password for the given user to the password string given. 
 *    To do this, I copy the whole file into a string stream line by line, but when 
 *    I get to the name and hash/salt I'm trying to edit I call the hashArgon2 and add 
 *    the new password hash into the stringstream, and finish copying the file into the
 *    stringstream.  Then I overwrite passwd with the contents of the stringstream
 *
 *    Params:  name - username string to change (case insensitive)
 *             passwd - the new password (case sensitive)
 *
 *    Returns: true if successful, false if the user was not found
 *
 *    Throws: pwfile_error if there were unanticipated problems opening the password file for
 *            writing
 *
 *******************************************************************************************/

bool PasswdMgr::changePasswd(const char *name, const char *passwd) {
   // Check to see if user exists
   if(!checkUser(name)){ return false; }

   // Variable set up:
   std::vector<uint8_t> salt, hash; 
   std::string line;
   std::string check(name);
   std::fstream read_pw_file(_pwd_file.c_str(), std::ios_base::in | std::ios_base::out | std::ios_base::binary);
   

   // Iterate over file, search for the name to grab the salt, then copy the line
   // into the string stream.
   while(std::getline(read_pw_file, line)){
      if(line == check){
         // The fstream is at the first character of the hash now, save this position
         auto hashStart = read_pw_file.tellg();
         
         // Get the hash and salt, then clear the hash
         for(int i = 0; i < hashlen; i++){
            hash.push_back(read_pw_file.get());
         }
         for(int i = 0; i < saltlen; i++){
            salt.push_back(read_pw_file.get());
         }
         hash.clear();

         // Get the hash with the salt
         hashArgon2(hash, salt, passwd, &salt);

         // Use seek to put the fstream back at the hashStart
         read_pw_file.seekp(hashStart);

         // Now overwrite the hash then break
         read_pw_file.write(reinterpret_cast<char*>(&hash[0]), hashlen);

         break;
      }
   }
   // Remember to close the file
   read_pw_file.close();
   return true;
}

/*****************************************************************************************************
 * readUser - Taking in an opened File Descriptor of the password file, reads in a user entry and
 *            loads the passed in variables
 *
 *    Params:  pwfile - FileDesc of password file already opened for reading
 *             name - std string to store the name read in
 *             hash, salt - vectors to store the read-in hash and salt respectively
 *
 *    Returns: true if a new entry was read, false if eof reached 
 * 
 *    Throws: pwfile_error exception if the file appeared corrupted
 *
 *****************************************************************************************************/

bool PasswdMgr::readUser(FileFD &pwfile, std::string &name, std::vector<uint8_t> &hash, std::vector<uint8_t> &salt)
{
   // Try to read the next line
   if(pwfile.readStr(name) == -1){
      // If -1 then there is nothing else to read in the FileFD
      name.clear();
      return false; 
   } else {
      // We got a name, remove the \n \r 
      clrNewlines(name); 
      
      // Now use the readBytes function to read in the next line, store it in a vector called line
      std::vector<uint8_t> line;
      int length = hashlen + saltlen;
      pwfile.readBytes(line, length);

      // Now that line contains our hash and salt, fill in hash and salt
      for(int i = 0; i < hashlen; i++){
         hash.push_back(line[i]);
      }
      for(int i = hashlen; i < hashlen + saltlen; i++){
         salt.push_back(line[i]);
      }

      unsigned char newLine; // Have to call getByte to get the newline at the end of this line too!
      pwfile.readByte(newLine); // Don't actually do anything with it. 
      
   }
   
   // If we got here return true
   return true;
}

/*****************************************************************************************************
 * writeUser - Taking in an opened File Descriptor of the password file, writes a user entry to disk
 *
 *    Params:  pwfile - FileDesc of password file already opened for writing
 *             name - std string of the name 
 *             hash, salt - vectors of the hash and salt to write to disk
 *
 *    Returns: bytes written
 *
 *    Throws: pwfile_error exception if the writes fail
 *
 *****************************************************************************************************/

int PasswdMgr::writeUser(FileFD &pwfile, std::string &name, std::vector<uint8_t> &hash, std::vector<uint8_t> &salt)
{
   int results = 0;

   // To add between the name and after the hash and salt
   const char newLine ('\n'); 

   // Write the name to file, then newline
   for(char& c : name){
      pwfile.writeByte(c);
      results++; 
   }
   pwfile.writeByte(newLine);
   results++; 

   // Write the hash and salt, no spaces, then the new line
   for(auto i = 0; i < hash.size(); i++){
      pwfile.writeByte(hash[i]);
      results++;
   }
   for(auto i = 0; i < salt.size(); i++){
      pwfile.writeByte(salt[i]);
      results++;
   }
   pwfile.writeByte(newLine);
   results++; 

   return results; 
}

/*****************************************************************************************************
 * findUser - Reads in the password file, finding the user (if they exist) and populating the two
 *            passed in vectors with their hash and salt
 *
 *    Params:  name - the username to search for
 *             hash - vector to store the user's password hash
 *             salt - vector to store the user's salt string
 *
 *    Returns: true if found, false if not
 *
 *    Throws: pwfile_error exception if the pwfile could not be opened for reading
 *
 *****************************************************************************************************/

bool PasswdMgr::findUser(const char *name, std::vector<uint8_t> &hash, std::vector<uint8_t> &salt) {
   // Check first to see if the user exists in our passwd file
   if(!checkUser(name)){
      hash.clear();
      salt.clear();
      return false; 
   }

   FileFD pwfile(_pwd_file.c_str());

   // You may need to change this code for your specific implementation

   if (!pwfile.openFile(FileFD::readfd))
      throw pwfile_error("Could not open passwd file for reading");

   // Password file should be in the format username\n{32 byte hash}{16 byte salt}\n
   bool eof = false;
   while (!eof) {
      std::string uname;
      hash.clear();
      salt.clear();
      uname.clear();

      if (!readUser(pwfile, uname, hash, salt)) {
         eof = true;
         continue;
      }

      if (!uname.compare(name)) {
         pwfile.closeFD();
         return true;
      }
   }

   hash.clear();
   salt.clear();
   pwfile.closeFD();
   return false;
}


/*****************************************************************************************************
 * hashArgon2 - Performs a hash on the password using the Argon2 library. Implementation algorithm
 *              taken from the http://github.com/P-H-C/phc-winner-argon2 example. 
 *
 *    Params:  dest - the std string object to store the hash
 *             passwd - the password to be hashed
 *
 *    Throws: runtime_error if the salt passed in is not the right size
 *****************************************************************************************************/
void PasswdMgr::hashArgon2(std::vector<uint8_t> &ret_hash, std::vector<uint8_t> &ret_salt, 
                           const char *in_passwd, std::vector<uint8_t> *in_salt) {
   
   // Check to see if in_salt is empty, if it is make a salt
   srand(time(0)); // Change the seed so we don't have the same salt every time
   if(in_salt->size() == 0 || in_salt == NULL){
      for (auto i = 0; i < saltlen; i++){
         // This generates a random number bettwen 65 (A in ascii) to 122 (z)
         ret_salt.push_back((rand() % 57) + 65);
      }
   }

   // Set up variables to pass into the argon method
   uint8_t hash[hashlen];
   uint8_t salt[saltlen];

   uint32_t t_cost = 2;            // 1-pass computation
   uint32_t m_cost = (1<<16);      // 64 mebibytes memory usage
   uint32_t parallelism = 1;       // number of threads and lanes

   std::string pwd (in_passwd);  // I turn the in_passwd to a string for more functionality

   // Fill in the salt 
   if(in_salt->size() == 0){
      for(auto i = 0; i < saltlen; i++){
         salt[i] = ret_salt[i];
      }
   } else {
      // There was a salt passed in
      for(auto i = 0; i < saltlen; i++){
         salt[i] = in_salt->at(i);
         
         // Since I'm already iterating over in_salt here might as well set up the ret_salt  
         ret_salt.push_back(in_salt->at(i));
      }
   }

   // Use the high-level API for argon 2
   argon2i_hash_raw(t_cost, m_cost, parallelism, in_passwd, strlen(in_passwd), salt, saltlen, hash, hashlen);
   
   // Put the hash into ret_hash 
   for(auto i = 0; i < hashlen; i++){
      ret_hash.push_back(hash[i]);
   }
}

/****************************************************************************************************
 * addUser - Adds the new user with a new password and salt
 *
 *    Throws: pwfile_error if issues editing the password file
 ****************************************************************************************************/

void PasswdMgr::addUser(const char *name, const char *passwd) {
   // Variable set up
   std::vector<uint8_t> hash; 
   std::vector<uint8_t> salt; 
   std::vector<uint8_t> in_salt;

   // Hash the password
   hashArgon2(hash, salt, passwd, &in_salt);

   // Now open up the passwd file and add the username, hash and salt:

   // Make the FileFD
   FileFD pwfile(_pwd_file.c_str());

   // Open the file with append flag
   if (!pwfile.openFile(FileFD::appendfd))
      throw pwfile_error("Could not open passwd file for reading");
   
   // Write the username, add the \n to the end
   std::string userName(name);
   lower(userName);
   userName.append("\n");
   pwfile.writeFD(userName);

   // Now write the hash and salt one byte at a time
   pwfile.writeBytes<uint8_t>(hash);
   pwfile.writeBytes<uint8_t>(salt);
   pwfile.writeFD("\n");

}

