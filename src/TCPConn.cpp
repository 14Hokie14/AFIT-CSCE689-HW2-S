#include <stdexcept>
#include <strings.h>
#include <unistd.h>
#include <cstring>
#include <algorithm>
#include <iostream>
#include "TCPConn.h"
#include "strfuncts.h"
#include <fstream>
#include "PasswdMgr.h"

// The filename/path of the password file
const char pwdfilename[] = "passwd";

TCPConn::TCPConn(){ // LogMgr &server_log):_server_log(server_log) {

}


TCPConn::~TCPConn() {

}

/**********************************************************************************************
 * accept - simply calls the acceptFD FileDesc method to accept a connection on a server socket.
 *
 *    Params: server - an open/bound server file descriptor with an available connection
 *
 *    Throws: socket_error for recoverable errors, runtime_error for unrecoverable types
 **********************************************************************************************/

bool TCPConn::accept(SocketFD &server) {
   return _connfd.acceptFD(server);
}

/**********************************************************************************************
 * sendText - simply calls the sendText FileDesc method to send a string to this FD
 *
 *    Params:  msg - the string to be sent
 *             size - if we know how much data we should expect to send, this should be populated
 *
 *    Throws: runtime_error for unrecoverable errors
 **********************************************************************************************/

int TCPConn::sendText(const char *msg) {
   return sendText(msg, strlen(msg));
}

int TCPConn::sendText(const char *msg, int size) {
   if (_connfd.writeFD(msg, size) < 0) {
      return -1;  
   }
   return 0;
}

/**********************************************************************************************
 * startAuthentication - Sets the status to request username
 *
 *    Throws: runtime_error for unrecoverable types
 **********************************************************************************************/

void TCPConn::startAuthentication() {

   // Skipping this for now
   _status = s_username;

   _connfd.writeFD("Username: "); 
}

/**********************************************************************************************
 * handleConnection - performs a check of the connection, looking for data on the socket and
 *                    handling it based on the _status, or stage, of the connection
 *
 *    Throws: runtime_error for unrecoverable issues
 **********************************************************************************************/

void TCPConn::handleConnection() {

   timespec sleeptime;
   sleeptime.tv_sec = 0;
   sleeptime.tv_nsec = 100000000;

   try {
      switch (_status) {
         case s_username:
            getUsername();
            break;

         case s_passwd:
            getPasswd();
            break;
   
         case s_changepwd:
         case s_confirmpwd:
            changePassword();
            break;

         case s_menu: 
            getMenuChoice();
            break;

         default:
            throw std::runtime_error("Invalid connection status!");
            break;
      }
   } catch (socket_error &e) {
      std::cout << "Socket error, disconnecting.";
      disconnect();
      return;
   }

   nanosleep(&sleeptime, NULL);
}

/**********************************************************************************************
 * getUsername - called from handleConnection when status is s_username--if it finds user data,
 *               it expects a username and compares it against the password database
 *
 *    Throws: runtime_error for unrecoverable issues
 **********************************************************************************************/

void TCPConn::getUsername() {
   // Read in a line from the connection
   std::string input;
   _connfd.readStr(input);
   lower(input);
   _username = input;
   PasswdMgr pwm("passwd");
   //const char* in = input.c_str();

   // Check to see if the username exists in the password file
   if(pwm.checkUser(input.c_str())){
      _status = s_passwd;
      _username.clear(); // Make sure _username is clear just in case
      _username.append(input); // Copy input into _username
      _connfd.writeFD("Password: "); 
      std::cout << "User " << _username << " has established a connection.\n"; 
   } else {
      _connfd.writeFD("There is no account for the given username,\n");
      _connfd.writeFD("please create an account with the my_adduser program.\n");
      std::cout << "Incorrect username, disconnecting.";

      std::string event ("IP Address: ");
      std::string ipaddr_str;
      getIPAddrStr(ipaddr_str);
      event.append(ipaddr_str);
      event.append(" ; User: ");
      event.append(input);
      event.append("; Incorrect username.");
      logEvent(event.c_str());

      disconnect();
   }
}

/**********************************************************************************************
 * getPasswd - called from handleConnection when status is s_passwd--if it finds user data,
 *             it assumes it's a password and hashes it, comparing to the database hash. Users
 *             get two tries before they are disconnected
 *
 *    Throws: runtime_error for unrecoverable issues
 **********************************************************************************************/

void TCPConn::getPasswd() {
   // Read in a line from the connection
   std::string input;
   _connfd.readStr(input);
   PasswdMgr pwm("passwd");

   // Now call checkPasswd() on the username and passwd 
   if(pwm.checkPasswd(_username.c_str(), input.c_str())){
      // The password matched what was in the file
      _connfd.writeFD("Correct, welcome to the server!\n");
      sendMenu(); // Send the menu to the user
      _status = s_menu;

      std::string event ("IP Address: ");
      std::string ipaddr_str;
      getIPAddrStr(ipaddr_str);
      event.append(ipaddr_str);
      event.append(" ; User: ");
      event.append(_username);
      event.append("; Successful connection.");
      logEvent(event.c_str());


   } else if(_pwd_attempts == 0){
      _connfd.writeFD("Incorrect password, please try again. 1 remaining attempt.\n");
      _connfd.writeFD("Password: "); 
      _pwd_attempts++;
   } else {
       _connfd.writeFD("Incorrect, this failed login has been logged.\n");
       _connfd.writeFD("You will now be disconnected from the server.\n");

      std::string event ("IP Address: ");
      std::string ipaddr_str;
      getIPAddrStr(ipaddr_str);
      event.append(ipaddr_str);
      event.append(" ; User: ");
      event.append(_username);
      event.append("; Failed to insert password twice.");
      logEvent(event.c_str());

       disconnect();
   }
   
}

/**********************************************************************************************
 * changePassword - called from handleConnection when status is s_changepwd or s_confirmpwd--
 *                  if it finds user data, with status s_changepwd, it saves the user-entered
 *                  password. If s_confirmpwd, it checks to ensure the saved password from
 *                  the s_changepwd phase is equal, then saves the new pwd to the database
 *
 *    Throws: runtime_error for unrecoverable issues
 **********************************************************************************************/

void TCPConn::changePassword() {
   std::string passwd1, passwd2;
   
   // Read in two strings, compare them, if they match change the password
   // if they don't match have the user input 2 new strings
   bool valid_passwd = false;
   while (!valid_passwd) {
      _connfd.readStr(passwd1);
      clrNewlines(passwd1);      

      _connfd.writeFD("Enter the password again: \n");

      _connfd.readStr(passwd2);
      clrNewlines(passwd2);

      if (passwd2.compare(passwd1) == 0)
         valid_passwd = true;
      else{
         _connfd.writeFD("Passwords must match. Try again with password 1:\n");
         passwd1.clear();
         passwd2.clear();
      }
   }

   // Now open up a password manager and change the password
   PasswdMgr pwm("passwd");
   pwm.changePasswd(_username.c_str(), passwd1.c_str());

   // Set the status to menu
   _status = s_menu;
   _connfd.writeFD("Your password is updated. You may now enter a new menu choice. \n");

}

/**********************************************************************************************
 * checkIPAddr - Compares the passed in string against the whitelist
 *
 * Returns: True if the passed in input matchs one of the IP addresses listed in the
 *    whitelist.  Returns false if the file fails to open correctly (also prints out an error
 *    message), or if the passed in ip address does not match anything in the white list. 
 **********************************************************************************************/

bool TCPConn::checkIPAddr(std::string ipaddr){
   // Set up the file stream and empty string for comparison 
   std::ifstream inputFile("whitelist");
   std::string line; 

   // Now iterate through each line of the file and compare the line to the ipaddr_str
   if(inputFile){
      // The stream opened correctly, now iteratre and compare, return true when you get a hit
      while(std::getline(inputFile, line)){
         if(ipaddr.compare(line) == 0){
            return true;
         }
      }
   } else {
      // Make sure the ifstream opened correctly
      perror("Failure to open file whitelist in TCPConn.\n");
      return false; 
   }

   return false; 
}

/**********************************************************************************************
 * getSocketFD - Returns this TCP connections file descriptor as an int. 
 *
 * Returns: The file descriptor as an int for prtinting to the server's terminal and 
 * logging
 **********************************************************************************************/

int TCPConn::getSocketFD() {
   return _connfd.getFD();
}

/**********************************************************************************************
 * getUserInput - Gets user data and includes a buffer to look for a carriage return before it is
 *                considered a complete user input. Performs some post-processing on it, removing
 *                the newlines
 *
 *    Params: cmd - the buffer to store commands - contents left alone if no command found
 *
 *    Returns: true if a carriage return was found and cmd was populated, false otherwise.
 *
 *    Throws: runtime_error for unrecoverable issues
 **********************************************************************************************/

bool TCPConn::getUserInput(std::string &cmd) {
   std::string readbuf;

   // read the data on the socket
   _connfd.readFD(readbuf);

   // concat the data onto anything we've read before
   _inputbuf += readbuf;

   // If it doesn't have a carriage return, then it's not a command
   int crpos;
   if ((crpos = _inputbuf.find("\n")) == std::string::npos)
      return false;

   cmd = _inputbuf.substr(0, crpos);
   _inputbuf.erase(0, crpos+1);

   // Remove \r if it is there
   clrNewlines(cmd);

   return true;
}

/**********************************************************************************************
 * getMenuChoice - Gets the user's command and interprets it, calling the appropriate function
 *                 if required.
 *
 *    Throws: runtime_error for unrecoverable issues
 **********************************************************************************************/

void TCPConn::getMenuChoice() {
   if (!_connfd.hasData())
      return;
   std::string cmd;
   if (!getUserInput(cmd))
      return;
   lower(cmd);      

   std::string msg;
   if (cmd.compare("hello") == 0) {
      _connfd.writeFD("Hello back!\n");
   } else if (cmd.compare("menu") == 0) {
      sendMenu();
   } else if (cmd.compare("exit") == 0) {
      _connfd.writeFD("Disconnecting...goodbye!\n");
      disconnect();
   } else if (cmd.compare("passwd") == 0) {
      _connfd.writeFD("New Password: \n");
      _status = s_changepwd;
   } else if (cmd.compare("1") == 0) {
      _connfd.writeFD("C++ got the OOP features from Simula67 Programming language.\n");
   } else if (cmd.compare("2") == 0) {
      msg += "Not purely object oriented: We can write C++ code without using\n";
      msg += "classes and it will compile without showing any error message.\n";
      _connfd.writeFD(msg);
   } else if (cmd.compare("3") == 0) {
      _connfd.writeFD("C and C++ were invented at same place i.e. at T bell laboratories.\n");
   } else if (cmd.compare("4") == 0) {
      msg += "Concept of reference variables: operator overloading borrowed from the Algol 68\n";
      msg += "Algol 68 programming language.\n";
      _connfd.writeFD(msg);
   } else if (cmd.compare("5") == 0) {
      _connfd.writeFD("A function is the minimum requirement for a C++ program to run.\n");
   } else {
      msg = "Unrecognized command: ";
      msg += cmd;
      msg += "\n";
      _connfd.writeFD(msg);
   }

}

/**********************************************************************************************
 * sendMenu - sends the menu to the user via their socket
 *
 *    Throws: runtime_error for unrecoverable issues
 **********************************************************************************************/
void TCPConn::sendMenu() {
   std::string menustr;

   menustr += "************************************\n";
   menustr += "Available menu choices are: \n";
   menustr += "  1-5 : provide c++ information.\n";
   menustr += "  Hello : self-explanatory\n";
   menustr += "  Passwd : change your password\n";
   menustr += "  Menu : display this menu\n";
   menustr += "  Exit : disconnect.\n";
   menustr += "************************************\n";

   _connfd.writeFD(menustr);
}


/**********************************************************************************************
 * disconnect - cleans up the socket as required and closes the FD
 *
 *    Throws: runtime_error for unrecoverable issues
 **********************************************************************************************/
void TCPConn::disconnect() {
   
   _connfd.closeFD();
}


/**********************************************************************************************
 * isConnected - performs a simple check on the socket to see if it is still open 
 *
 *    Throws: runtime_error for unrecoverable issues
 **********************************************************************************************/
bool TCPConn::isConnected() {
   return _connfd.isOpen();
}

/**********************************************************************************************
 * getIPAddrStr - gets a string format of the IP address and loads it in buf
 *
 **********************************************************************************************/
void TCPConn::getIPAddrStr(std::string &buf) {
   return _connfd.getIPAddrStr(buf);
}

/**
 * logEvent - takes a string and writes it to the log file, after a date/time
 * 
 *    params - event string to write to the file
 * 
 */
void TCPConn::logEvent(const char* event){
   // Open the file with the append option
   FileFD logFile("server.log");
   if (!logFile.openFile(FileFD::appendfd))
      perror ("Could not open server.log\n");
   
   // Get the current time and write it to the buffer
   time_t now = time(0);
   char* localTime = ctime(&now);
   std::string local(localTime);
   clrNewlines(local);
   logFile.writeFD(local);
   logFile.writeFD(" : "); // Just to make the line more readable

   // Now write the event sting and a newline. 
   logFile.writeFD(event);
   logFile.writeFD("\n");
}


