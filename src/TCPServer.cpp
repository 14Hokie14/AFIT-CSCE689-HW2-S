#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdexcept>
#include <strings.h>
#include <vector>
#include <iostream>
#include <memory>
#include <sstream>
#include <ctime>
#include "TCPServer.h"
#include "strfuncts.h"

TCPServer::TCPServer(){ 
   logEvent("Server started.");
}


TCPServer::~TCPServer() {

}

/**********************************************************************************************
 * bindSvr - Creates a network socket and sets it nonblocking so we can loop through looking for
 *           data. Then binds it to the ip address and port
 *
 *    Throws: socket_error for recoverable errors, runtime_error for unrecoverable types
 **********************************************************************************************/

void TCPServer::bindSvr(const char *ip_addr, short unsigned int port) {

   struct sockaddr_in servaddr;

   // _server_log.writeLog("Server started.");

   // Set the socket to nonblocking
   _sockfd.setNonBlocking();

   // Load the socket information to prep for binding
   _sockfd.bindFD(ip_addr, port);
 
}

/**********************************************************************************************
 * listenSvr - Performs a loop to look for connections and create TCPConn objects to handle
 *             them. Also loops through the list of connections and handles data received and
 *             sending of data. 
 *
 *    Throws: socket_error for recoverable errors, runtime_error for unrecoverable types
 **********************************************************************************************/

void TCPServer::listenSvr() {

   bool online = true;
   timespec sleeptime;
   sleeptime.tv_sec = 0;
   sleeptime.tv_nsec = 100000000;
   int num_read = 0;

   // Start the server socket listening
   _sockfd.listenFD(5);

    
   while (online) {
      struct sockaddr_in cliaddr;
      socklen_t len = sizeof(cliaddr);

      if (_sockfd.hasData()) {
         TCPConn *new_conn = new TCPConn();
         if (!new_conn->accept(_sockfd)) {
            // _server_log.strerrLog("Data received on socket but failed to accept.");
            continue;
         }
         
         std::cout << "***New Connection on socket " << new_conn->getSocketFD()  << "***\n";

         _connlist.push_back(std::unique_ptr<TCPConn>(new_conn));

         // Get their IP Address string to use in logging
         std::string ipaddr_str;
         new_conn->getIPAddrStr(ipaddr_str);
         
         std::cout << "***Checking IP Address " << ipaddr_str << " against whitelist now.***\n";
         if(new_conn->checkIPAddr(ipaddr_str)){
            std::cout << "***IP Address was contained in the white list.***\n";
            std::string event ("IP Address: ");
            event.append(ipaddr_str);
            event.append(" connected to the server.");
            logEvent(event.c_str());
         } else {
            std::cout << "***IP Address was not contained in the white list.***\n";
            new_conn->sendText("Your IP Address was not contained in the whitelist.\n");
            new_conn->sendText("You're now being disconnected from the server.\n");
            new_conn->disconnect();
            std::string event ("IP Address: ");
            event.append(ipaddr_str);
            event.append(" failed to connect to the server because it wasn't on the whitelist.");
            logEvent(event.c_str());
            continue; 
            
         }

         new_conn->sendText("Welcome to the CSCE 689 Server!\n");

         // Change this later
         new_conn->startAuthentication();
      }

      // Loop through our connections, handling them
      std::list<std::unique_ptr<TCPConn>>::iterator tptr = _connlist.begin();
      while (tptr != _connlist.end())
      {
         // If the user lost connection
         if (!(*tptr)->isConnected()) {
            std::string event ("IP Address: ");
            std::string ipaddr_str;
            (*tptr)->getIPAddrStr(ipaddr_str);
            event.append(ipaddr_str);
            event.append(" ; User: ");
            event.append((*tptr)->getUsernameStr());
            event.append("; Disconnected.");
            logEvent(event.c_str());

            // Remove them from the connect list
            tptr = _connlist.erase(tptr);
            std::cout << "Connection disconnected.\n";
            continue;
         }

         // Process any user inputs
         (*tptr)->handleConnection();

         // Increment our iterator
         tptr++;
      }

      // So we're not chewing up CPU cycles unnecessarily
      nanosleep(&sleeptime, NULL);
   } 


   
}


/**********************************************************************************************
 * shutdown - Cleanly closes the socket FD.
 *
 *    Throws: socket_error for recoverable errors, runtime_error for unrecoverable types
 **********************************************************************************************/

void TCPServer::shutdown() {

   _sockfd.closeFD();
}

/**
 * logEvent - takes a string and writes it to the log file, after a date/time
 * 
 *    params - event string to write to the file
 * 
 */
void TCPServer::logEvent(const char* event){
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


