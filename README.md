# CN Project Phase 2

This is a simple server-client implementation using TCP. The project includes functionality for sending messages, files, and even some fun options! Note that only one client is allowed to connect to the server at a time.

## Table of Contents
- [Environment](#environment)
- [Dependencies](#dependencies)
- [Features](#features)
- [Usage](#usage)
- [Options](#options)

---

## Environment

This project is designed to run on **macOS Sonoma 14.6.1**. Compatibility with other macOS versions or operating systems is not guaranteed. 

---

## Dependencies

This project requires the following external libraries:

1. **OpenSSL**  
   - Used for secure connections between the server and client.
   - Installation:
     ```bash
     brew install openssl
     ```
   - Ensure OpenSSL is linked correctly:
     ```bash
     export LDFLAGS="-L/opt/homebrew/opt/openssl@3/lib"
     export CPPFLAGS="-I/opt/homebrew/opt/openssl@3/include"
     ```

2. **PortAudio**  
   - Used for audio processing and playback.
   - Installation:
     ```bash
     brew install portaudio
     ```

3. **mpg123**  
   - Used for decoding MP3 files for audio playback.
   - Installation:
     ```bash
     brew install mpg123
     ```

4. **Standard C Libraries**  
   - Used for basic input/output and networking (`<stdio.h>`, `<stdlib.h>`, `<string.h>`, `<arpa/inet.h>`, `<unistd.h>`).

Ensure these libraries are properly installed before running the project.

---

## Features

This implementation includes the following features:
- Sending and receiving messages between the client and server.
- Sending messages to other clients.
- Registering and logging in users.
- Sending files to other clients.
- Receiving files from other clients.
- Fun and interactive options, including audio playback with PortAudio and mpg123.
- Encrypted message transfer.
- Beautiful and colorful client terminal interface.

---

## Usage

Follow these steps to compile and run the server and client:

1. **Compile the Server and Client**
   Use the provided `Makefile` to compile both the server and client programs:
   ```bash
   make
   ```
2. **Start the Server**
    ```bash
    ./server [port_number]
    ```
3. **Start the Client**
    We support up to 10 clients for a single server.
    ```bash
    ./client [port_number]
    ```

4. **Example**
    ```bash
    ./server 8080
    ./client 8080
    ```

If the makefile can't run properly on your machine, you can directly use the executable file "server" and "client" in the code directory to run the program.

## Options

### **Log in ([L]):**

- Enter your username and password to log in.
- If the credentials are correct, you will gain access to the system's features.
- If the credentials are incorrect, the server will notify you.

---

### **Register ([R]):**

- Create a new account by providing a unique username and password.
- The server will confirm successful registration.
- If the username is already in use, you will be asked to try another one.

---

### **Quit ([Q]):**

- Exit the application gracefully.

---

### **Send a Message to the Server ([S]):**

- Type a message, and it will be sent directly to the server.
- The server will respond with a confirmation message.

---

### **Send a Message to Another User ([T]):**

- Enter the recipient's username and the message you wish to send.
- If the user is valid, the message will be delivered.

---

### **Read Messages from Others ([R]):**

- View messages that have been sent to you by other users.
- The server will list the messages with the sender's username.

---

### **Send a File to Another Client ([F]):**

- Provide the filename and the recipient's username.
- The file will be securely transferred to the specified user.

---

### **Get a File from Other Clients ([G]):**

- View and download files that other users have sent to you.
- The file will be saved in your local directory.

---

### **Listen to Chipi Chipi Chapa Chapa ([A]):**

- Relax and enjoy a fun audio feature as a small Easter egg. 🐻🎶


### **Quit ([Q]):**

- Exit the application gracefully.





