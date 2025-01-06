#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <stdint.h>
#include <pthread.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <cstring>
#include <fstream>
#include <iostream>
#include <portaudio.h>

// Cool Color Things
#define RESET   "\033[0m"
#define RED     "\033[31m"
#define GREEN   "\033[32m"
#define YELLOW  "\033[33m"
#define BLUE    "\033[1;94m"
#define CYAN    "\033[36m"
#define MAGENTA "\033[35m"
#define BOLD    "\033[1m"
#define ORANGE "\033[38;5;214m"
#define GREY "\033[38;5;247m"

#define MAX_MSG_LEN 5000  
#define USER_NAME_MAX_LEN 20
#define USER_PWD_MAX_LEN 20
#define FILE_CHUNK_SIZE 4096

// Global listening socket
int listen_fd;

SSL *ssl ;

struct AudioData {
    int socket_fd;
    unsigned char buffer[MAX_MSG_LEN];
    size_t buffer_size;
};

#include <queue>

std::queue<unsigned char> audio_buffer;  // Ring buffer for audio data
std::mutex buffer_mutex;

static int audio_callback(const void* inputBuffer, void* outputBuffer,
                          unsigned long framesPerBuffer, const PaStreamCallbackTimeInfo* timeInfo,
                          PaStreamCallbackFlags statusFlags, void* userData) {
    size_t bytes_needed = framesPerBuffer * 2 * sizeof(int16_t);  // Stereo, 16-bit samples
    unsigned char* out = (unsigned char*)outputBuffer;

    std::unique_lock<std::mutex> lock(buffer_mutex);
    if (audio_buffer.size() < bytes_needed) {
        // Not enough data, output silence
        std::memset(out, 0, bytes_needed);
        return paContinue;
    }

    // Fill the output buffer with data from the ring buffer
    for (size_t i = 0; i < bytes_needed; ++i) {
        out[i] = audio_buffer.front();
        audio_buffer.pop();
    }
    return paContinue;
}




void play_audio(int socket_fd) {
    PaStream* stream;
    unsigned char buffer[MAX_MSG_LEN];
    const std::string termination_signal = "<<<END_STREAM>>>";
    std::string leftover_data;
    bool termination_signal_detected = false;

    // Start PortAudio
    Pa_Initialize();
    Pa_OpenDefaultStream(&stream, 0, 2, paInt16, 44100, 256, audio_callback, nullptr);
    Pa_StartStream(stream);

    printf(MAGENTA "ʕっ•ᴥ•ʔっ Playing Chipi Chipi Chapa Chapa っʕ•ᴥ•っʔ\n" RESET) ;

    while (Pa_IsStreamActive(stream) || !audio_buffer.empty()) {
        // Continue receiving data until termination signal is detected
        if (!termination_signal_detected) {
            ssize_t bytes_received = recv(socket_fd, buffer, sizeof(buffer), 0);

            if (bytes_received <= 0) {
                std::cerr << "Socket closed or error. Stopping playback.\n";
                break;  // Socket closed or error
            }

            // Append received data to leftover_data
            leftover_data.append((char*)buffer, bytes_received);

            // Look for the termination signal
            size_t signal_pos = leftover_data.find(termination_signal);
            if (signal_pos != std::string::npos) {
                // Process all audio data before the termination signal
                size_t audio_data_size = signal_pos;

                std::unique_lock<std::mutex> lock(buffer_mutex);
                for (size_t i = 0; i < audio_data_size; ++i) {
                    audio_buffer.push(leftover_data[i]);
                }
                lock.unlock();

                // Mark termination signal detected
                termination_signal_detected = true;

                // Remove processed audio data and the termination signal from leftover_data
                leftover_data.erase(0, signal_pos + termination_signal.length());
                printf(MAGENTA "ʕっ•ᴥ•ʔっ Termination signal detected. Waiting for buffer to empty. っʕ•ᴥ•っʔ\n" RESET) ;
            } else {
                // If no termination signal, process all received data
                std::unique_lock<std::mutex> lock(buffer_mutex);
                for (char c : leftover_data) {
                    audio_buffer.push(c);
                }
                leftover_data.clear();
                lock.unlock();
            }
        }
        // Ensure playback continues until the buffer is empty
        if (termination_signal_detected && audio_buffer.empty()) {
            printf(MAGENTA "ʕっ•ᴥ•ʔっ All data played. Stopping playback. っʕ•ᴥ•っʔ\n" RESET) ;
            break;
        }

    }

    Pa_StopStream(stream);
    Pa_CloseStream(stream);
    Pa_Terminate();
}





int send_message(int client_fd, char const *message) {
    uint32_t message_length = htonl(strlen(message));  
    int bytes_sent;

    // Send the header with the message length
    bytes_sent = SSL_write(ssl, &message_length, sizeof(message_length));
    if (bytes_sent != sizeof(message_length)) {
        perror(RED "Failed to send message length" RESET);
        close(client_fd);
        exit(EXIT_FAILURE);
    }


    // Send the actual message
    int total_sent = 0;
    int message_size = strlen(message);
    while (total_sent < message_size) {
        bytes_sent = SSL_write(ssl, message + total_sent, message_size - total_sent);
        if (bytes_sent == -1) {
            perror(RED "Send failed" RESET);
            close(client_fd);
            exit(EXIT_FAILURE);
        }
        total_sent += bytes_sent;
    }

    return total_sent;
}




// Receives the entire response based on the length specified in the header
int receive_response(int client_fd, char *response, bool to_print) {
    uint32_t response_length;
    int bytes_received;

    // Receive the header to get response length
    bytes_received = SSL_read(ssl, &response_length, sizeof(response_length));
    if (bytes_received != sizeof(response_length)) {
        perror(RED "Failed to receive response length" RESET);
        close(client_fd);
        exit(EXIT_FAILURE);
    }
    response_length = ntohl(response_length);  

    // Receive the response in chunks if necessary
    int total_received = 0;
    while (total_received < response_length) {
        bytes_received = SSL_read(ssl, response + total_received, response_length - total_received);
        if (bytes_received == -1) {
            perror(RED "Receive failed" RESET);
            close(client_fd);
            exit(EXIT_FAILURE);
        }
        total_received += bytes_received;
    }
    response[total_received] = '\0';  // Null-terminate
    if (to_print) printf(BLUE "Server says: %s\n" RESET, response);
    return total_received;
}


void send_file_with_name(const std::string& filename, int client_fd) {
    // Send the file name
    send_message(client_fd, filename.c_str()) ;
    char response[MAX_MSG_LEN + 1] ;
    receive_response(client_fd, response, false) ; // server good   
    // Open the file for reading
    std::ifstream file(filename, std::ios::binary);
    if (!file.is_open()) {
        printf(RED "Failed to open file.\n" RESET);
        send_message(client_fd, "Failed to open file.") ;
        return;
    }
    send_message(client_fd, "Good") ;

    // Get the file size
    file.seekg(0, std::ios::end);
    uint32_t file_size = file.tellg();
    file.seekg(0, std::ios::beg);

    std::string number_file_size = std::to_string(file_size) ;
    send_message(client_fd, number_file_size.c_str()) ;
    receive_response(client_fd, response, false) ; // server good
    // Send the file content in chunks
    char buffer[FILE_CHUNK_SIZE];
    while (file.read(buffer, sizeof(buffer)) || file.gcount() > 0) {
        ssize_t bytes_to_send = file.gcount();  // Get the number of bytes read
        buffer[bytes_to_send] = '\0';  // Null-terminate the buffer
        send_message(client_fd, buffer);
    }

    file.close();
    receive_response(client_fd, response, false) ; // server good
    printf(GREEN "File sent successfully.\n" RESET);
}

void receive_file_from_server(int client_fd, const char *store_directory) {
    char buffer[MAX_MSG_LEN + 1];
    // Receive the file name
    receive_response(client_fd, buffer, false);
    std::string filename(buffer);
    send_message(client_fd, "Good") ;

    receive_response(client_fd, buffer, false);
    if (strcmp(buffer, "Good") != 0) {
        printf(RED "Server failed to open file.\n" RESET);
        return;
    } 
    
    // Receive the file size
    receive_response(client_fd, buffer, false);
    std::string file_size_str(buffer);
    uint32_t file_size = std::stoi(file_size_str);
    send_message(client_fd, "Good") ;

    std::string storage_path = store_directory ;
    storage_path.erase(storage_path.size() -1) ;
    storage_path = storage_path + filename ;
    std::ofstream file(storage_path, std::ios::binary);
    if (!file.is_open()) {
        printf(RED "Failed to open storage file.\n" RESET) ;
        return;
    }

    uint32_t bytes_received = 0 ;
    uint32_t total_received = 0;
    while ((bytes_received = receive_response(client_fd, buffer, false)) > 0) {
        file.write(buffer, bytes_received);
        total_received += bytes_received;
        if (total_received >= file_size) {
            break;
        }
    }

    if (total_received < 0) {
        printf(RED "Failed to receive file.\n" RESET);
    } else {
        char temp_output[1000] ;
        snprintf(temp_output, sizeof(temp_output), "File \"%s\" was saved as \"%s\".\n", filename.c_str(), storage_path.c_str()) ;
        printf(MAGENTA "%s" RESET, temp_output) ;
    }

    file.close();
    send_message(client_fd, "Good") ;
    return ;
}


SSL_CTX *create_context() {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    
    method = TLS_client_method();
    ctx = SSL_CTX_new(method);

    if (ctx == NULL) {
        perror(RED "Unable to create SSL context" RESET);
        ERR_print_errors_fp(stderr);
        abort();
    }
    if (SSL_CTX_load_verify_locations(ctx, "./localhost.crt", nullptr) <= 0) {
        perror(RED "Unable to load certificate" RESET);
        ERR_print_errors_fp(stderr);
        abort();
    }

    return ctx;
}



int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf(RED "Please provide desired port number!\n" RESET) ;
        return 0 ;
    }
    SSL_CTX *context ;
    signal(SIGPIPE, SIG_IGN) ;
    context = create_context() ;
    
    int port_number = atoi(argv[1]) ;
    int client_fd ;
    struct sockaddr_in server_addr ;
    char message[MAX_MSG_LEN] ;
    char response[MAX_MSG_LEN] ;
    


    // Create the client socket
    if ((client_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror(RED "Client socket creation failed" RESET) ;
        exit(EXIT_FAILURE) ;
    }

    // Set up the server address structure
    server_addr.sin_family = AF_INET ;
    server_addr.sin_port = htons(port_number) ;
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1") ;  // Localhost IP

    // Connect to the server
    if (connect(client_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror(RED "Connect failed" RESET) ;
        close(client_fd) ;
        exit(EXIT_FAILURE) ;
    }


    ssl = SSL_new(context) ;
    SSL_set_fd(ssl, client_fd) ;
    SSL_connect(ssl) ;

    X509 *cert = SSL_get_peer_certificate(ssl) ;

        printf(RED BOLD            "\n============================================================================\n" RESET);
        printf(ORANGE BOLD            "+++++    \\    /\\         $$      WELOCOME      $$           /\\    /    +++++\n" RESET);
        printf(YELLOW BOLD         "++        )  ( ')        $$         TO         $$          (' )  (        ++\n" RESET);
        printf( GREEN  BOLD       "++       (  /  )         $$  COMPUTER NETWORK  $$           (  \\  )       ++\n" RESET);
        printf(CYAN BOLD          "+++++     \\(__)|         $$   FINAL PROJECT!   $$           |(__)/     +++++\n" RESET);
        printf(BLUE BOLD            "============================================================================\n" RESET);
    while (1) {

        printf("\n" CYAN BOLD "+========================= OPTIONS =========================+\n" RESET);
        printf(CYAN BOLD    "║" RESET YELLOW BOLD  " [L] " RESET CYAN BOLD "Log in                                                ║\n" RESET);
        printf(CYAN BOLD    "║" RESET YELLOW BOLD  " [R] " RESET CYAN BOLD "Register                                              ║\n" RESET);
        printf(CYAN BOLD    "║" RESET YELLOW BOLD  " [Q] " RESET CYAN BOLD "Quit the application                                  ║\n" RESET);
        printf(CYAN BOLD      "+===========================================================+\n\n" RESET);
        printf(GREEN "Type your choice: " RESET);

        fgets(message, sizeof(message), stdin) ;
        message[strcspn(message, "\n")] = '\0' ;
        if (strcmp(message, "L") == 0) {
            message[strcspn(message, "\n")] = '\0' ;
            send_message(client_fd, message) ;

            printf(GREEN "(Login) Enter user name: " RESET) ;
            fgets(message, sizeof(message), stdin) ;
            message[strcspn(message, "\n")] = '\0' ;
            send_message(client_fd, message) ;
            receive_response(client_fd, response, false) ;
            if (strcmp(response, "Good") != 0) {
                printf(RED "Server says: %s\n" RESET, response) ;
                continue ;
            }
        
            printf(GREEN "(Login) Enter password: " RESET) ;
            fgets(message, sizeof(message), stdin) ;
            message[strcspn(message, "\n")] = '\0' ;
            send_message(client_fd, message) ;
            receive_response(client_fd, response, false) ;
            if (strcmp(response, "Good") != 0) {
                printf(RED "Server says: %s\n" RESET, response) ;
                continue ;
            }
            printf(GREEN "(Login) Successfully logged in!\n" RESET) ;
            break ;
        } else if (strcmp(message, "R") == 0) {
            message[strcspn(message, "\n")] = '\0' ;
            send_message(client_fd, message) ;
            receive_response(client_fd, response, false) ;
            if (strcmp(response, "Good") != 0) {
                printf(RED "Server says: %s\n" RESET, response) ;
                continue ;
            }
            printf(GREEN "(Registration) Enter user name: " RESET) ;
            fgets(message, sizeof(message), stdin) ;
            message[strcspn(message, "\n")] = '\0' ;
            send_message(client_fd, message) ;
            receive_response(client_fd, response, false) ;
            if (strcmp(response, "Good") != 0) {
                printf(RED "Server says: %s\n" RESET, response) ;
                continue ;
            }
            printf(GREEN "(Registration) Enter password: " RESET) ;
            fgets(message, sizeof(message), stdin) ;
            message[strcspn(message, "\n")] = '\0' ;
            send_message(client_fd, message) ;
            receive_response(client_fd, response, true) ;
        } else if (strcmp(message, "Q") == 0) {
            printf(GREEN "Exiting...\n" RESET) ;
            send_message(client_fd, message) ;
            receive_response(client_fd, response, true) ;
            close(client_fd) ;

            return 0 ;
        } else {
            printf(RED "Wrong input :(\n" RESET) ;
            continue ;
        }
    }
    

    while (1) {
        printf("\n" CYAN BOLD "+========================= OPTIONS ===========================+\n" RESET);
        printf(CYAN BOLD      "║                                                             ║\n" RESET);
        printf(CYAN BOLD      "║" RESET YELLOW BOLD  "  [S] " RESET CYAN BOLD "Send a message to the server                           ║\n" RESET);
        printf(CYAN BOLD      "║" RESET YELLOW BOLD  "  [T] " RESET CYAN BOLD "Send a message to another user                         ║\n" RESET);
        printf(CYAN BOLD      "║" RESET YELLOW BOLD  "  [R] " RESET CYAN BOLD "Read messages from others                              ║\n" RESET);
        printf(CYAN BOLD      "║" RESET YELLOW BOLD  "  [F] " RESET CYAN BOLD "Send a file to another client                          ║\n" RESET);
        printf(CYAN BOLD      "║" RESET YELLOW BOLD  "  [G] " RESET CYAN BOLD "Get file from other clients                            ║\n" RESET);
        printf(CYAN BOLD      "║" RESET YELLOW BOLD  "  [A] " RESET CYAN BOLD "ʕっ•ᴥ•ʔっ Listen to Chipi Chipi Chapa Chapa っʕ•ᴥ•っʔ  ║\n" RESET);
        printf(CYAN BOLD      "║" RESET YELLOW BOLD  "  [Q] " RESET CYAN BOLD "Quit the application                                   ║\n" RESET);
        printf(CYAN BOLD      "║                                                             ║\n" RESET);
        printf(CYAN BOLD      "+=============================================================+\n\n" RESET);
        printf(GREEN"Type your choice: " RESET);
        fgets(message, sizeof(message), stdin) ;
        message[strcspn(message, "\n")] = '\0' ;  // Remove the newline character
        send_message(client_fd, message) ;

        if (strcmp(message, "Q") == 0) {
            printf(GREEN "Exiting...\n" RESET) ;
            receive_response(client_fd, response, true) ;
            break ;
        } else if (strcmp(message, "S") == 0) {
            send_message(client_fd, message) ;
            printf(GREEN "Enter message to send to server: " RESET) ;
            fgets(message, sizeof(message), stdin) ;
            message[strcspn(message, "\n")] = '\0' ;
            send_message(client_fd, message) ;
            receive_response(client_fd, response, true) ;
        } else if (strcmp(message, "T") == 0) {
            printf(GREEN "Enter the user name: " RESET) ;
            fgets(message, sizeof(message), stdin) ;
            message[strcspn(message, "\n")] = '\0' ;
            send_message(client_fd, message) ;
            receive_response(client_fd, response, false) ;
            if (strcmp(response, "Good") != 0) {
                printf(RED "Server says: %s\n" RESET, response) ;
                continue ;
            }
            printf(GREEN "Enter the message: " RESET) ;
            fgets(message, sizeof(message), stdin) ;
            message[strcspn(message, "\n")] = '\0' ;
            send_message(client_fd, message) ;
            receive_response(client_fd, response, true) ;
        } else if (strcmp(message, "R") == 0) {
            receive_response(client_fd, response, false) ;
            int number_of_messages = atoi(response) ;
            if (number_of_messages == 0) {
                printf(RED "No messages to read :(\n" RESET) ;
                continue ;
            }
            for (int i = 0; i < number_of_messages; i++) {
                receive_response(client_fd, response, false) ;
                printf(MAGENTA BOLD "\n====================== Message %d ======================\n" RESET, i + 1);
                printf(GREY "From: "  "%s\n" RESET, response);
                snprintf(message, sizeof(message), "Good") ;
                send_message(client_fd, message) ;
                receive_response(client_fd, response, false) ;
                printf(GREY "Message: %s\n" RESET, response) ;
                snprintf(message, sizeof(message), "Good") ;
                send_message(client_fd, message) ;
            }
            printf(MAGENTA "\n=======================================================" RESET);
            if(number_of_messages >= 10) {
                printf(MAGENTA "=" RESET) ;
            } 
            printf("\n\n") ;
        } else if (strcmp(message, "F") == 0) {
            receive_response(client_fd, response, false) ;
            if (strcmp(response, "Good") != 0) {
                printf(RED "Server says: %s\n" RESET, response) ;
                continue ;
            }
            printf(GREEN "Enter the user name to send: " RESET) ;
            fgets(message, sizeof(message), stdin) ;
            message[strcspn(message, "\n")] = '\0' ;
            send_message(client_fd, message) ;
            receive_response(client_fd, response, false) ;
            if (strcmp(response, "Good") != 0) {
                printf(RED "Server says: %s\n" RESET, response) ;
                continue ;
            }
            printf(GREEN "Enter the file name: " RESET) ;
            fgets(message, sizeof(message), stdin) ;
            message[strcspn(message, "\n")] = '\0' ;
            std::string filename(message) ;
            send_file_with_name(filename, client_fd) ;

        } else if (strcmp(message, "G") == 0) {
            receive_response(client_fd, response, false) ;
            int number_of_messages = atoi(response) ;
            if (number_of_messages == 0) {
                printf(RED "No file from others :(\n" RESET) ;
                continue ;
            } else {
                printf(MAGENTA "Number of files from others: %d\n" RESET, number_of_messages) ;
            }
            for (int i = 0; i < number_of_messages; i++) {
                receive_response(client_fd, response, false) ;
                printf(MAGENTA BOLD "\n====================== FILE %d ======================\n" RESET, i + 1);
                printf(GREY"From: " RESET MAGENTA "%s\n" RESET, response);
                snprintf(message, sizeof(message), "Good") ;
                send_message(client_fd, message) ;
                receive_response(client_fd, response, false) ;
                printf(GREY "File_name: %s\n" RESET, response) ;
                snprintf(message, sizeof(message), "Good") ;
                send_message(client_fd, message) ;
            }
            printf(MAGENTA "\n====================================================\n\n" RESET) ;
            printf(GREEN "Enter a directory to place the downloaded files: " RESET);
            char d_directory[MAX_MSG_LEN] ;
            fgets(d_directory, sizeof(d_directory), stdin);
            message[strcspn(d_directory, "\n")] = '\0';
            
            for (int i = 0; i < number_of_messages; i++) {
                receive_file_from_server(client_fd, d_directory) ;
            }
        } else if (strcmp(message, "A") == 0) { 
            play_audio(client_fd) ;
        }else {
            printf(RED "Wrong input :(\n" RESET) ;
            continue ;
        }
    }
    
    SSL_shutdown(ssl) ;
    SSL_free(ssl) ;
    SSL_CTX_free(context) ;

    // Close the client socket
    close(client_fd) ;

    return 0;
}