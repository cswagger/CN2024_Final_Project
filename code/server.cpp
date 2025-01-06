#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <cstring>
#include <fstream>
#include <iostream>
#include <filesystem>
#include <stdexcept>
#include <mpg123.h>
#include <cstdio>

#define MAX_MSG_LEN 5000
#define MAX_INCOME_QUEUE_NUM 5
#define USER_NAME_MAX_LEN 20
#define USER_PWD_MAX_LEN 20
#define WORKER_COUNT 12
#define QUEUE_SIZE 12
#define MAX_RECEIVE_MESSAGE_NUM 10
#define FILE_CHUNK_SIZE 4096
#define MAX_STORAGE_FILE 100
#define BUFFER_SIZE 8192

#define RESET   "\033[0m"
#define RED     "\033[31m"
#define GREEN   "\033[32m"
#define YELLOW  "\033[33m"
#define CYAN    "\033[36m"
#define MAGENTA "\033[35m"
#define BLUE    "\033[1;94m"
#define ORANGE "\033[38;2;255;165;0m"

std::string storage_directory = "./server_store/";

int receive_message(int client_fd, char *message, SSL *ssl) ;
int send_response(int client_fd, const char *response, SSL *ssl) ;
void thread_safe_print(const char *message, const char *color);
void thread_safe_int(int input, const char *color);
SSL_CTX *context ;

void stream_audio(const char* file_path, int client_fd) {
    mpg123_handle* mh = mpg123_new(nullptr, nullptr);
    unsigned char buffer[BUFFER_SIZE];
    size_t bytes_read;

    // Initialize MPG123
    if (mpg123_init() != MPG123_OK) {
        std::cerr << "Error: Failed to initialize MPG123.\n";
        return;
    }

    if (mpg123_open(mh, file_path) != MPG123_OK) {
        std::cerr << "Error: Failed to open MP3 file.\n";
        mpg123_exit();
        return;
    }

    // Set the audio format
    long rate;
    int channels, encoding;
    mpg123_getformat(mh, &rate, &channels, &encoding);
    char temp_output[100] ;
    snprintf(temp_output, sizeof(temp_output), "ʕっ•ᴥ•ʔっ Audio format: %ld Hz, %d channels っʕ•ᴥ•っʔ", rate, channels) ;
    thread_safe_print(temp_output, MAGENTA) ;

    // Ensure the format matches what the client expects
    if (rate != 44100 || channels != 2 || encoding != MPG123_ENC_SIGNED_16) {
        std::cerr << "Error: Unsupported audio format. Expected 44100 Hz, 2 channels, 16-bit PCM.\n";
        mpg123_close(mh);
        mpg123_exit();
        return;
    }

    thread_safe_print("ʕっ•ᴥ•ʔっ Streaming Chipi Chipi Chapa Chapa っʕ•ᴥ•っʔ", MAGENTA) ;

    // Stream the audio data
    while (mpg123_read(mh, buffer, BUFFER_SIZE, &bytes_read) == MPG123_OK) {
        if (send(client_fd, buffer, bytes_read, 0) <= 0) {
            std::cerr << "Error: Failed to send audio data.\n";
            break;
        }
        // Optional: Sleep to simulate real-time streaming
        usleep(40000); // sleep to prevent client overload
    }


    // Send termination signal
    const char* termination_signal = "<<<END_STREAM>>>";
    send(client_fd, termination_signal, strlen(termination_signal), 0);
    thread_safe_print("ʕっ•ᴥ•ʔっ Finished Streaming Audio っʕ•ᴥ•っʔ", MAGENTA) ;

    mpg123_close(mh);
    mpg123_exit();
}

char* extract_file_name(const char* file_path) {
    if (file_path == nullptr) {
        return nullptr;
    }

    const char* last_slash = strrchr(file_path, '/');

    if (last_slash != nullptr) {
        return strdup(last_slash + 1);
    }

    return strdup(file_path);
}


typedef struct {
    bool is_available_file[MAX_STORAGE_FILE] ;
    char original_file_name[MAX_STORAGE_FILE][MAX_MSG_LEN] ;
    char storage_file_name[MAX_STORAGE_FILE][MAX_MSG_LEN] ;
    char file_sender[MAX_STORAGE_FILE][USER_NAME_MAX_LEN] ;
    char file_receiver[MAX_STORAGE_FILE][USER_NAME_MAX_LEN] ;
    int file_storage_count ;
} file_info_t ;

file_info_t file_info ;

typedef struct {
    int client_fd;
    struct sockaddr_in client_addr, listen_addr;
    SSL *ssl ;
} client_task_t;

typedef struct {
    int client_fd;
    char username[USER_NAME_MAX_LEN + 1];
    char password[USER_PWD_MAX_LEN + 1];
    bool is_online;
    char message_from_others[MAX_RECEIVE_MESSAGE_NUM][MAX_MSG_LEN + 1] ;
    char message_author[MAX_RECEIVE_MESSAGE_NUM][USER_NAME_MAX_LEN + 1] ;
    bool message_list[MAX_RECEIVE_MESSAGE_NUM] ;
    int message_count ;
} client_info_t;

int find_empty_file() {
    for (int i = 0; i < MAX_STORAGE_FILE; i++) {
        if (file_info.is_available_file[i] == false) {
            return i ;
        }
    }
    return -1 ;
}

void send_files_to_user(int client_fd, int file_index, SSL *ssl) {
    // Send the file name
    send_response(client_fd, file_info.original_file_name[file_index], ssl) ;
    char response[MAX_MSG_LEN + 1] ;
    receive_message(client_fd, response, ssl) ; // client good   
    
    std::string storagefile_index(file_info.storage_file_name[file_index]) ;
    // Open the file for reading
    std::string storage_path = "./server_store/" + storagefile_index;

    std::ifstream file(storage_path, std::ios::binary);
    if (!file.is_open()) {
        thread_safe_print("Failed to open file.", RED);
        send_response(client_fd, "Failed to open file.", ssl) ;
        return;
    }
    send_response(client_fd, "Good", ssl) ;

    // Get the file size
    file.seekg(0, std::ios::end);
    uint32_t file_size = file.tellg();
    file.seekg(0, std::ios::beg);

    std::string number_file_size = std::to_string(file_size) ;
    send_response(client_fd, number_file_size.c_str(), ssl) ;
    receive_message(client_fd, response, ssl) ; // client good
    
    // Send the file content in chunks
    char buffer[FILE_CHUNK_SIZE];
    while (file.read(buffer, sizeof(buffer)) || file.gcount() > 0) {
        ssize_t bytes_to_send = file.gcount();  // Get the number of bytes read
        buffer[bytes_to_send] = '\0';  // Null-terminate the buffer
        send_response(client_fd, buffer, ssl);
    }


    file.close();
    // Attempt to delete the file
    if (remove(storage_path.c_str()) == 0) {
        char temp_output[1000] ;
        snprintf(temp_output, sizeof(temp_output), "A file was removed from ./server_store/") ;
        thread_safe_print(temp_output, BLUE) ;
    } else {
        perror("Error deleting file");
    }
    receive_message(client_fd, response, ssl) ; // client good
    printf(GREEN "File sent successfully.\n" RESET);
}

void add_file(const char *filename, const char *sender, const char *receiver, char *storage_name, int size_storage_name) {
    int index = find_empty_file() ;
    if (index == -1) {
        return ;
    }
    char storage_file_name[20] ;
    file_info.file_storage_count++ ;
    snprintf(storage_file_name, 20, "%s", std::to_string(index).c_str());
    file_info.is_available_file[index] = true ;
    
    char *actually_storage_file_name = extract_file_name(filename) ;
    snprintf(file_info.original_file_name[index], sizeof(file_info.original_file_name[index]), "%s", actually_storage_file_name) ;
    snprintf(file_info.storage_file_name[index], sizeof(file_info.storage_file_name[index]), "%s", storage_file_name) ;
    snprintf(file_info.file_sender[index], sizeof(file_info.file_sender[index]), "%s", sender) ;
    snprintf(file_info.file_receiver[index], sizeof(file_info.file_receiver[index]), "%s", receiver) ;
    snprintf(storage_name, size_storage_name, "%s", storage_file_name) ;
}

int countfile(const char *username) {
    int count = 0 ;
    for (int i = 0; i < MAX_STORAGE_FILE; i++) {
        if (file_info.is_available_file[i] == true && strcmp(file_info.file_receiver[i], username) == 0) {
            count++ ;
        }
    }
    return count ;
}

void receive_file_with_name(int client_fd, SSL *ssl, const char *sender, const char *receiver) {
    char buffer[MAX_MSG_LEN + 1];
    // Receive the file name
    receive_message(client_fd, buffer, ssl);
    std::string filename(buffer);
    send_response(client_fd, "Good", ssl) ;

    receive_message(client_fd, buffer, ssl);
    if (strcmp(buffer, "Good") != 0) {
        thread_safe_print("Client failed to open file.", RED);
        return;
    } 
    
    char storage_name[20] ;
    add_file(filename.c_str(), sender, receiver, storage_name, sizeof(storage_name)) ;
    
    // Receive the file size
    receive_message(client_fd, buffer, ssl);
    std::string file_size_str(buffer);
    uint32_t file_size = std::stoi(file_size_str);
    send_response(client_fd, "Good", ssl) ;

    std::string storage_path = storage_directory;
    storage_path += storage_name;
    std::ofstream file(storage_path, std::ios::binary);
    if (!file.is_open()) {
        thread_safe_print("Failed to open file", RED);
        return;
    }

    uint32_t bytes_received = 0 ;
    uint32_t total_received = 0;
    while ((bytes_received = receive_message(client_fd, buffer, ssl)) > 0) {
        file.write(buffer, bytes_received);
        total_received += bytes_received;
        if (total_received >= file_size) {
            break;
        }
    }
    if (total_received < 0) {
        thread_safe_print("Failed to receive file", RED);
    } else {
        char temp_output[1000] ;
        snprintf(temp_output, sizeof(temp_output), "File \"%s\" received from \"%s\" was temporarily saved as \"./server_store/%s\".", filename.c_str(), sender, storage_name);
        thread_safe_print(temp_output, BLUE);
    }
    file.close();
    send_response(client_fd, "Good", ssl) ;
    return ;
}

#define MAX_CLIENTS 100


client_info_t clients[MAX_CLIENTS];
int client_count = 0;
pthread_mutex_t clients_mutex = PTHREAD_MUTEX_INITIALIZER;

void add_client(client_info_t client) {
    pthread_mutex_lock(&clients_mutex);
    if (client_count < MAX_CLIENTS) {
        clients[client_count++] = client;
    }
    pthread_mutex_unlock(&clients_mutex);
}

client_info_t *find_client(const char *username) {
    pthread_mutex_lock(&clients_mutex);
    for (int i = 0; i < client_count; i++) {
        if (strcmp(clients[i].username, username) == 0) {
            pthread_mutex_unlock(&clients_mutex);
            return &clients[i];
        }
    }
    pthread_mutex_unlock(&clients_mutex);
    return NULL;
}

void remove_client(int client_fd) {
    pthread_mutex_lock(&clients_mutex);
    for (int i = 0; i < client_count; i++) {
        if (clients[i].client_fd == client_fd) {
            clients[i] = clients[client_count - 1];
            client_count--;
            break;
        }
    }
    pthread_mutex_unlock(&clients_mutex);
}




client_task_t task_queue[QUEUE_SIZE];
int queue_front = 0, queue_rear = 0, queue_count = 0;
pthread_mutex_t queue_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t queue_cond = PTHREAD_COND_INITIALIZER;

pthread_mutex_t print_mutex = PTHREAD_MUTEX_INITIALIZER;

char user_name[USER_NAME_MAX_LEN + 1];
char user_pwd[USER_PWD_MAX_LEN + 1];
int user_count = 0;
int server_fd;

void enqueue_task(client_task_t task) {
    pthread_mutex_lock(&queue_mutex);
    while (queue_count == QUEUE_SIZE) {
        pthread_cond_wait(&queue_cond, &queue_mutex);
    }
    task_queue[queue_rear] = task;
    queue_rear = (queue_rear + 1) % QUEUE_SIZE;
    queue_count++;
    pthread_cond_signal(&queue_cond);
    pthread_mutex_unlock(&queue_mutex);
}

client_task_t dequeue_task() {
    pthread_mutex_lock(&queue_mutex);
    while (queue_count == 0) {
        pthread_cond_wait(&queue_cond, &queue_mutex);
    }
    client_task_t task = task_queue[queue_front];
    queue_front = (queue_front + 1) % QUEUE_SIZE;
    queue_count--;
    pthread_cond_signal(&queue_cond);
    pthread_mutex_unlock(&queue_mutex);
    return task;
}

int send_response(int client_fd, const char *response, SSL *ssl) {
    uint32_t message_length = htonl(strlen(response)); 
    size_t total_sent = 0;                             
    size_t message_size = sizeof(message_length);     

   
    for (const char *ptr = (const char *)&message_length; total_sent < message_size;) {
        int bytes_sent = SSL_write(ssl, ptr + total_sent, message_size - total_sent);
        if (bytes_sent <= 0) {
            ERR_print_errors_fp(stderr);  
            return -1 ;                  
        }
        total_sent += bytes_sent;
    }
    // Send the actual message
    total_sent = 0;
    message_size = strlen(response);
    for (const char *ptr = response; total_sent < message_size;) {
        int bytes_sent = SSL_write(ssl, ptr + total_sent, message_size - total_sent);
        if (bytes_sent <= 0) {
            ERR_print_errors_fp(stderr); 
            return -1 ;                     
        }
        total_sent += bytes_sent;
    }

    return total_sent;
}

int receive_message(int client_fd, char *message, SSL *ssl) {
    uint32_t message_length;
    size_t total_received = 0;
    size_t length_to_receive = sizeof(message_length);

    // Receive message length
    for (char *ptr = (char *)&message_length; total_received < length_to_receive;) {
        int bytes_received = SSL_read(ssl, ptr + total_received, length_to_receive - total_received);
        if (bytes_received <= 0) {
            ERR_print_errors_fp(stderr);  
            return -1 ;                   
        }
        total_received += bytes_received;
    }

    
    message_length = ntohl(message_length);

    if (message_length > MAX_MSG_LEN) {
        fprintf(stderr, "Received message length exceeds buffer size.\n");
        return -1 ; 
    }

    // Receive the actual message
    total_received = 0;
    for (char *ptr = message; total_received < message_length;) {
        int bytes_received = SSL_read(ssl, ptr + total_received, message_length - total_received);
        if (bytes_received <= 0) {
            ERR_print_errors_fp(stderr);  
            return -1 ;                     
        }
        total_received += bytes_received;
    }

    // Null-terminate
    message[message_length] = '\0';
    return total_received;
}



void thread_safe_print(const char *message, const char *color) {
    pthread_mutex_lock(&print_mutex);
    printf("%s%s%s\n", color,  message, "\033[0m");
    pthread_mutex_unlock(&print_mutex);
}
void thread_safe_int(int input, const char *color) {
    pthread_mutex_lock(&print_mutex);
    printf("%s%d%s\n", color,  input, "\033[0m");
    pthread_mutex_unlock(&print_mutex);
}


void send_message_to_others(client_info_t *receive_client, const char *author,const char *message) {
    pthread_mutex_lock(&clients_mutex);
    for (int i = 0; i < MAX_MSG_LEN; i++) {
        if (receive_client->message_list[i] == false) {
            snprintf(receive_client->message_from_others[i], sizeof(receive_client->message_from_others[i]), "%s", message);
            snprintf(receive_client->message_author[i], sizeof(receive_client->message_author[i]), "%s", author);
            receive_client->message_list[i] = true;
            receive_client->message_count++ ;
            break;
        }
    }
    pthread_mutex_unlock(&clients_mutex);
    return;
}


void *worker_thread(void *arg) {
    while (1) {
        client_task_t task = dequeue_task();
        int client_fd = task.client_fd;
        char message[MAX_MSG_LEN];
        char response[MAX_MSG_LEN];

        client_info_t *current_client = NULL;
        while (1) {
            receive_message(client_fd, message, task.ssl);
            
            if (current_client == NULL && strcmp(message, "R") == 0) {  // Registration
                client_info_t new_client;
                new_client.client_fd = client_fd;
                pthread_mutex_lock(&clients_mutex);
                if (client_count > MAX_CLIENTS) {
                    send_response(client_fd, "We are unable to allow more users to register.", task.ssl);
                    pthread_mutex_unlock(&clients_mutex);
                    continue;
                } else {
                    send_response(client_fd, "Good", task.ssl);
                }
                pthread_mutex_unlock(&clients_mutex);
                
                // Get username
                receive_message(client_fd, new_client.username, task.ssl);
                client_info_t *check = find_client(new_client.username);
                if (check != NULL) {
                    send_response(client_fd, "Username already exists.", task.ssl);
                    continue;
                }
                send_response(client_fd, "Good", task.ssl);

                // Get password
                receive_message(client_fd, new_client.password, task.ssl);
                add_client(new_client);
                
                send_response(client_fd, "Registration successful.", task.ssl);
            } else if (current_client == NULL && strcmp(message, "L") == 0) {  // Login
                char username[USER_NAME_MAX_LEN + 1];
                char password[USER_PWD_MAX_LEN + 1];
                receive_message(client_fd, username, task.ssl);
                // Find client
                current_client = find_client(username);
                if (current_client == NULL) {
                    send_response(client_fd, "Invalid username.", task.ssl);
                    continue;
                } else if (current_client->is_online) {
                    snprintf(response, sizeof(response), "User %s is already online.", current_client->username);
                    send_response(client_fd, response, task.ssl) ;
                    current_client = NULL ;
                    continue;
                } else {
                    send_response(client_fd, "Good", task.ssl);
                }

                // Get password
                receive_message(client_fd, password, task.ssl);
                // Check password
                if (strcmp(current_client->password, password) == 0) {
                    send_response(client_fd, "Good", task.ssl);
                    pthread_mutex_lock(&clients_mutex);
                    current_client->is_online = true ;
                    pthread_mutex_unlock(&clients_mutex);
                } else {
                    send_response(client_fd, "Invalid password.", task.ssl);
                    current_client = NULL;
                }
            } else if (strcmp(message, "Q") == 0) {  // Quit
                send_response(client_fd, "OK BYE!", task.ssl);
                if (current_client != NULL) {
                    pthread_mutex_lock(&clients_mutex);
                    current_client->is_online = false;
                    pthread_mutex_unlock(&clients_mutex);
                }
                close(client_fd);
                SSL_shutdown(task.ssl);
                SSL_free(task.ssl);
                break;
            } else if (current_client != NULL && strcmp(message, "S") == 0) {  // Message to server
                receive_message(client_fd, message, task.ssl);
                char temp_output[1000] ;
                receive_message(client_fd, message, task.ssl);
                snprintf(temp_output, sizeof(temp_output), "User \"%s\": %s", current_client->username, message);
                thread_safe_print(temp_output, CYAN);
                snprintf(response, sizeof(response), "User %s, server loves your message \"%s\"!", current_client->username, message);
                send_response(client_fd, response, task.ssl) ;
            } else if (current_client != NULL && strcmp(message, "T") == 0) {
                char receiver[USER_NAME_MAX_LEN + 1];
                char message_to_send[MAX_MSG_LEN];
                receive_message(client_fd, receiver, task.ssl);
                client_info_t* message_receiver = find_client(receiver) ;
                if (message_receiver == NULL) {
                    send_response(client_fd, "User not found.", task.ssl);
                    continue;
                } else if (message_receiver->message_count == MAX_RECEIVE_MESSAGE_NUM) {
                    send_response(client_fd, "He/She is too popular, has too many messages.", task.ssl);
                    continue;
                } else {
                    send_response(client_fd, "Good", task.ssl);
                }
                receive_message(client_fd, message_to_send, task.ssl);
                send_message_to_others(message_receiver, current_client->username, message_to_send) ;
                send_response(client_fd, "Message sent.", task.ssl);
            } else if (current_client != NULL && strcmp(message, "R") == 0) {
                snprintf(response, sizeof(response), "%d", current_client->message_count);
                send_response(client_fd, response, task.ssl);
                for (int i = 0; i < MAX_RECEIVE_MESSAGE_NUM; i++) {
                    if (current_client->message_list[i] == true) {
                        snprintf(response, sizeof(response), "%s", current_client->message_author[i]);
                        send_response(client_fd, response, task.ssl);
                        receive_message(client_fd, message, task.ssl);
                        snprintf(response, sizeof(response), "%s", current_client->message_from_others[i]);
                        send_response(client_fd, response, task.ssl);
                        receive_message(client_fd, message, task.ssl);
                        current_client->message_list[i] = false;
                    }
                }
                current_client->message_count = 0 ;
            } else if (current_client != NULL && strcmp(message, "F") == 0) {
                if (file_info.file_storage_count == MAX_STORAGE_FILE) {
                    send_response(client_fd, "Server storage is full.", task.ssl);
                    continue;
                } else {
                    send_response(client_fd, "Good", task.ssl);
                }
                char receiver[USER_NAME_MAX_LEN + 1];

                receive_message(client_fd, receiver, task.ssl);
                if (find_client(receiver) == NULL) {
                    send_response(client_fd, "User not found.", task.ssl);
                    continue;
                } else {
                    send_response(client_fd, "Good", task.ssl);
                }
                receive_file_with_name(client_fd, task.ssl, current_client->username, receiver) ;
            } else if (current_client != NULL && strcmp(message, "G") == 0) {
                int file_count = countfile(current_client->username) ;
                snprintf(response, sizeof(response), "%d", file_count);
                if (file_count == 0) {
                    send_response(client_fd, "No file from others.", task.ssl);
                    continue;
                } else {
                    send_response(client_fd, response, task.ssl);
                }
                for (int i = 0; i < MAX_STORAGE_FILE; i++) {
                    if (file_info.is_available_file[i] == true && strcmp(file_info.file_receiver[i], current_client->username) == 0) {
                        snprintf(response, sizeof(response), "%s", file_info.file_sender[i]);
                        send_response(client_fd, response, task.ssl);
                        receive_message(client_fd, message, task.ssl);
                        snprintf(response, sizeof(response), "%s", file_info.original_file_name[i]);
                        send_response(client_fd, response, task.ssl);
                        receive_message(client_fd, message, task.ssl);
                    }
                }

                for (int i = 0; i < MAX_STORAGE_FILE; i++) {
                    if (file_info.is_available_file[i] == true && strcmp(file_info.file_receiver[i], current_client->username) == 0) {
                        send_files_to_user(client_fd, i, task.ssl) ;
                        file_info.file_storage_count-- ;
                        file_info.is_available_file[i] = false ;
                        //!remove file
                    }
                }
            } else if (current_client != NULL && strcmp(message,"A") == 0) {
                stream_audio("chipichapa.mp3", client_fd);
            } else {
                // invalid input
            }
        }
    }
    return NULL;
}

SSL_CTX *create_context() {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    
    method = TLS_server_method();
    ctx = SSL_CTX_new(method);

    if (ctx == NULL) {
        perror(RED "Unable to create SSL context" RESET);
        ERR_print_errors_fp(stderr);
        abort();
    }
    if (SSL_CTX_use_certificate_file(ctx, "localhost.crt", SSL_FILETYPE_PEM) <= 0) {
        perror(RED "Unable to load certificate" RESET);
        ERR_print_errors_fp(stderr);
        abort();
    }
    if(SSL_CTX_use_PrivateKey_file(ctx, "localhost.key", SSL_FILETYPE_PEM) <= 0) {
        perror(RED "Unable to load private key" RESET);
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}


int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf(RED "Please provide the desired port number!\n" RESET);
        return 0;
    }

    signal(SIGPIPE, SIG_IGN);
    context = create_context();

    int port_number = atoi(argv[1]);
    
    struct sockaddr_in server_addr;

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror(RED "Socket creation failed" RESET);
        exit(EXIT_FAILURE);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port_number);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror(RED "Binding failed" RESET);
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, MAX_INCOME_QUEUE_NUM) < 0) {
        perror(RED "Listen failed" RESET);
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    printf(GREEN "Server is listening on port %d...\n" RESET, port_number);

    pthread_t workers[WORKER_COUNT];
    for (int i = 0; i < WORKER_COUNT; i++) {
        pthread_create(&workers[i], NULL, worker_thread, NULL);
    }

    while (1) {
        struct sockaddr_in client_addr;
        socklen_t client_addr_len = sizeof(client_addr);
        SSL *ssl ;
        int client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_addr_len);
        
        if (client_fd < 0) {
            perror(RED "Accept failed" RESET);
            continue;
        } else {
            printf(GREEN "A new client connected.\n" RESET);
        }
        
        ssl = SSL_new(context);
        SSL_set_fd(ssl, client_fd);

        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            close(client_fd);
            continue;
        }

        client_task_t task;
        task.client_fd = client_fd;
        task.client_addr = client_addr;
        task.ssl = ssl;

        enqueue_task(task);
    }

    close(server_fd);
    SSL_CTX_free(context);
    return 0;
}
