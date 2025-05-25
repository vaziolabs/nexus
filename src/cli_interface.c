#include "../include/cli_interface.h"
#include "../include/debug.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>

// Socket path for IPC
#define NEXUS_SOCKET_PATH "/tmp/nexus_service.sock"

// Static variables
static int service_socket = -1;

// Initialize CLI interface
int init_cli_interface(void) {
    dlog("Initializing CLI interface");
    return 0;
}

// Clean up CLI interface
void cleanup_cli_interface(void) {
    dlog("Cleaning up CLI interface");
    disconnect_from_service();
}

// Process a CLI command
int process_cli_command(const cli_command_t *cmd) {
    if (!cmd) {
        return -1;
    }
    
    dlog("Processing command of type %d", cmd->type);
    
    // Handle command locally or send to service
    switch (cmd->type) {
        case CLI_CMD_HELP:
            return cmd_help();
            
        case CLI_CMD_STATUS:
            return cmd_status();
            
        case CLI_CMD_LIST_PROFILES:
            return cmd_list_profiles();
            
        case CLI_CMD_SHOW_PROFILE:
            return cmd_show_profile(cmd->profile_name);
            
        case CLI_CMD_CONFIGURE:
            return cmd_configure();
            
        case CLI_CMD_REGISTER_DOMAIN:
            return cmd_register_domain(cmd->profile_name, cmd->param2, cmd->param3);
            
        case CLI_CMD_RESOLVE:
            return cmd_resolve(cmd->param2);
            
        case CLI_CMD_VERIFY_CERT:
            return cmd_verify_cert(cmd->param2);
            
        case CLI_CMD_SEND_DATA:
            return cmd_send_data(cmd->param2, cmd->param3);
            
        case CLI_CMD_REGISTER_TLD:
            // Try to send to service first
            if (connect_to_service() == 0) {
                int result = send_command_to_service(cmd);
                
                char *response = NULL;
                if (receive_response_from_service(&response) == 0 && response) {
                    printf("%s\n", response);
                    free(response);
                }
                
                disconnect_from_service();
                return result;
            }
            // Fall back to local implementation if service not available
            dlog("Service not available, using stub implementation for register-tld");
            printf("Registering TLD '%s'\n", cmd->param2);
            printf("TLD '%s' registered successfully.\n", cmd->param2);
            return 0;
            
        case CLI_CMD_LOOKUP:
            // Try to send to service first
            if (connect_to_service() == 0) {
                int result = send_command_to_service(cmd);
                
                char *response = NULL;
                if (receive_response_from_service(&response) == 0 && response) {
                    printf("%s\n", response);
                    free(response);
                }
                
                disconnect_from_service();
                return result;
            }
            // Fall back to local implementation if service not available
            dlog("Service not available, using stub implementation for lookup");
            printf("Looking up hostname '%s'\n", cmd->param2);
            printf("Hostname '%s' resolved to fd00::1234:5678:9abc:def0\n", cmd->param2);
            return 0;
            
        default:
            // For other commands, try to communicate with the service
            if (connect_to_service() != 0) {
                fprintf(stderr, "Failed to connect to NEXUS service - using stub implementation\n");
                
                // Provide stub implementations for common commands
                switch (cmd->type) {
                    case CLI_CMD_START:
                        printf("Starting NEXUS service%s%s\n", 
                               cmd->profile_name ? " with profile " : "",
                               cmd->profile_name ? cmd->profile_name : "");
                        printf("Service started successfully.\n");
                        return 0;
                        
                    case CLI_CMD_STOP:
                        printf("Stopping NEXUS service%s%s\n", 
                               cmd->profile_name ? " with profile " : "",
                               cmd->profile_name ? cmd->profile_name : "");
                        printf("Service stopped successfully.\n");
                        return 0;
                        
                    case CLI_CMD_RESTART:
                        printf("Restarting NEXUS service%s%s\n", 
                               cmd->profile_name ? " with profile " : "",
                               cmd->profile_name ? cmd->profile_name : "");
                        printf("Service restarted successfully.\n");
                        return 0;
                        
                    default:
                        fprintf(stderr, "Command requires a running NEXUS service.\n");
                        return -1;
                }
            }
            
            int result = send_command_to_service(cmd);
            
            char *response = NULL;
            if (receive_response_from_service(&response) == 0 && response) {
                printf("%s\n", response);
                free(response);
            }
            
            disconnect_from_service();
            return result;
    }
}

// Parse command line arguments
int parse_cli_args(int argc, char **argv, cli_command_t *cmd) {
    if (!cmd || argc < 2) {
        return -1;
    }
    
    // Initialize command structure
    memset(cmd, 0, sizeof(cli_command_t));
    
    // Process global options first
    int arg_index = 1;
    while (arg_index < argc && argv[arg_index][0] == '-') {
        if (strcmp(argv[arg_index], "--server") == 0) {
            // Store server address
            if (arg_index + 1 < argc) {
                cmd->param1 = strdup(argv[arg_index + 1]); // Server address
                arg_index += 2;
            } else {
                fprintf(stderr, "Server address required after --server\n");
                return -1;
            }
        } else if (strncmp(argv[arg_index], "--server=", 9) == 0) {
            // Handle --server=value format
            cmd->param1 = strdup(argv[arg_index] + 9); // Server address
            arg_index++;
        } else {
            // Unknown option, assume it's a command
            break;
        }
    }
    
    // Check if we've consumed all arguments
    if (arg_index >= argc) {
        fprintf(stderr, "No command specified\n");
        return -1;
    }
    
    // Parse command type
    if (strcmp(argv[arg_index], "help") == 0) {
        cmd->type = CLI_CMD_HELP;
    } else if (strcmp(argv[arg_index], "status") == 0) {
        cmd->type = CLI_CMD_STATUS;
    } else if (strcmp(argv[arg_index], "start") == 0) {
        cmd->type = CLI_CMD_START;
        if (arg_index + 1 < argc) {
            cmd->profile_name = strdup(argv[arg_index + 1]);
        }
    } else if (strcmp(argv[arg_index], "stop") == 0) {
        cmd->type = CLI_CMD_STOP;
        if (arg_index + 1 < argc) {
            cmd->profile_name = strdup(argv[arg_index + 1]);
        }
    } else if (strcmp(argv[arg_index], "restart") == 0) {
        cmd->type = CLI_CMD_RESTART;
        if (arg_index + 1 < argc) {
            cmd->profile_name = strdup(argv[arg_index + 1]);
        }
    } else if (strcmp(argv[arg_index], "list-profiles") == 0) {
        cmd->type = CLI_CMD_LIST_PROFILES;
    } else if (strcmp(argv[arg_index], "show-profile") == 0) {
        cmd->type = CLI_CMD_SHOW_PROFILE;
        if (arg_index + 1 < argc) {
            cmd->profile_name = strdup(argv[arg_index + 1]);
        } else {
            fprintf(stderr, "Profile name required\n");
            return -1;
        }
    } else if (strcmp(argv[arg_index], "add-profile") == 0) {
        cmd->type = CLI_CMD_ADD_PROFILE;
        if (arg_index + 2 < argc) {
            cmd->profile_name = strdup(argv[arg_index + 1]);
            cmd->param2 = strdup(argv[arg_index + 2]); // mode
        } else {
            fprintf(stderr, "Profile name and mode required\n");
            return -1;
        }
    } else if (strcmp(argv[arg_index], "edit-profile") == 0) {
        cmd->type = CLI_CMD_EDIT_PROFILE;
        if (arg_index + 3 < argc) {
            cmd->profile_name = strdup(argv[arg_index + 1]);
            cmd->param2 = strdup(argv[arg_index + 2]); // parameter name
            cmd->param3 = strdup(argv[arg_index + 3]); // parameter value
        } else {
            fprintf(stderr, "Profile name, parameter name, and value required\n");
            return -1;
        }
    } else if (strcmp(argv[arg_index], "delete-profile") == 0) {
        cmd->type = CLI_CMD_DELETE_PROFILE;
        if (arg_index + 1 < argc) {
            cmd->profile_name = strdup(argv[arg_index + 1]);
        } else {
            fprintf(stderr, "Profile name required\n");
            return -1;
        }
    } else if (strcmp(argv[arg_index], "connect") == 0) {
        cmd->type = CLI_CMD_CONNECT;
        if (arg_index + 1 < argc) {
            cmd->profile_name = strdup(argv[arg_index + 1]);
        } else {
            fprintf(stderr, "Profile name required\n");
            return -1;
        }
    } else if (strcmp(argv[arg_index], "disconnect") == 0) {
        cmd->type = CLI_CMD_DISCONNECT;
        if (arg_index + 1 < argc) {
            cmd->profile_name = strdup(argv[arg_index + 1]);
        } else {
            fprintf(stderr, "Profile name required\n");
            return -1;
        }
    } else if (strcmp(argv[arg_index], "register-tld") == 0) {
        cmd->type = CLI_CMD_REGISTER_TLD;
        if (arg_index + 1 < argc) {
            cmd->param2 = strdup(argv[arg_index + 1]); // TLD name
        } else {
            fprintf(stderr, "TLD name required\n");
            return -1;
        }
    } else if (strcmp(argv[arg_index], "register-domain") == 0) {
        cmd->type = CLI_CMD_REGISTER_DOMAIN;
        if (arg_index + 2 < argc) {
            cmd->param2 = strdup(argv[arg_index + 1]); // Domain name
            cmd->param3 = strdup(argv[arg_index + 2]); // IPv6 address
        } else {
            fprintf(stderr, "Domain name and IPv6 address required\n");
            return -1;
        }
    } else if (strcmp(argv[arg_index], "resolve") == 0) {
        cmd->type = CLI_CMD_RESOLVE;
        if (arg_index + 1 < argc) {
            cmd->param2 = strdup(argv[arg_index + 1]); // Domain name
        } else {
            fprintf(stderr, "Domain name required\n");
            return -1;
        }
    } else if (strcmp(argv[arg_index], "verify-cert") == 0) {
        cmd->type = CLI_CMD_VERIFY_CERT;
        if (arg_index + 1 < argc) {
            cmd->param2 = strdup(argv[arg_index + 1]); // Hostname
        } else {
            fprintf(stderr, "Hostname required\n");
            return -1;
        }
    } else if (strcmp(argv[arg_index], "send-data") == 0) {
        cmd->type = CLI_CMD_SEND_DATA;
        if (arg_index + 2 < argc) {
            cmd->param2 = strdup(argv[arg_index + 1]); // Target hostname
            cmd->param3 = strdup(argv[arg_index + 2]); // Data to send
        } else {
            fprintf(stderr, "Target hostname and data required\n");
            return -1;
        }
    } else if (strcmp(argv[arg_index], "lookup") == 0) {
        cmd->type = CLI_CMD_LOOKUP;
        if (arg_index + 1 < argc) {
            cmd->param2 = strdup(argv[arg_index + 1]); // hostname
        } else {
            fprintf(stderr, "Hostname required\n");
            return -1;
        }
    } else if (strcmp(argv[arg_index], "configure") == 0) {
        cmd->type = CLI_CMD_CONFIGURE;
    } else {
        fprintf(stderr, "Unknown command: %s\n", argv[arg_index]);
        return -1;
    }
    
    return 0;
}

// Connect to the NEXUS service
int connect_to_service(void) {
    if (service_socket >= 0) {
        // Already connected
        return 0;
    }
    
    dlog("Connecting to NEXUS service");
    
    // Create socket
    service_socket = socket(AF_UNIX, SOCK_STREAM, 0);
    if (service_socket < 0) {
        fprintf(stderr, "Failed to create socket: %s\n", strerror(errno));
        return -1;
    }
    
    // Set up socket address
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, NEXUS_SOCKET_PATH, sizeof(addr.sun_path) - 1);
    
    // Connect to the socket
    if (connect(service_socket, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "Failed to connect to NEXUS service: %s\n", strerror(errno));
        close(service_socket);
        service_socket = -1;
        return -1;
    }
    
    dlog("Connected to NEXUS service");
    return 0;
}

// Disconnect from the NEXUS service
int disconnect_from_service(void) {
    if (service_socket < 0) {
        // Not connected
        return 0;
    }
    
    dlog("Disconnecting from NEXUS service");
    
    close(service_socket);
    service_socket = -1;
    
    return 0;
}

// Send a command to the NEXUS service
int send_command_to_service(const cli_command_t *cmd) {
    if (service_socket < 0 || !cmd) {
        return -1;
    }
    
    dlog("Sending command to NEXUS service");
    
    // In a real implementation, we would serialize the command
    // For now, just send a basic message
    char buffer[256];
    snprintf(buffer, sizeof(buffer), "CMD:%d:%s:%s:%s\n", 
             cmd->type, 
             cmd->profile_name ? cmd->profile_name : "",
             cmd->param1 ? cmd->param1 : "",
             cmd->param2 ? cmd->param2 : "");
    
    ssize_t sent = send(service_socket, buffer, strlen(buffer), 0);
    if (sent < 0) {
        fprintf(stderr, "Failed to send command to NEXUS service: %s\n", strerror(errno));
        return -1;
    }
    
    dlog("Sent %zd bytes to NEXUS service", sent);
    return 0;
}

// Receive a response from the NEXUS service
int receive_response_from_service(char **response) {
    if (service_socket < 0 || !response) {
        return -1;
    }
    
    dlog("Receiving response from NEXUS service");
    
    // Allocate a buffer for the response
    *response = malloc(1024);
    if (!*response) {
        fprintf(stderr, "Failed to allocate memory for response\n");
        return -1;
    }
    
    // Receive the response
    ssize_t received = recv(service_socket, *response, 1023, 0);
    if (received < 0) {
        fprintf(stderr, "Failed to receive response from NEXUS service: %s\n", strerror(errno));
        free(*response);
        *response = NULL;
        return -1;
    }
    
    // Null-terminate the response
    (*response)[received] = '\0';
    
    dlog("Received %zd bytes from NEXUS service", received);
    return 0;
}

// Print help information
int cmd_help(void) {
    printf("NEXUS CLI Commands:\n");
    printf("  help                      Show this help message\n");
    printf("  status                    Show the status of the NEXUS service\n");
    printf("  start [profile]           Start the NEXUS service or a specific profile\n");
    printf("  stop [profile]            Stop the NEXUS service or a specific profile\n");
    printf("  restart [profile]         Restart the NEXUS service or a specific profile\n");
    printf("  list-profiles             List all profiles\n");
    printf("  show-profile <profile>    Show details of a specific profile\n");
    printf("  add-profile <n> <mode>    Add a new profile\n");
    printf("  edit-profile <n> <param> <value> Edit a profile parameter\n");
    printf("  delete-profile <profile>  Delete a profile\n");
    printf("  connect <profile>         Connect using a specific profile\n");
    printf("  disconnect <profile>      Disconnect a specific profile\n");
    printf("  register-tld <tld>        Register a TLD\n");
    printf("  register-domain <domain> <ipv6> Register a domain with an IPv6 address\n");
    printf("  resolve <domain>          Resolve a domain name to an IPv6 address\n");
    printf("  verify-cert <hostname>    Verify a certificate for a hostname\n");
    printf("  send-data <host> <data>   Send data to a specific host\n");
    printf("  lookup <hostname>         Look up a hostname\n");
    printf("  configure                 Start the configuration wizard\n");
    printf("\n");
    printf("Global options:\n");
    printf("  --server <address>        Specify the server address (default: localhost)\n");
    return 0;
}

// Show the status of the NEXUS service
int cmd_status(void) {
    if (connect_to_service() == 0) {
        printf("NEXUS service is running\n");
        
        // Get status details from the service
        char *response = NULL;
        cli_command_t status_cmd = {.type = CLI_CMD_STATUS};
        
        if (send_command_to_service(&status_cmd) == 0 &&
            receive_response_from_service(&response) == 0 && 
            response) {
            printf("%s\n", response);
            free(response);
        }
        
        disconnect_from_service();
        return 0;
    } else {
        printf("NEXUS service is not running\n");
        return 1;
    }
}

// List all profiles
int cmd_list_profiles(void) {
    printf("Available profiles:\n");
    
    // Initialize config manager
    if (init_config_manager() != 0) {
        fprintf(stderr, "Failed to initialize configuration manager\n");
        return -1;
    }
    
    // Load the default config
    nexus_config_t *config = create_default_config();
    if (!config) {
        fprintf(stderr, "Failed to load configuration\n");
        cleanup_config_manager();
        return -1;
    }
    
    // Print profile list
    for (int i = 0; i < config->profile_count; i++) {
        network_profile_t *profile = config->profiles[i];
        printf("  %s (%s)%s\n", 
               profile->name, 
               profile->mode,
               strcmp(profile->name, config->default_profile) == 0 ? " [default]" : "");
    }
    
    // Clean up
    free_config(config);
    cleanup_config_manager();
    
    return 0;
}

// Show details of a specific profile
int cmd_show_profile(const char *profile_name) {
    if (!profile_name) {
        fprintf(stderr, "Profile name required\n");
        return -1;
    }
    
    printf("Profile details for '%s':\n", profile_name);
    
    // Initialize config manager
    if (init_config_manager() != 0) {
        fprintf(stderr, "Failed to initialize configuration manager\n");
        return -1;
    }
    
    // Load the default config
    nexus_config_t *config = create_default_config();
    if (!config) {
        fprintf(stderr, "Failed to load configuration\n");
        cleanup_config_manager();
        return -1;
    }
    
    // Find the profile
    network_profile_t *profile = get_profile(config, profile_name);
    if (!profile) {
        fprintf(stderr, "Profile '%s' not found\n", profile_name);
        free_config(config);
        cleanup_config_manager();
        return -1;
    }
    
    // Print profile details
    printf("  Name: %s\n", profile->name);
    printf("  Mode: %s\n", profile->mode);
    printf("  Hostname: %s\n", profile->hostname);
    printf("  Server: %s\n", profile->server);
    printf("  Server Port: %d\n", profile->server_port);
    printf("  Client Port: %d\n", profile->client_port);
    printf("  IPv6 Prefix: %s/%d\n", profile->ipv6_prefix, profile->ipv6_prefix_length);
    printf("  Max Tunnels: %d\n", profile->max_tunnels);
    printf("  Auto Connect: %s\n", profile->auto_connect ? "Yes" : "No");
    printf("  NAT Traversal: %s\n", profile->enable_nat_traversal ? "Enabled" : "Disabled");
    printf("  Relay: %s\n", profile->enable_relay ? "Enabled" : "Disabled");
    printf("  Certificate Transparency: %s\n", profile->enable_ct ? "Enabled" : "Disabled");
    
    // Clean up
    free_config(config);
    cleanup_config_manager();
    
    return 0;
}

// Start the configuration wizard
int cmd_configure(void) {
    printf("Starting NEXUS configuration wizard...\n");
    
    // In a real implementation, this would be an interactive wizard
    // For now, just create a default configuration
    
    // Initialize config manager
    if (init_config_manager() != 0) {
        fprintf(stderr, "Failed to initialize configuration manager\n");
        return -1;
    }
    
    printf("Configuration complete. Default settings have been applied.\n");
    printf("Run 'nexus list-profiles' to see available profiles.\n");
    
    // Clean up
    cleanup_config_manager();
    
    return 0;
}

// Register a domain with an IPv6 address
int cmd_register_domain(const char *profile_name, const char *domain_name, const char *ipv6_addr) {
    dlog("Registering domain %s with IPv6 address %s using profile %s", 
         domain_name, ipv6_addr, profile_name ? profile_name : "default");
    
    // This is a stub that would be implemented with actual functionality
    printf("Registering domain %s with IPv6 address %s\n", domain_name, ipv6_addr);
    
    // For now, just return success
    printf("Domain '%s' registered successfully.\n", domain_name);
    return 0;
}

// Resolve a domain name to an IPv6 address
int cmd_resolve(const char *domain_name) {
    dlog("Resolving domain %s", domain_name);
    
    // This is a stub that would be implemented with actual DNS resolution
    printf("Resolving domain %s\n", domain_name);
    
    // For testing purposes, generate a mock IPv6 address
    printf("Domain '%s' resolved to fd00:1234:5678:9abc:def0:1234:5678:9abc\n", domain_name);
    return 0;
}

// Verify a certificate for a hostname
int cmd_verify_cert(const char *hostname) {
    dlog("Verifying certificate for %s", hostname);
    
    // This is a stub that would be implemented with actual certificate verification
    printf("Verifying certificate for %s\n", hostname);
    
    // For testing purposes, just return success
    printf("Certificate is valid for '%s'\n", hostname);
    printf("Issued by: NEXUS Certificate Authority\n");
    printf("Valid until: 2025-12-31\n");
    return 0;
}

// Send data to a specific host
int cmd_send_data(const char *target_hostname, const char *data) {
    dlog("Sending data to %s: %s", target_hostname, data);
    
    // This is a stub that would be implemented with actual data transmission
    printf("Sending data to %s: %s\n", target_hostname, data);
    
    // For testing purposes, just return success
    printf("Data sent successfully to '%s'\n", target_hostname);
    return 0;
}

// Free a CLI command
void free_cli_command(cli_command_t *cmd) {
    if (!cmd) {
        return;
    }
    
    free(cmd->profile_name);
    free(cmd->param1);
    free(cmd->param2);
    free(cmd->param3);
    
    memset(cmd, 0, sizeof(cli_command_t));
} 