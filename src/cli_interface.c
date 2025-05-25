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
            
        default:
            // For other commands, we need to communicate with the service
            if (connect_to_service() != 0) {
                fprintf(stderr, "Failed to connect to NEXUS service\n");
                return -1;
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
    
    // Parse command type
    if (strcmp(argv[1], "help") == 0) {
        cmd->type = CLI_CMD_HELP;
    } else if (strcmp(argv[1], "status") == 0) {
        cmd->type = CLI_CMD_STATUS;
    } else if (strcmp(argv[1], "start") == 0) {
        cmd->type = CLI_CMD_START;
        if (argc > 2) {
            cmd->profile_name = strdup(argv[2]);
        }
    } else if (strcmp(argv[1], "stop") == 0) {
        cmd->type = CLI_CMD_STOP;
        if (argc > 2) {
            cmd->profile_name = strdup(argv[2]);
        }
    } else if (strcmp(argv[1], "restart") == 0) {
        cmd->type = CLI_CMD_RESTART;
        if (argc > 2) {
            cmd->profile_name = strdup(argv[2]);
        }
    } else if (strcmp(argv[1], "list-profiles") == 0) {
        cmd->type = CLI_CMD_LIST_PROFILES;
    } else if (strcmp(argv[1], "show-profile") == 0) {
        cmd->type = CLI_CMD_SHOW_PROFILE;
        if (argc > 2) {
            cmd->profile_name = strdup(argv[2]);
        } else {
            fprintf(stderr, "Profile name required\n");
            return -1;
        }
    } else if (strcmp(argv[1], "add-profile") == 0) {
        cmd->type = CLI_CMD_ADD_PROFILE;
        if (argc > 3) {
            cmd->profile_name = strdup(argv[2]);
            cmd->param1 = strdup(argv[3]); // mode
        } else {
            fprintf(stderr, "Profile name and mode required\n");
            return -1;
        }
    } else if (strcmp(argv[1], "edit-profile") == 0) {
        cmd->type = CLI_CMD_EDIT_PROFILE;
        if (argc > 4) {
            cmd->profile_name = strdup(argv[2]);
            cmd->param1 = strdup(argv[3]); // parameter name
            cmd->param2 = strdup(argv[4]); // parameter value
        } else {
            fprintf(stderr, "Profile name, parameter name, and value required\n");
            return -1;
        }
    } else if (strcmp(argv[1], "delete-profile") == 0) {
        cmd->type = CLI_CMD_DELETE_PROFILE;
        if (argc > 2) {
            cmd->profile_name = strdup(argv[2]);
        } else {
            fprintf(stderr, "Profile name required\n");
            return -1;
        }
    } else if (strcmp(argv[1], "connect") == 0) {
        cmd->type = CLI_CMD_CONNECT;
        if (argc > 2) {
            cmd->profile_name = strdup(argv[2]);
        } else {
            fprintf(stderr, "Profile name required\n");
            return -1;
        }
    } else if (strcmp(argv[1], "disconnect") == 0) {
        cmd->type = CLI_CMD_DISCONNECT;
        if (argc > 2) {
            cmd->profile_name = strdup(argv[2]);
        } else {
            fprintf(stderr, "Profile name required\n");
            return -1;
        }
    } else if (strcmp(argv[1], "register-tld") == 0) {
        cmd->type = CLI_CMD_REGISTER_TLD;
        if (argc > 3) {
            cmd->profile_name = strdup(argv[2]);
            cmd->param1 = strdup(argv[3]); // TLD name
        } else {
            fprintf(stderr, "Profile name and TLD name required\n");
            return -1;
        }
    } else if (strcmp(argv[1], "lookup") == 0) {
        cmd->type = CLI_CMD_LOOKUP;
        if (argc > 2) {
            cmd->param1 = strdup(argv[2]); // hostname
        } else {
            fprintf(stderr, "Hostname required\n");
            return -1;
        }
    } else if (strcmp(argv[1], "configure") == 0) {
        cmd->type = CLI_CMD_CONFIGURE;
    } else {
        fprintf(stderr, "Unknown command: %s\n", argv[1]);
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
    printf("  add-profile <name> <mode> Add a new profile\n");
    printf("  edit-profile <name> <param> <value> Edit a profile parameter\n");
    printf("  delete-profile <profile>  Delete a profile\n");
    printf("  connect <profile>         Connect using a specific profile\n");
    printf("  disconnect <profile>      Disconnect a specific profile\n");
    printf("  register-tld <profile> <tld> Register a TLD using a specific profile\n");
    printf("  lookup <hostname>         Look up a hostname\n");
    printf("  configure                 Start the configuration wizard\n");
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

// Free a CLI command
void free_cli_command(cli_command_t *cmd) {
    if (!cmd) {
        return;
    }
    
    free(cmd->profile_name);
    free(cmd->param1);
    free(cmd->param2);
    
    memset(cmd, 0, sizeof(cli_command_t));
} 