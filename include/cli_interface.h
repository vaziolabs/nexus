#ifndef CLI_INTERFACE_H
#define CLI_INTERFACE_H

#include <stdint.h>
#include "config_manager.h"

// CLI command types
typedef enum {
    CLI_CMD_HELP,
    CLI_CMD_STATUS,
    CLI_CMD_START,
    CLI_CMD_STOP,
    CLI_CMD_RESTART,
    CLI_CMD_LIST_PROFILES,
    CLI_CMD_SHOW_PROFILE,
    CLI_CMD_ADD_PROFILE,
    CLI_CMD_EDIT_PROFILE,
    CLI_CMD_DELETE_PROFILE,
    CLI_CMD_CONNECT,
    CLI_CMD_DISCONNECT,
    CLI_CMD_REGISTER_TLD,
    CLI_CMD_REGISTER_DOMAIN,
    CLI_CMD_RESOLVE,
    CLI_CMD_VERIFY_CERT,
    CLI_CMD_SEND_DATA,
    CLI_CMD_LOOKUP,
    CLI_CMD_CONFIGURE
} cli_command_type_t;

// CLI command structure
typedef struct {
    cli_command_type_t type;
    char *profile_name;
    char *param1;
    char *param2;
    char *param3;
    int flag1;
    int flag2;
} cli_command_t;

// Function declarations
int init_cli_interface(void);
void cleanup_cli_interface(void);

// Command processing
int process_cli_command(const cli_command_t *cmd);
int parse_cli_args(int argc, char **argv, cli_command_t *cmd, char **socket_path, char **config_profile_name);

// Command execution
int cmd_help(void);
int cmd_status(void);
int cmd_start(const char *profile_name);
int cmd_stop(const char *profile_name);
int cmd_restart(const char *profile_name);
int cmd_list_profiles(void);
int cmd_show_profile(const char *profile_name);
int cmd_add_profile(const char *profile_name, const char *mode);
int cmd_edit_profile(const char *profile_name, const char *param, const char *value);
int cmd_delete_profile(const char *profile_name);
int cmd_connect(const char *profile_name);
int cmd_disconnect(const char *profile_name);
int cmd_register_tld(const char *profile_name, const char *tld_name);
int cmd_register_domain(const char *profile_name, const char *domain_name, const char *ipv6_addr);
int cmd_resolve(const char *domain_name, const char *server_address);
int cmd_verify_cert(const char *hostname);
int cmd_send_data(const char *target_hostname, const char *data);
int cmd_lookup(const char *hostname);
int cmd_configure(void);

// IPC communication with service
int connect_to_service(void);
int disconnect_from_service(void);
int send_command_to_service(const cli_command_t *cmd);
int receive_response_from_service(char **response);

// Utility functions
void print_command_help(void);
void free_cli_command(cli_command_t *cmd);

// New CLI command handlers
int handle_cli_command(int argc, char *argv[]);
int handle_status_command(int argc, char *argv[]);
int handle_resolve_command(int argc, char *argv[]);
int handle_send_command(int argc, char *argv[]);

#endif // CLI_INTERFACE_H 