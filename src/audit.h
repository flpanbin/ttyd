#ifndef AUDIT_H
#define AUDIT_H

#include <time.h>
#include <stdbool.h>

// Custom field structure
typedef struct {
    char *key;
    char *value;
} audit_custom_field_t;

// Audit configuration structure
typedef struct {
    bool enabled;
    char *log_file;
    audit_custom_field_t *custom_fields;  // Custom fields array
    int custom_fields_count;              // Custom fields count
    size_t max_size;                      // Maximum size of single log file (bytes)
} audit_config_t;

// Audit log entry structure
typedef struct {
    time_t timestamp;
    char *address;
    char *command;
    audit_custom_field_t *custom_fields;  // Custom fields array
    int custom_fields_count;              // Custom fields count
} audit_entry_t;

// Initialize audit system
int audit_init(const char *log_file);

// Log command
void audit_log_command(const char *address, const char *command);

// 关闭审计系统
void audit_cleanup(void);

// 新增函数声明
int audit_add_custom_field(const char *key, const char *value);
void audit_clear_custom_fields(void);

// Validate audit field format
int validate_audit_field(const char *field);

#endif // AUDIT_H 