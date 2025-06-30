#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <libwebsockets.h>
#include <sys/stat.h>
#include <errno.h>
#include "audit.h"
#include "utils.h"

static audit_config_t config = {0};
static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

static int ensure_log_dir(const char *log_file) {
    char *log_dir = strdup(log_file);
    char *last_slash = strrchr(log_dir, '/');
    if (last_slash) {
        *last_slash = '\0';
        lwsl_notice("Creating log directory: %s\n", log_dir);
        if (mkdir(log_dir, 0755) != 0 && errno != EEXIST) {
            lwsl_err("Failed to create log directory: %s, error: %s\n", log_dir, strerror(errno));
            free(log_dir);
            return -1;
        }
        lwsl_notice("Log directory created or already exists: %s\n", log_dir);
    }
    free(log_dir);
    return 0;
}

int audit_init(const char *log_file) {
    lwsl_notice("Initializing audit system with log file: %s\n", log_file);
    
    if (config.enabled) {
        lwsl_notice("Audit system already initialized\n");
        return 0;
    }

    // Ensure log directory exists
    if (ensure_log_dir(log_file) != 0) {
        lwsl_err("Failed to ensure log directory exists\n");
        return -1;
    }

    config.log_file = strdup(log_file);
    config.enabled = true;
    config.max_size = 10 * 1024 * 1024;  // Default 10MB

    lwsl_notice("Opening log file: %s\n", log_file);
    // Create log file
    FILE *fp = fopen(log_file, "a");
    if (fp == NULL) {
        lwsl_err("Failed to open audit log file: %s, error: %s\n", log_file, strerror(errno));
        return -1;
    }
    fclose(fp);
    lwsl_notice("Log file opened successfully\n");

    lwsl_notice("Audit system initialized successfully\n");
    return 0;
}

// Add custom fields
int audit_add_custom_field(const char *key, const char *value) {
    if (!key || !value) {
        lwsl_err("Invalid custom field key or value\n");
        return -1;
    }

    pthread_mutex_lock(&log_mutex);
    
    // Reallocate memory
    audit_custom_field_t *new_fields = xrealloc(config.custom_fields, 
        (config.custom_fields_count + 1) * sizeof(audit_custom_field_t));
    
    if (!new_fields) {
        lwsl_err("Failed to allocate memory for custom field\n");
        pthread_mutex_unlock(&log_mutex);
        return -1;
    }
    
    config.custom_fields = new_fields;
    
    // Add new field
    size_t key_len = strlen(key);
    size_t value_len = strlen(value);
    
    config.custom_fields[config.custom_fields_count].key = xmalloc(key_len + 1);
    config.custom_fields[config.custom_fields_count].value = xmalloc(value_len + 1);
    
    if (!config.custom_fields[config.custom_fields_count].key || 
        !config.custom_fields[config.custom_fields_count].value) {
        lwsl_err("Failed to allocate memory for custom field strings\n");
        if (config.custom_fields[config.custom_fields_count].key) {
            free(config.custom_fields[config.custom_fields_count].key);
        }
        if (config.custom_fields[config.custom_fields_count].value) {
            free(config.custom_fields[config.custom_fields_count].value);
        }
        pthread_mutex_unlock(&log_mutex);
        return -1;
    }
    
    strncpy(config.custom_fields[config.custom_fields_count].key, key, key_len);
    config.custom_fields[config.custom_fields_count].key[key_len] = '\0';
    
    strncpy(config.custom_fields[config.custom_fields_count].value, value, value_len);
    config.custom_fields[config.custom_fields_count].value[value_len] = '\0';
    
    config.custom_fields_count++;
    pthread_mutex_unlock(&log_mutex);
    
    lwsl_notice("Added custom field: %s=%s\n", key, value);
    return 0;
}

// Clear all custom fields
void audit_clear_custom_fields(void) {
    pthread_mutex_lock(&log_mutex);
    
    for (int i = 0; i < config.custom_fields_count; i++) {
        free(config.custom_fields[i].key);
        free(config.custom_fields[i].value);
    }
    
    free(config.custom_fields);
    config.custom_fields = NULL;
    config.custom_fields_count = 0;
    
    pthread_mutex_unlock(&log_mutex);
    lwsl_notice("Cleared all custom fields\n");
}

// Rotate log file
static int rotate_log(void) {
    char new_name[256];
    snprintf(new_name, sizeof(new_name), "%s.1", config.log_file);
    
    // Rename current log file
    if (rename(config.log_file, new_name) != 0) {
        lwsl_err("Failed to rename log file: %s\n", strerror(errno));
        return -1;
    }

    // Create new log file
    FILE *fp = fopen(config.log_file, "a");
    if (fp == NULL) {
        lwsl_err("Failed to create new log file: %s\n", strerror(errno));
        // If creating new file fails, try to restore original file
        if (rename(new_name, config.log_file) != 0) {
            lwsl_err("Failed to restore original log file: %s\n", strerror(errno));
        }
        return -1;
    }
    fclose(fp);

    lwsl_notice("Log rotated: %s -> %s\n", config.log_file, new_name);
    return 0;
}

static void write_log_entry(const audit_entry_t *entry) {
    lwsl_notice("Writing log entry to file: %s\n", config.log_file);
    pthread_mutex_lock(&log_mutex);

    // Check file size
    struct stat st;
    if (stat(config.log_file, &st) == 0 && st.st_size >= config.max_size) {
        lwsl_notice("Need to rotate log file, current file size: %d, config.max_size: %d\n",st.st_size,config.max_size);
        int ret = rotate_log();
        if (ret != 0) {
            lwsl_err("Failed to rotate log file\n");
            pthread_mutex_unlock(&log_mutex);
            return;
        }
    }

    FILE *fp = fopen(config.log_file, "a");
    if (fp == NULL) {
        lwsl_err("Failed to open audit log file for writing: %s\n", strerror(errno));
        pthread_mutex_unlock(&log_mutex);
        return;
    }

    char timestamp[32];
    struct tm *tm_info = localtime(&entry->timestamp);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);

    // Write timestamp and address
    fprintf(fp, "[%s] Address: %s", 
            timestamp, 
            entry->address ? entry->address : "unknown");
            
    // Write custom fields
    for (int i = 0; i < entry->custom_fields_count; i++) {
        fprintf(fp, ", %s: %s", 
                entry->custom_fields[i].key,
                entry->custom_fields[i].value);
    }

    if (entry->command) {
        fprintf(fp, ", Command: %s", entry->command);
    }
    fprintf(fp, "\n");
    fflush(fp);
    fclose(fp);
    pthread_mutex_unlock(&log_mutex);
    lwsl_notice("Log entry written successfully\n");
}

// Clean command string, remove control characters
static char *clean_command_string(const char *cmd) {
    if (!cmd) return NULL;
    
    size_t len = strlen(cmd);
    char *clean = xmalloc(len + 1);
    size_t j = 0;
    
    for (size_t i = 0; i < len; i++) {
        // Skip control characters (ASCII 0-31, except newline and carriage return)
        if (cmd[i] >= 32 || cmd[i] == '\n' || cmd[i] == '\r') {
            clean[j++] = cmd[i];
        }
    }
    clean[j] = '\0';
    
    // Remove trailing whitespace characters
    while (j > 0 && (clean[j-1] == ' ' || clean[j-1] == '\t')) {
        clean[--j] = '\0';
    }
    
    return clean;
}

// Modify audit_log_command function
void audit_log_command(const char *address, const char *command) {
    if (!config.enabled) {
        lwsl_notice("Audit system is not enabled, skipping log entry\n");
        return;
    }
    
    char *clean_cmd = clean_command_string(command);
    lwsl_notice("Logging command: address='%s', command='%s'\n", 
               address, clean_cmd);
               
    audit_entry_t entry = {
        .timestamp = time(NULL),
        .address = strdup(address),
        .command = clean_cmd,
        .custom_fields = NULL,
        .custom_fields_count = 0
    };

    // Copy custom fields
    if (config.custom_fields_count > 0) {
        entry.custom_fields = xmalloc((config.custom_fields_count + 1) * sizeof(audit_custom_field_t));
        entry.custom_fields_count = config.custom_fields_count;
        
        for (int i = 0; i < config.custom_fields_count; i++) {
            entry.custom_fields[i].key = strdup(config.custom_fields[i].key);
            entry.custom_fields[i].value = strdup(config.custom_fields[i].value);
        }
    } else {
        entry.custom_fields = xmalloc(sizeof(audit_custom_field_t));
        entry.custom_fields_count = 0;
    }

    write_log_entry(&entry);

    // Clean memory
    free(entry.address);
    free(entry.command);
    for (int i = 0; i < entry.custom_fields_count; i++) {
        free(entry.custom_fields[i].key);
        free(entry.custom_fields[i].value);
    }
    free(entry.custom_fields);
}

// Validate audit field format
int validate_audit_field(const char *field) {
    if (!field) {
        lwsl_err("Invalid audit field: NULL\n");
        return -1;
    }

    // Check if it contains an equal sign
    char *value = strchr(field, '=');
    if (!value) {
        lwsl_err("Invalid audit field format: %s (should be key=value)\n", field);
        return -1;
    }

    // Validate key name is not empty
    if (value == field) {
        lwsl_err("Empty key in audit field: %s\n", field);
        return -1;
    }

    // Validate value is not empty
    if (*(value + 1) == '\0') {
        lwsl_err("Empty value in audit field: %s\n", field);
        return -1;
    }

    return 0;
}

// Modify audit_cleanup function to clean up custom fields
void audit_cleanup(void) {
    lwsl_notice("Cleaning up audit system\n");
    if (!config.enabled) {
        lwsl_notice("Audit system is not enabled, nothing to clean up\n");
        return;
    }

    free(config.log_file);
    audit_clear_custom_fields();  // Clean up custom fields
    config.enabled = false;
    pthread_mutex_destroy(&log_mutex);
    lwsl_notice("Audit system cleaned up successfully\n");
} 