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

// 确保日志目录存在
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

int audit_init(const char *log_file, bool log_commands, bool log_output) {
    lwsl_notice("Initializing audit system with log file: %s\n", log_file);
    
    if (config.enabled) {
        lwsl_notice("Audit system already initialized\n");
        return 0;
    }

    // 确保日志目录存在
    if (ensure_log_dir(log_file) != 0) {
        lwsl_err("Failed to ensure log directory exists\n");
        return -1;
    }

    config.log_file = strdup(log_file);
    config.enabled = true;
    config.log_commands = log_commands;
    config.log_output = log_output;

    lwsl_notice("Opening log file: %s\n", log_file);
    // 创建日志文件
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

static void write_log_entry(const audit_entry_t *entry) {
    if (!config.enabled) {
        lwsl_notice("Audit system is not enabled, skipping log entry\n");
        return;
    }

    lwsl_notice("Writing log entry to file: %s\n", config.log_file);
    pthread_mutex_lock(&log_mutex);

    FILE *fp = fopen(config.log_file, "a");
    if (fp == NULL) {
        lwsl_err("Failed to open audit log file for writing: %s\n", strerror(errno));
        pthread_mutex_unlock(&log_mutex);
        return;
    }

    char timestamp[32];
    struct tm *tm_info = localtime(&entry->timestamp);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);

    // 写入日志文件，所有信息都在一行
    if (entry->command) {
        fprintf(fp, "[%s] User: %s, Address: %s, Command: %s, Status: %d\n", 
                timestamp, 
                entry->user ? entry->user : "unknown", 
                entry->address ? entry->address : "unknown",
                entry->command,
                entry->status);
    } else {
        fprintf(fp, "[%s] User: %s, Address: %s\n", 
                timestamp, 
                entry->user ? entry->user : "unknown", 
                entry->address ? entry->address : "unknown");
    }

    if (entry->output) {
        fprintf(fp, "Output: %s\n", entry->output);
    }
    fprintf(fp, "---\n");
    fflush(fp);  // 确保立即写入文件

    fclose(fp);
    pthread_mutex_unlock(&log_mutex);
    lwsl_notice("Log entry written successfully with user: %s\n", entry->user ? entry->user : "unknown");
}

void audit_log_command(const char *user, const char *address, const char *command, int status) {
    lwsl_notice("Logging command: user='%s', address='%s', command='%s', status=%d\n", 
                user ? user : "unknown", address, command, status);
    
    if (!config.enabled || !config.log_commands) {
        lwsl_notice("Command logging is disabled, skipping\n");
        return;
    }

    if (!user || strlen(user) == 0) {
        lwsl_warn("Empty username detected, using 'unknown'\n");
    }

    audit_entry_t entry = {
        .timestamp = time(NULL),
        .user = strdup(user && strlen(user) > 0 ? user : "unknown"),
        .address = strdup(address),
        .command = strdup(command),
        .output = NULL,
        .status = status
    };

    lwsl_notice("Created audit entry with user: '%s'\n", entry.user);
    write_log_entry(&entry);

    free(entry.user);
    free(entry.address);
    free(entry.command);
    lwsl_notice("Command logged successfully\n");
}

void audit_log_output(const char *user, const char *address, const char *output) {
    lwsl_notice("Logging output: user=%s, address=%s\n", user, address);
    
    if (!config.enabled || !config.log_output) {
        lwsl_notice("Output logging is disabled, skipping\n");
        return;
    }

    audit_entry_t entry = {
        .timestamp = time(NULL),
        .user = strdup(user),
        .address = strdup(address),
        .command = NULL,
        .output = strdup(output),
        .status = 0
    };

    write_log_entry(&entry);

    free(entry.user);
    free(entry.address);
    free(entry.output);
    lwsl_notice("Output logged successfully\n");
}

void audit_cleanup(void) {
    lwsl_notice("Cleaning up audit system\n");
    if (!config.enabled) {
        lwsl_notice("Audit system is not enabled, nothing to clean up\n");
        return;
    }

    free(config.log_file);
    config.enabled = false;
    pthread_mutex_destroy(&log_mutex);
    lwsl_notice("Audit system cleaned up successfully\n");
} 