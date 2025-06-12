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

int audit_init(const char *log_file) {
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

// 添加自定义字段
int audit_add_custom_field(const char *key, const char *value) {
    if (!key || !value) {
        lwsl_err("Invalid custom field key or value\n");
        return -1;
    }

    pthread_mutex_lock(&log_mutex);
    
    // 重新分配内存
    audit_custom_field_t *new_fields = xrealloc(config.custom_fields, 
        (config.custom_fields_count + 1) * sizeof(audit_custom_field_t));
    
    if (!new_fields) {
        lwsl_err("Failed to allocate memory for custom field\n");
        pthread_mutex_unlock(&log_mutex);
        return -1;
    }
    
    config.custom_fields = new_fields;
    
    // 添加新字段
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

// 清除所有自定义字段
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

// 修改 write_log_entry 函数
static void write_log_entry(const audit_entry_t *entry) {
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

    // 写入时间戳和地址
    fprintf(fp, "[%s] Address: %s", 
            timestamp, 
            entry->address ? entry->address : "unknown");
            
    // 写入自定义字段
    for (int i = 0; i < entry->custom_fields_count; i++) {
        fprintf(fp, ", %s: %s", 
                entry->custom_fields[i].key,
                entry->custom_fields[i].value);
    }

    if (entry->command) {
        fprintf(fp, ", Command: %s, Status: %d\n", 
                entry->command,
                entry->status);
    } else {
        fprintf(fp, "\n");
    }

    if (entry->output) {
        fprintf(fp, "Output: %s\n", entry->output);
    }
    fprintf(fp, "---\n");
    fflush(fp);

    fclose(fp);
    pthread_mutex_unlock(&log_mutex);
    lwsl_notice("Log entry written successfully\n");
}

// 清理命令字符串，移除控制字符
static char *clean_command_string(const char *cmd) {
    if (!cmd) return NULL;
    
    size_t len = strlen(cmd);
    char *clean = xmalloc(len + 1);
    size_t j = 0;
    
    for (size_t i = 0; i < len; i++) {
        // 跳过控制字符（ASCII 0-31，除了换行符和回车符）
        if (cmd[i] >= 32 || cmd[i] == '\n' || cmd[i] == '\r') {
            clean[j++] = cmd[i];
        }
    }
    clean[j] = '\0';
    
    // 移除末尾的空白字符
    while (j > 0 && (clean[j-1] == ' ' || clean[j-1] == '\t')) {
        clean[--j] = '\0';
    }
    
    return clean;
}

// 修改 audit_log_command 函数
void audit_log_command(const char *address, const char *command, int status) {
    if (!config.enabled) {
        lwsl_notice("Audit system is not enabled, skipping log entry\n");
        return;
    }
    
    char *clean_cmd = clean_command_string(command);
    lwsl_notice("Logging command: address='%s', command='%s', status=%d\n", 
               address, clean_cmd, status);
               
    audit_entry_t entry = {
        .timestamp = time(NULL),
        .address = strdup(address),
        .command = clean_cmd,
        .output = NULL,
        .status = status,
        .custom_fields = NULL,
        .custom_fields_count = 0
    };

    // 复制自定义字段
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

    // 清理内存
    free(entry.address);
    free(entry.command);
    for (int i = 0; i < entry.custom_fields_count; i++) {
        free(entry.custom_fields[i].key);
        free(entry.custom_fields[i].value);
    }
    free(entry.custom_fields);
    
    lwsl_notice("Command logged successfully\n");
}

// 验证审计字段格式
int validate_audit_field(const char *field) {
    if (!field) {
        lwsl_err("Invalid audit field: NULL\n");
        return -1;
    }

    // 检查是否包含等号
    char *value = strchr(field, '=');
    if (!value) {
        lwsl_err("Invalid audit field format: %s (should be key=value)\n", field);
        return -1;
    }

    // 验证键名不为空
    if (value == field) {
        lwsl_err("Empty key in audit field: %s\n", field);
        return -1;
    }

    // 验证值不为空
    if (*(value + 1) == '\0') {
        lwsl_err("Empty value in audit field: %s\n", field);
        return -1;
    }

    return 0;
}

// 修改 audit_cleanup 函数以清理自定义字段
void audit_cleanup(void) {
    lwsl_notice("Cleaning up audit system\n");
    if (!config.enabled) {
        lwsl_notice("Audit system is not enabled, nothing to clean up\n");
        return;
    }

    free(config.log_file);
    audit_clear_custom_fields();  // 清理自定义字段
    config.enabled = false;
    pthread_mutex_destroy(&log_mutex);
    lwsl_notice("Audit system cleaned up successfully\n");
} 