#ifndef TTYD_AUDIT_H
#define TTYD_AUDIT_H

#include <time.h>
#include <stdbool.h>

// 自定义字段结构
typedef struct {
    char *key;
    char *value;
} audit_custom_field_t;

// 审计配置结构
typedef struct {
    bool enabled;
    char *log_file;
    audit_custom_field_t *custom_fields;  // 自定义字段数组
    int custom_fields_count;              // 自定义字段数量
} audit_config_t;

// 审计日志条目结构
typedef struct {
    time_t timestamp;
    char *address;
    char *command;
    char *output;
    int status;
    audit_custom_field_t *custom_fields;  // 自定义字段数组
    int custom_fields_count;              // 自定义字段数量
} audit_entry_t;

// 初始化审计系统
int audit_init(const char *log_file);

// 记录命令
void audit_log_command(const char *address, const char *command, int status);

// 关闭审计系统
void audit_cleanup(void);

// 新增函数声明
int audit_add_custom_field(const char *key, const char *value);
void audit_clear_custom_fields(void);

// 验证审计字段格式
int validate_audit_field(const char *field);

#endif // TTYD_AUDIT_H 