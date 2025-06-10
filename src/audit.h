#ifndef TTYD_AUDIT_H
#define TTYD_AUDIT_H

#include <time.h>
#include <stdbool.h>

// 审计日志结构体
typedef struct {
    char *log_file;        // 日志文件路径
    bool enabled;          // 是否启用审计
    bool log_commands;     // 是否记录命令
    bool log_output;       // 是否记录输出
} audit_config_t;

// 审计日志条目结构体
typedef struct {
    time_t timestamp;      // 时间戳
    char *user;           // 用户名
    char *address;        // 客户端地址
    char *command;        // 执行的命令
    char *output;         // 命令输出
    int status;           // 命令执行状态
} audit_entry_t;

// 初始化审计系统
int audit_init(const char *log_file, bool log_commands, bool log_output);

// 记录命令
void audit_log_command(const char *user, const char *address, const char *command, int status);

// 记录输出
void audit_log_output(const char *user, const char *address, const char *output);

// 关闭审计系统
void audit_cleanup(void);

#endif // TTYD_AUDIT_H 