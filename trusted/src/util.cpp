#include "util.h"
#include "common.h"
#include "enclave_t.h"
#include <stdarg.h>
#include <stdio.h>


void main_logger(int level, const char *file, int line, const char *format,
                 ...) {
  char buf[BUFSIZ] = {'\0'};
  char *buf_ptr = buf;
  va_list ap;
  size_t size = 0;
  switch (level) {
  case LOG_TYPE_TRACE:
    size = snprintf(buf_ptr, 4096,
                    ANSI_COLOR_CYAN "-------------------------" ANSI_COLOR_RESET
                                    "\n");
    buf_ptr = buf_ptr + size;
    size = snprintf(buf_ptr, 4096,
                    ANSI_COLOR_CYAN "[TRACE] -- %s:%d" ANSI_COLOR_RESET "\n",
                    file, line);
    buf_ptr = buf_ptr + size;
    
    va_start(ap, format);
    size = vsnprintf(buf_ptr, 4096, format, ap);
    buf_ptr = buf_ptr + size;
    va_end(ap);
    size = snprintf(buf_ptr, 4096,
                    ANSI_COLOR_CYAN "-------------------------" ANSI_COLOR_RESET
                                    "\n");
    ocall_print_log(buf);
    break;
  case LOG_TYPE_DEBUG:
    size = snprintf(buf_ptr, 4096,
                    ANSI_COLOR_MAGENTA
                    "-------------------------" ANSI_COLOR_RESET "\n");
    buf_ptr = buf_ptr + size;
    size = snprintf(buf_ptr, 4096,
                    ANSI_COLOR_MAGENTA "[DEBUG] -- %s:%d" ANSI_COLOR_RESET "\n",
                    file, line);
    buf_ptr = buf_ptr + size;
    va_start(ap, format);
    size = vsnprintf(buf_ptr, 4096, format, ap);
    buf_ptr = buf_ptr + size;
    va_end(ap);
    size = snprintf(buf_ptr, 4096,
                    ANSI_COLOR_MAGENTA
                    "-------------------------" ANSI_COLOR_RESET "\n");
    ocall_print_log(buf);
    break;

  case LOG_TYPE_INFO:
    size = snprintf(buf_ptr, 4096,
                    ANSI_COLOR_BLUE
                    "-------------------------" ANSI_COLOR_RESET "\n");
    buf_ptr = buf_ptr + size;
    size = snprintf(buf_ptr, 4096,
                    ANSI_COLOR_BLUE "[INFO] -- %s:%d" ANSI_COLOR_RESET "\n",
                    file, line);
    buf_ptr = buf_ptr + size;
    va_start(ap, format);
    size = vsnprintf(buf_ptr, 4096, format, ap);
    buf_ptr = buf_ptr + size;
    va_end(ap);
    size = snprintf(buf_ptr, 4096,
                    ANSI_COLOR_BLUE
                    "-------------------------" ANSI_COLOR_RESET "\n");
    ocall_print_log(buf);
    break;

    case LOG_TYPE_WARN:
    size = snprintf(buf_ptr, 4096,
                    ANSI_COLOR_YELLOW
                    "-------------------------" ANSI_COLOR_RESET "\n");
    buf_ptr = buf_ptr + size;
    size = snprintf(buf_ptr, 4096,
                    ANSI_COLOR_YELLOW "[WARNING] -- %s:%d" ANSI_COLOR_RESET "\n",
                    file, line);
    buf_ptr = buf_ptr + size;
    va_start(ap, format);
    size = vsnprintf(buf_ptr, 4096, format, ap);
    buf_ptr = buf_ptr + size;
    va_end(ap);
    size = snprintf(buf_ptr, 4096,
                    ANSI_COLOR_YELLOW
                    "-------------------------" ANSI_COLOR_RESET "\n");
    ocall_print_log(buf);
    break;
    case LOG_TYPE_ERROR:
    size = snprintf(buf_ptr, 4096,
                    ANSI_COLOR_RED
                    "-------------------------" ANSI_COLOR_RESET "\n");
    buf_ptr = buf_ptr + size;
    size = snprintf(buf_ptr, 4096,
                    ANSI_COLOR_RED "[ERROR] -- %s:%d" ANSI_COLOR_RESET "\n",
                    file, line);
    buf_ptr = buf_ptr + size;
    va_start(ap, format);
    size = vsnprintf(buf_ptr, 4096, format, ap);
    buf_ptr = buf_ptr + size;
    va_end(ap);
    size = snprintf(buf_ptr, 4096,
                    ANSI_COLOR_RED
                    "-------------------------" ANSI_COLOR_RESET "\n");
    ocall_print_log(buf);
    break;
    case LOG_TYPE_OUT:
    size = snprintf(buf_ptr, 4096,
                    ANSI_COLOR_GREEN
                    "-------------------------" ANSI_COLOR_RESET "\n");
    buf_ptr = buf_ptr + size;
    size = snprintf(buf_ptr, 4096,
                    ANSI_COLOR_GREEN "[OUT] -- %s:%d" ANSI_COLOR_RESET "\n",
                    file, line);
    buf_ptr = buf_ptr + size;
    va_start(ap, format);
    size = vsnprintf(buf_ptr, 4096, format, ap);
    buf_ptr = buf_ptr + size;
    va_end(ap);
    size = snprintf(buf_ptr, 4096,
                    ANSI_COLOR_GREEN
                    "-------------------------" ANSI_COLOR_RESET "\n");
    ocall_print_log(buf);
    break;
  default:
    break;
  }
}