#ifndef __HANDLER_H
#define __HANDLER_H

#include <ntddk.h>

BOOLEAN handler(PEXCEPTION_RECORD ExceptionRecord, PCONTEXT Context);


#endif //__HANDLER_H