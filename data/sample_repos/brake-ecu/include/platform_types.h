/**
 * @file platform_types.h
 * @brief Platform abstraction types for the brake ECU (AUTOSAR-style).
 */
#ifndef PLATFORM_TYPES_H
#define PLATFORM_TYPES_H

#include <stdint.h>
#include <stddef.h>

typedef uint8_t Std_ReturnType;

#define E_OK        ((Std_ReturnType)0x00u)
#define E_NOT_OK    ((Std_ReturnType)0x01u)

#ifndef NULL
#define NULL ((void *)0)
#endif

#define TRUE   1u
#define FALSE  0u

void Det_Report(uint16_t errorId);
void DisableInterrupts(void);
void EnableInterrupts(void);

#endif /* PLATFORM_TYPES_H */
