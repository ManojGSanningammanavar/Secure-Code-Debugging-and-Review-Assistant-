/**
 * @file can_driver.h
 * @brief Minimal CAN driver interface used by the brake ECU.
 */
#ifndef CAN_DRIVER_H
#define CAN_DRIVER_H

#include "platform_types.h"

#define CAN_MAX_DLC        8u
#define CAN_RX_QUEUE_LEN   16u

typedef struct
{
    uint32_t id;
    uint8_t dlc;
    uint8_t data[CAN_MAX_DLC];
} CanFrame_t;

Std_ReturnType Can_Transmit(const CanFrame_t *frame);
Std_ReturnType Can_Receive(CanFrame_t *frame);
void Can_CopyPayload(CanFrame_t *frame, const uint8_t *src, uint8_t len);
void Can_ClearQueue(void);
uint8_t Can_GetFilter(uint8_t index);

#endif /* CAN_DRIVER_H */
