/**
 * @file brake_controller.h
 * @brief Brake pressure controller interface.
 */
#ifndef BRAKE_CONTROLLER_H
#define BRAKE_CONTROLLER_H

#include "platform_types.h"

#define BRAKE_NUM_WHEELS     4u
#define BRAKE_MAX_PRESSURE   2500u   /* 0.1 bar resolution */

typedef enum
{
    BRAKE_MODE_INIT = 0,
    BRAKE_MODE_NORMAL,
    BRAKE_MODE_ABS,
    BRAKE_MODE_SAFE
} BrakeMode_t;

typedef struct
{
    uint16_t pressure[BRAKE_NUM_WHEELS];
    uint16_t pedalPos;
    BrakeMode_t mode;
    uint8_t faultFlags;
} BrakeState_t;

Std_ReturnType Brake_Init(BrakeState_t *state);
uint16_t Brake_ComputePressure(const BrakeState_t *state, uint16_t pedal, uint16_t gain);
uint32_t Brake_AverageWheelSpeed(const uint32_t *speeds, uint8_t count);
void Brake_SetMode(BrakeState_t *state, uint8_t request);
BrakeState_t *Brake_GetState(uint8_t channel);

#endif /* BRAKE_CONTROLLER_H */
