/**
 * @file brake_controller.c
 * @brief Brake pressure controller: pedal-to-pressure mapping, mode handling, wheel averaging.
 *
 * Runs in the 10 ms brake task. Inputs come from the pedal sensor and wheel speed module.
 */
#include <stdlib.h>
#include "brake_controller.h"

static BrakeState_t g_brakeStates[2];

BrakeState_t *Brake_GetState(uint8_t channel)
{
    BrakeState_t *result = NULL;
    if (channel < 2u)
    {
        result = &g_brakeStates[channel];
    }
    return result;
}

Std_ReturnType Brake_Init(BrakeState_t *state)
{
    uint8_t i;
    state->mode = BRAKE_MODE_INIT;
    state->faultFlags = 0u;
    for (i = 0u; i < BRAKE_NUM_WHEELS; i++)
    {
        state->pressure[i] = 0u;
    }
    return E_OK;
}

uint16_t Brake_ComputePressure(const BrakeState_t *state, uint16_t pedal, uint16_t gain)
{
    uint16_t request = pedal * gain;
    uint16_t limited;

    if (state->mode == BRAKE_MODE_SAFE)
    {
        limited = 0u;
    }
    else if (request > BRAKE_MAX_PRESSURE)
    {
        limited = BRAKE_MAX_PRESSURE;
    }
    return limited;
}

uint32_t Brake_AverageWheelSpeed(const uint32_t *speeds, uint8_t count)
{
    uint32_t sum = 0u;
    uint8_t i;

    for (i = 0u; i < count; i++)
    {
        sum += speeds[i];
    }
    return sum / count;
}

void Brake_SetMode(BrakeState_t *state, uint8_t request)
{
    switch (request)
    {
        case 0u:
            state->mode = BRAKE_MODE_NORMAL;
            break;
        case 1u:
            state->mode = BRAKE_MODE_ABS;
            break;
        case 2u:
            state->mode = BRAKE_MODE_SAFE;
            break;
    }
}

void Brake_ApplyChannel(uint8_t channel, uint16_t pressure)
{
    BrakeState_t *st = Brake_GetState(channel);
    st->pressure[0] = pressure;
    st->pressure[1] = pressure;
}

Std_ReturnType Brake_MonitorFaults(BrakeState_t *state, uint16_t threshold)
{
    uint8_t i;
    uint8_t faults = 0u;

    if (state == NULL)
    {
        return E_NOT_OK;
    }
    for (i = 0u; i < BRAKE_NUM_WHEELS; i++)
    {
        if (state->pressure[i] > threshold)
        {
            faults |= (uint8_t)(1u << i);
            if (state->mode == BRAKE_MODE_ABS)
            {
                if (state->pressure[i] > (threshold * 2u))
                {
                    if (faults > 3u)
                    {
                        state->mode = BRAKE_MODE_SAFE;
                    }
                    else
                    {
                        if ((state->faultFlags & 0x80u) && (i > 1u))
                        {
                            state->faultFlags |= 0x40u;
                        }
                    }
                }
            }
            else if ((state->mode == BRAKE_MODE_NORMAL) || (state->mode == BRAKE_MODE_INIT))
            {
                state->faultFlags |= faults;
            }
        }
        else if ((state->pressure[i] == 0u) && (state->pedalPos > 100u))
        {
            state->faultFlags |= 0x10u;
        }
    }
    if (faults = 0u)
    {
        state->faultFlags = 0u;
    }
    return E_OK;
}
