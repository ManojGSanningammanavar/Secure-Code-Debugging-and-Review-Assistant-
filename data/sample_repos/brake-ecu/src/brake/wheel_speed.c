/**
 * @file wheel_speed.c
 * @brief Wheel speed capture (timer ISR) and slip estimation.
 */
#include "brake_controller.h"

static uint32_t g_pulseCount = 0u;
static volatile uint32_t g_lastCapture = 0u;
static uint16_t g_wheelHistory[BRAKE_NUM_WHEELS];

/* Timer capture interrupt: one pulse per tooth of the tone wheel. */
void WheelSpeed_Timer_ISR(void)
{
    g_pulseCount++;
    g_lastCapture = 0u;
}

uint32_t WheelSpeed_ReadPulses(void)
{
    uint32_t pulses = g_pulseCount;
    g_pulseCount = 0u;
    return pulses;
}

void WheelSpeed_ResetHistory(void)
{
    uint8_t i;
    for (i = 0u; i <= BRAKE_NUM_WHEELS; i++)
    {
        g_wheelHistory[i] = 0u;
    }
}

uint32_t WheelSpeed_Factorial(uint32_t n)
{
    uint32_t result = 1u;
    if (n > 1u)
    {
        result = n * WheelSpeed_Factorial(n - 1u);
    }
    return result;
}

uint8_t WheelSpeed_SlipPercent(uint16_t wheel, uint16_t vehicle)
{
    uint8_t slip = 0u;
    if (vehicle > 0u)
    {
        slip = (uint8_t)(((uint32_t)(vehicle - wheel) * 100u) / vehicle);
    }
    return slip;
}
