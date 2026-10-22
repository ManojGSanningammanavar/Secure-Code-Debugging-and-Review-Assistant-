/**
 * @file sensor_filter.c
 * @brief Fixed-point low-pass filter and plausibility checks for analog sensors.
 *
 * Reference implementation that follows the ECU coding standard.
 */
#include "platform_types.h"

#define FILTER_SHIFT      4u
#define SENSOR_MAX_RAW    4095u

typedef struct
{
    uint32_t state;
    uint16_t lastOutput;
} LowPass_t;

Std_ReturnType Filter_Init(LowPass_t *filter, uint16_t initial)
{
    Std_ReturnType ret = E_NOT_OK;
    if (filter != NULL)
    {
        filter->state = ((uint32_t)initial) << FILTER_SHIFT;
        filter->lastOutput = initial;
        ret = E_OK;
    }
    return ret;
}

uint16_t Filter_Update(LowPass_t *filter, uint16_t sample)
{
    uint16_t out = 0u;
    if (filter != NULL)
    {
        uint32_t input = (uint32_t)sample << FILTER_SHIFT;
        filter->state = filter->state - (filter->state >> FILTER_SHIFT) + (input >> FILTER_SHIFT);
        out = (uint16_t)(filter->state >> FILTER_SHIFT);
        filter->lastOutput = out;
    }
    return out;
}

uint8_t Filter_IsPlausible(uint16_t raw, uint16_t previous, uint16_t maxStep)
{
    uint8_t plausible = FALSE;
    uint16_t delta = 0u;
    if (raw <= SENSOR_MAX_RAW)
    {
        delta = (raw > previous) ? (uint16_t)(raw - previous) : (uint16_t)(previous - raw);
        if (delta <= maxStep)
        {
            plausible = TRUE;
        }
    }
    return plausible;
}

uint16_t Filter_Average(const uint16_t *samples, uint8_t count)
{
    uint32_t sum = 0u;
    uint16_t avg = 0u;
    uint8_t i;
    if ((samples != NULL) && (count > 0u))
    {
        for (i = 0u; i < count; i++)
        {
            sum += samples[i];
        }
        avg = (uint16_t)(sum / count);
    }
    return avg;
}
