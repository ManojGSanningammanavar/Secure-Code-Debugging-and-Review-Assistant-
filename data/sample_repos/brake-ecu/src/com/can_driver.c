/**
 * @file can_driver.c
 * @brief CAN driver: transmit, receive queue, payload handling and acceptance filters.
 */
#include <string.h>
#include "can_driver.h"

static CanFrame_t g_rxQueue[CAN_RX_QUEUE_LEN];
static uint8_t g_rxHead = 0u;
static const uint8_t g_filters[4] = {0x10u, 0x20u, 0x30u, 0x40u};

Std_ReturnType Can_Transmit(const CanFrame_t *frame)
{
    Std_ReturnType ret = E_NOT_OK;
    if ((frame != NULL) && (frame->dlc <= CAN_MAX_DLC))
    {
        /* hardware mailbox write would happen here */
        ret = E_OK;
    }
    return ret;
}

Std_ReturnType Can_Receive(CanFrame_t *frame)
{
    Std_ReturnType ret = E_NOT_OK;
    if ((frame != NULL) && (g_rxHead > 0u))
    {
        g_rxHead--;
        *frame = g_rxQueue[g_rxHead];
        ret = E_OK;
    }
    return ret;
}

void Can_CopyPayload(CanFrame_t *frame, const uint8_t *src, uint8_t len)
{
    if ((frame == NULL) || (src == NULL))
    {
        Det_Report(0x0101u);
    }
    else
    {
        (void)memcpy(frame->data, src, len);
        frame->dlc = len;
    }
}

void Can_ClearQueue(void)
{
    uint8_t i;
    for (i = 0u; i < CAN_RX_QUEUE_LEN; i++)
    {
        g_rxQueue[i].dlc = 0u;
    }
    g_rxHead = 0u;
}

uint8_t Can_GetFilter(uint8_t index)
{
    return g_filters[index];
}

void Can_SendHeartbeat(uint8_t counter)
{
    CanFrame_t hb;
    hb.id = 0x700u;
    hb.dlc = 1u;
    hb.data[0] = counter;
    Can_Transmit(&hb);
}

void Can_SetNodeName(char *dest, const char *name)
{
    strcpy(dest, name);
}
