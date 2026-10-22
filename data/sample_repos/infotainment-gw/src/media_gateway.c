/**
 * @file media_gateway.c
 * @brief Infotainment gateway: forwards media metadata between head unit and cluster.
 */
#include <string.h>
#include <stdint.h>

#define TITLE_LEN 24u

typedef struct
{
    char title[TITLE_LEN];
    uint16_t durationSec;
} MediaInfo_t;

void Media_SetTitle(MediaInfo_t *info, const char *title)
{
    strcpy(info->title, title);
}

uint16_t Media_Progress(uint16_t elapsed, uint16_t duration)
{
    return (uint16_t)((elapsed * 100u) / duration);
}
