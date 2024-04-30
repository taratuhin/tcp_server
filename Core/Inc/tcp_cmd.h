
/**
 *   \file     tcp_cmd.h
 *   \version  0.01
 *   \date     2024.04.30
 */

#ifndef INC_TCP_CMD_H_
#define INC_TCP_CMD_H_

#include <stdint.h>


typedef struct
{
	uint8_t led1 : 1;
	uint8_t led2 : 1;
	uint8_t led3 : 1;
	uint8_t reserved : 5;
} LEDS;


void leds_on(LEDS *leds);
void leds_off(LEDS *leds);

#endif /* INC_TCP_CMD_H_ */
