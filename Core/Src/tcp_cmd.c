
/**
 *   \file     tcp_cmd.c
 *   \version  0.01
 *   \date     2024.04.30
 */

#include "gpio.h"
#include "tcp_cmd.h"


/**
 *   \brief   Включение светодиодов
 *   \param  *leds - структура с признаками какой светодиод включать
 *   \retval  Нет
 */
void leds_on(LEDS *leds)
{
    if (leds->led1)
    {
        HAL_GPIO_WritePin(GPIOB, RED_LED_Pin, GPIO_PIN_SET);
    }

    if (leds->led2)
    {
        HAL_GPIO_WritePin(GPIOB, GREEN_LED_Pin, GPIO_PIN_SET);
    }

    if (leds->led3)
    {
        HAL_GPIO_WritePin(GPIOB, BLUE_LED_Pin, GPIO_PIN_SET);
    }
}


/**
 *   \brief   Выключение светодиодов
 *   \param  *leds - структура с признаками какой светодиод выключать
 *   \retval  Нет
 */
void leds_off(LEDS *leds)
{
    if (leds->led1)
    {
        HAL_GPIO_WritePin(GPIOB, RED_LED_Pin, GPIO_PIN_RESET);
    }

    if (leds->led2)
    {
        HAL_GPIO_WritePin(GPIOB, GREEN_LED_Pin, GPIO_PIN_RESET);
    }

    if (leds->led3)
    {
        HAL_GPIO_WritePin(GPIOB, BLUE_LED_Pin, GPIO_PIN_RESET);
    }
}
