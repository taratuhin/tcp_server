
/**
 *   \file     tcp_server.c
 *   \version  0.01
 *   \date     2024.04.30
 */

#include "lwip/tcp.h"
#include "tcp_cmd.h"

#include <string.h>


#define  SIZE_BUF 255

extern ip4_addr_t ipaddr;
extern ip4_addr_t netmask;
extern ip4_addr_t gw;


/* Состояния протокола */
enum tcp_server_states
{
  ES_NONE = 0,
  ES_ACCEPTED,
  ES_RECEIVED,
  ES_CLOSING
};


/* Структура для хранения информации о соединении, которая будет передаваться в качестве аргумента в обратные вызовы LwIP*/
struct tcp_server_struct
{
  u8_t state;           /* текущее состояние соединения */
  u8_t retries;
  struct tcp_pcb *pcb;  /* указатель на текущий tcp_pcb */
  struct pbuf *p;       /* указатель на полученный/подлежащий передаче pbuf */
};


static err_t tcp_server_accept(void *arg, struct tcp_pcb *newpcb, err_t err);
static err_t tcp_server_recv(void *arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err);
static void tcp_server_error(void *arg, err_t err);
static err_t tcp_server_poll(void *arg, struct tcp_pcb *tpcb);
static err_t tcp_server_sent(void *arg, struct tcp_pcb *tpcb, u16_t len);
static void tcp_server_send(struct tcp_pcb *tpcb, struct tcp_server_struct *es);
static void tcp_server_connection_close(struct tcp_pcb *tpcb, struct tcp_server_struct *es);
static void tcp_server_handle(struct tcp_pcb *tpcb, struct tcp_server_struct *es);
static void create_command(char *cmd, LEDS *leds);


/**
 *   \brief   Настройка сервера
 *   \param   Нет
 *   \return  Нет
 */
void tcp_server_init(void)
{
    struct tcp_pcb *tpcb;
    ip_addr_t ip_addr;
    err_t err;


    tpcb = tcp_new();
    IP_ADDR4(&ip_addr, 10, 0, 0, 123);
    err = tcp_bind(tpcb, &ip_addr, 49001);
    if (err == ERR_OK)
    {
        tpcb = tcp_listen(tpcb);

        tcp_accept(tpcb, tcp_server_accept);
    }
    else
    {
        memp_free(MEMP_TCP_PCB, tpcb);
    }
}


/**
 *   \brief   Функция обратного вызова tcp_accept LwIP.
 *   \param   arg - не используется
 *   \param   newpcb - указатель на структуру tcp_pcb для вновь созданного соединения TCP
 *   \param   err - не используется
 *   \return  Код ошибки
 */
static err_t tcp_server_accept(void *arg, struct tcp_pcb *newpcb, err_t err)
{
    err_t ret_err;
    struct tcp_server_struct *es;

    LWIP_UNUSED_ARG(arg);
    LWIP_UNUSED_ARG(err);


    tcp_setprio(newpcb, TCP_PRIO_MIN);

    es = (struct tcp_server_struct *) mem_malloc(sizeof(struct tcp_server_struct));
    if (es != NULL)
    {
        es->state = ES_ACCEPTED;
        es->pcb = newpcb;
        es->retries = 0;
        es->p = NULL;

        tcp_arg(newpcb, es);

        tcp_recv(newpcb, tcp_server_recv);

        tcp_err(newpcb, tcp_server_error);

        tcp_poll(newpcb, tcp_server_poll, 0);

        ret_err = ERR_OK;
    }
    else
    {
        tcp_server_connection_close(newpcb, es);

        ret_err = ERR_MEM;
    }

    return ret_err;
}


/**
 *   \brief   Функция обратного вызова tcp_recv LwIP.
 *   \param   arg - указатель на аргумент для соединения tcp_pcb
 *   \param   tpcb - указатель на соединение tcp_pcb
 *   \param   pbuf - указатель на полученный pbuf
 *   \param   err - информация об ошибке относительно полученного pbuf
 *   \return  Код ошибки
 */
static err_t tcp_server_recv(void *arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err)
{
    struct tcp_server_struct *es;
    err_t ret_err;


    LWIP_ASSERT("arg != NULL", arg != NULL);

    es = (struct tcp_server_struct *) arg;

    if (p == NULL)
    {
        es->state = ES_CLOSING;

        if (es->p == NULL)
        {
            tcp_server_connection_close(tpcb, es);
        }
        else
        {
            tcp_sent(tpcb, tcp_server_sent);

            tcp_server_send(tpcb, es);
        }

        ret_err = ERR_OK;
    }
    else if (err != ERR_OK)
    {
        if (p != NULL)
        {
            es->p = NULL;

            pbuf_free(p);
        }

        ret_err = err;
    }
    else if (es->state == ES_ACCEPTED)
    {
        es->state = ES_RECEIVED;

        es->p = p;

        tcp_sent(tpcb, tcp_server_sent);

        tcp_server_handle(tpcb, es);

        ret_err = ERR_OK;
    }
    else if (es->state == ES_RECEIVED)
    {
        if (es->p == NULL)
        {
            es->p = p;

            tcp_server_handle(tpcb, es);
        }
        else
        {
            struct pbuf *ptr;

            ptr = es->p;

            pbuf_chain(ptr,p);
        }

        ret_err = ERR_OK;
    }
    else if (es->state == ES_CLOSING)
    {
        tcp_recved(tpcb, p->tot_len);
        es->p = NULL;
        pbuf_free(p);
        ret_err = ERR_OK;
    }
    else
    {
        tcp_recved(tpcb, p->tot_len);
        es->p = NULL;
        pbuf_free(p);
        ret_err = ERR_OK;
    }

    return ret_err;
}


/**
 *   \brief   Функция обратного вызова tcp_err (вызывается при возникновении ошибки tcp_connection)
 *   \param   arg - указатель на параметр аргумента
 *   \param   err - не используется
 *   \return  Нет
 */
static void tcp_server_error(void *arg, err_t err)
{
    struct tcp_server_struct *es;


    LWIP_UNUSED_ARG(err);

    es = (struct tcp_server_struct *) arg;

    if (es != NULL)
    {
        mem_free(es);
    }
}


/**
 *   \brief   Функция обратного вызова LwIP tcp_poll.
 *   \param   arg - указатель на аргумент, переданный в обратный вызов
 *   \param   tpcb - указатель на tcp_pcb для текущего соединения TCP
 *   \return  Код ошибки
 */
static err_t tcp_server_poll(void *arg, struct tcp_pcb *tpcb)
{
	struct tcp_server_struct *es;
    err_t ret_err;


    es = (struct tcp_server_struct *) arg;
    if (es != NULL)
    {
        if (es->p != NULL)
        {
            tcp_sent(tpcb, tcp_server_sent);

            tcp_server_send(tpcb, es);
        }
        else
        {
            if (es->state == ES_CLOSING)
            {
                tcp_server_connection_close(tpcb, es);
            }
        }

        ret_err = ERR_OK;
    }
    else
    {
        tcp_abort(tpcb);
        ret_err = ERR_ABRT;
    }

    return ret_err;
}


/**
 *   \brief  Функция обратного вызова tcp_sent LwIP (вызывается, когда от удаленного хоста получено подтверждение
 *           для отправленных данных).
 *   \param  arg -
 *   \param  tpcb - указатель на соединение tcp_pcb
 *   \param  len -
 *   \retval Код ошибки
 */
static err_t tcp_server_sent(void *arg, struct tcp_pcb *tpcb, u16_t len)
{
    struct tcp_server_struct *es;

    LWIP_UNUSED_ARG(len);

    es = (struct tcp_server_struct *) arg;
    es->retries = 0;

    if (es->p != NULL)
    {
        tcp_sent(tpcb, tcp_server_sent);
        tcp_server_send(tpcb, es);
    }
    else
    {
        if (es->state == ES_CLOSING)
        {
            tcp_server_connection_close(tpcb, es);
        }
    }

    return  ERR_OK;
}


/**
 *   \brief   Отправка данных по TCP-соединению
 *   \param   tpcb - указатель на соединение tcp_pcb
 *   \param   es - указатель на структуру tcp_server_struct
 *   \retval  Код ошибки
 */
static void tcp_server_send(struct tcp_pcb *tpcb, struct tcp_server_struct *es)
{
    struct pbuf *ptr;
    err_t wr_err = ERR_OK;


    while ((wr_err == ERR_OK) && (es->p != NULL) && (es->p->len <= tcp_sndbuf(tpcb)))
    {
        ptr = es->p;

        wr_err = tcp_write(tpcb, ptr->payload, ptr->len, 1);

        if (wr_err == ERR_OK)
        {
            u16_t plen;
            u8_t freed;

            plen = ptr->len;

            es->p = ptr->next;

            if (es->p != NULL)
            {
                pbuf_ref(es->p);
            }

            do
            {
                freed = pbuf_free(ptr);
            }
            while (freed == 0);

            tcp_recved(tpcb, plen);
        }
        else if (wr_err == ERR_MEM)
        {
            es->p = ptr;
        }
        else
        {
            /* Другие ошибки */
        }
    }
}


/**
 *   \brief   Закрывает TCP-соединение
 *   \param   tpcb - указатель на TCP-соединение
 *   \param   es - указатель на структуру tcp_server_struct
 *   \retval  Нет
 */
static void tcp_server_connection_close(struct tcp_pcb *tpcb, struct tcp_server_struct *es)
{
    tcp_arg(tpcb, NULL);
    tcp_sent(tpcb, NULL);
    tcp_recv(tpcb, NULL);
    tcp_err(tpcb, NULL);
    tcp_poll(tpcb, NULL, 0);

    if (es != NULL)
    {
        mem_free(es);
    }

    tcp_close(tpcb);
}


/**
 *   \brief   Обработка входящих данных по TCP
 *   \param   tpcb - указатель на TCP-соединение
 *   \param   es - указатель на структуру tcp_server_struct
 *   \retval  Нет
 */
static void tcp_server_handle(struct tcp_pcb *tpcb, struct tcp_server_struct *es)
{
	LEDS leds = {0, 0, 0};
    struct tcp_server_struct *es_tx = NULL;
    char *check = NULL;
    //char *ip = ipaddr_ntoa(&(tpcb->local_ip));


    es_tx->state = es->state;
    es_tx->pcb = es->pcb;
    es_tx->p = es->p;

    char buf[SIZE_BUF];
    memset(buf, '\0', SIZE_BUF);

    strncpy(buf, (char *) es->p->payload, es->p->tot_len);
    check = strtok(buf, " ");
    if (!strncmp(check, "ifconfig", 8))
    {
    	memset(buf, '\0', SIZE_BUF);
    	strcpy(buf, "IP: ");
    	char *ip = ipaddr_ntoa(&ipaddr);
    	strcat(buf, ip);
    	strcat(buf, "\n");
    	strcat(buf, "Mask: ");
    	char *mask = ipaddr_ntoa(&netmask);
    	strcat(buf, mask);
    	strcat(buf, "\n");
    	strcat(buf, "Gateway: ");
    	char *gateway = ipaddr_ntoa(&gw);
    	strcat(buf, gateway);
    }

    if (!strncmp(check, "./start_leds", 12))
    {
    	create_command(check, &leds);
    	leds_on( &leds );
    }

    if (!strncmp(check, "./stop_leds", 11))
    {
    	create_command(check, &leds);
    	leds_off( &leds );
    }

    es_tx->p->payload = (void *) buf;
    es_tx->p->tot_len += strlen(buf);
    es_tx->p->len = strlen(buf);

    tcp_server_send(tpcb, es_tx);

    pbuf_free(es->p);
}


/**
 *   \brief   Создание команды серверу
 *   \param  *cmd - команда
 *   \param  *leds - данные для сервера
 *   \return  Нет
 */
static void create_command(char *cmd, LEDS *leds)
{
    while (cmd != NULL)
    {
        if (!strcmp(cmd, "LED1"))
        {
            leds->led1 = 1;
        }

        if (!strcmp(cmd, "LED2"))
        {
            leds->led2 = 1;
        }

        if (!strcmp(cmd, "LED3"))
        {
            leds->led3 = 1;
        }

        cmd = strtok(NULL, " \n");
    }
}
