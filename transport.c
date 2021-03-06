/*
 * transport.c 
 *
 * CS244a HW#3 (Reliable Transport)
 *
 * This file implements the STCP layer that sits between the
 * mysocket and network layers. You are required to fill in the STCP
 * functionality in this file. 
 *
 */


#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <time.h>
#include <arpa/inet.h>
#include "mysock.h"
#include "stcp_api.h"
#include "transport.h"

#define MAX_PAYLOAD_SIZE 516
#define MIN_CWND_SIZE 3027
enum {CSTATE_CLOSED,CSTATE_ESTABLISHED,CSTATE_LISTEN,CSTATE_SYN_SENT,CSTATE_SYN_RCVD,CSTATE_FIN_WAIT_1,CSTATE_FIN_WAIT_2,CSTATE_CLOSE_WAIT,CSTATE_LAST_ACK,CSTATE_CLOSING };    /* obviously you should have more states */


/* this structure is global to a mysocket descriptor */
typedef struct
{
    bool_t done;    /* TRUE once connection is closed */

    int connection_state;   /* state of the connection (established, etc.) */
    tcp_seq initial_sequence_num;
  tcp_seq initial_sequence_num2;
  
    /* any other connection-wide global variables go here */
} context_t;
typedef struct
{
  STCPHeader stcpheader;
  char data[MAX_PAYLOAD_SIZE];
}SEGMENT;

static void generate_initial_seq_num(context_t *ctx);
static void control_loop(mysocket_t sd, context_t *ctx);


/* initialise the transport layer, and start the main loop, handling
 * any data from the peer or the application.  this function should not
 * return until the connection is closed.
 */
void transport_init(mysocket_t sd, bool_t is_active)
{
    context_t *ctx;
    SEGMENT *recvSegment,*sendSegment;
    unsigned int event;
    ctx = (context_t *) calloc(1, sizeof(context_t));
    recvSegment = (SEGMENT *) calloc(1, sizeof(SEGMENT));
    sendSegment = (SEGMENT *) calloc(1, sizeof(SEGMENT));
    if(!(ctx))
      {
	fprintf(stderr,"Memory allocation failed\n");
      }
    assert(ctx);
    generate_initial_seq_num(ctx);
    fprintf(stdout,"initial seq num : %d\n",ctx->initial_sequence_num);
    /* XXX: you should send a SYN packet here if is_active, or wait for one
     * to arrive if !is_active.  after the handshake completes, unblock the
     * application with stcp_unblock_application(sd).  you may also use
     * this to communicate an error condition back to the application, e.g.
     * if connection fails; to do so, just set errno appropriately (e.g. to
     * ECONNREFUSED, etc.) before calling the function.*/
    if(is_active) /*if active open*/
      {
	/*set the SYN segment header*/
        sendSegment->stcpheader.th_seq=htonl(ctx->initial_sequence_num);
        sendSegment->stcpheader.th_flags=TH_SYN;
	sendSegment->stcpheader.th_win=htons(MIN_CWND_SIZE);
	sendSegment->stcpheader.th_off=5;
	/*send SYN packet*/
	stcp_network_send(sd,sendSegment,sizeof(SEGMENT),NULL);
	ctx->connection_state=CSTATE_SYN_SENT;  /* SYN_SENT STATE*/
	stcp_network_recv(sd,recvSegment,sizeof(SEGMENT));
	if(recvSegment->stcpheader.th_flags==(TH_ACK | TH_SYN)) /*if received packet is SYN+ACK*/
	  {
	    /*If sequence number unmatched print error*/
	    if(ntohl(recvSegment->stcpheader.th_ack)!=(ctx->initial_sequence_num+1))
	      {
		fprintf(stderr,"Active open failed, wrong ack\n");
		exit(2);
	      }
	    /*If sequence number matched received ACK. send ACK*/
	    else
	      {
		ctx->initial_sequence_num++;
		ctx->initial_sequence_num2=ntohl(recvSegment->stcpheader.th_seq)+1;
		bzero(sendSegment,sizeof(SEGMENT));
		sendSegment->stcpheader.th_seq=htonl(ctx->initial_sequence_num);
		sendSegment->stcpheader.th_flags=TH_ACK;
		sendSegment->stcpheader.th_win=htons(MIN_CWND_SIZE);
		sendSegment->stcpheader.th_off=5;
		sendSegment->stcpheader.th_ack=htonl(ctx->initial_sequence_num2);
		stcp_network_send(sd,sendSegment,sizeof(SEGMENT),NULL);
	      }
	  }
	/* if received packet is SYN. Simulteneous initialize. Not finished yet*/
	else if(recvSegment->stcpheader.th_flags==TH_SYN)  
	  {
	    /*send SYN+ACK*/
	    bzero(sendSegment,sizeof(SEGMENT));
	    sendSegment->stcpheader.th_seq=htonl(ctx->initial_sequence_num);
	    sendSegment->stcpheader.th_flags=(TH_ACK | TH_SYN);
	    sendSegment->stcpheader.th_win=htons(MIN_CWND_SIZE);
	    sendSegment->stcpheader.th_off=5;
	    sendSegment->stcpheader.th_ack=htonl(ntohl(recvSegment->stcpheader.th_seq)+1);
	    stcp_network_send(sd,sendSegment,sizeof(SEGMENT),NULL);
	    ctx->connection_state=CSTATE_SYN_RCVD;
	    /*wait for event*/
	    event=stcp_wait_for_event(sd,ANY_EVENT,NULL);
	    if(event & NETWORK_DATA)
	      {
		bzero(recvSegment,sizeof(SEGMENT));
		stcp_network_recv(sd,recvSegment,sizeof(SEGMENT));
		if(recvSegment->stcpheader.th_flags==(TH_ACK | TH_SYN)) /*if received packet is ACK+SYN*/
		  {
		    if(ntohl(recvSegment->stcpheader.th_ack)!=(ctx->initial_sequence_num+1))
		      {
			fprintf(stderr,"Initialize failed : does not match sequence number\n");
			exit(2);
		      }
		    else
		      {
			ctx->initial_sequence_num++;
		      }
		    
		  }
	      }
	    else if(event==APP_CLOSE_REQUESTED)
	      {
		/*have to do*/
	      }
	  }
	else /*if received packet is neitehr ACK nor ACK+SYN*/
	  {
	    fprintf(stderr,"Initialized failed in SYN_SENT : Neitehr ACK nor ACK+SYN\n");
	    exit(2);
	  }
      }
    else                                        /* if passive open*/
      {
	ctx->connection_state=CSTATE_LISTEN;    /* LISTEN STATE*/
	event=stcp_wait_for_event(sd,ANY_EVENT,NULL);/* wait for ANY_EVENT infinitely*/
	if(event & NETWORK_DATA) /* when event is network_data*/
	  {
	    stcp_network_recv(sd,recvSegment,sizeof(SEGMENT));
	    if(recvSegment->stcpheader.th_flags==TH_SYN)/* if segment is SYN*/
	      {
		/*send SYN+ACK*/
		ctx->initial_sequence_num2=ntohl(recvSegment->stcpheader.th_seq);
		bzero(sendSegment,sizeof(SEGMENT));
		sendSegment->stcpheader.th_seq=htonl(ctx->initial_sequence_num);
		sendSegment->stcpheader.th_flags=(TH_ACK | TH_SYN);
		sendSegment->stcpheader.th_win=htons(MIN_CWND_SIZE);
		sendSegment->stcpheader.th_off=5;
		sendSegment->stcpheader.th_ack=htonl(ctx->initial_sequence_num2+1);
		stcp_network_send(sd,sendSegment,sizeof(SEGMENT),NULL);
		ctx->connection_state=CSTATE_SYN_RCVD;
		/* wait for the event*/
		event=stcp_wait_for_event(sd,ANY_EVENT,NULL);
		if(event & APP_CLOSE_REQUESTED)
		  {
		    ctx->connection_state=CSTATE_FIN_WAIT_1;
		    bzero(sendSegment,sizeof(SEGMENT));
		    sendSegment->stcpheader.th_flags=TH_FIN;
		    sendSegment->stcpheader.th_ack=htonl(ctx->initial_sequence_num2);
		    sendSegment->stcpheader.th_win=htons(MIN_CWND_SIZE);
		    sendSegment->stcpheader.th_off=5;
		 free(recvSegment);
		 free(sendSegment);
		    goto FIN;
		  }
		else if(event==NETWORK_DATA)
		  {
		    bzero(recvSegment,sizeof(SEGMENT));
		    stcp_network_recv(sd,recvSegment,sizeof(SEGMENT));
		    if(recvSegment->stcpheader.th_flags==TH_ACK)/*if receive ACK*/
		      {
			
			ctx->initial_sequence_num++;
			ctx->initial_sequence_num2++;
		      }
		  }
	      }
	    else
	      {
		fprintf(stderr,"Initialized failed in SYN_RCVD : Not SYN\n");
		exit(2);
	      }
	  }
      }
    ctx->connection_state = CSTATE_ESTABLISHED;
    fprintf(stdout,"before establish last check. seq1 : %d\nseq2 : %d\n",ctx->initial_sequence_num,ctx->initial_sequence_num2);
    fflush(stdout);
    stcp_unblock_application(sd);
    control_loop(sd, ctx);
    if(ctx->connection_state==CSTATE_CLOSE_WAIT)
      {
	bzero(sendSegment,sizeof(SEGMENT));
	event=stcp_wait_for_event(sd,APP_CLOSE_REQUESTED,NULL);
	sendSegment->stcpheader.th_flags=TH_FIN;
	ctx->initial_sequence_num+=1;
	sendSegment->stcpheader.th_seq=htonl(ctx->initial_sequence_num);
	sendSegment->stcpheader.th_win=htons(MIN_CWND_SIZE);
	sendSegment->stcpheader.th_off=5;
	stcp_network_send(sd,sendSegment,sizeof(SEGMENT),NULL);
	ctx->connection_state=CSTATE_LAST_ACK;
	bzero(recvSegment,sizeof(SEGMENT));
	stcp_network_recv(sd,recvSegment,sizeof(SEGMENT));
	if(recvSegment->stcpheader.th_flags==TH_ACK)
	  {
	    free(ctx);
	    free(recvSegment);
	    free(sendSegment);
	    return;
	  }
      }
 FIN:
    
    bzero(recvSegment,sizeof(SEGMENT));
    stcp_network_recv(sd,recvSegment,sizeof(SEGMENT));
    fprintf(stdout,"recv : %d %d %X %d %d %s\n",ntohl(recvSegment->stcpheader.th_seq),ntohl(recvSegment->stcpheader.th_ack),recvSegment->stcpheader.th_flags,ntohs(recvSegment->stcpheader.th_win),strlen(recvSegment->data),recvSegment->data);
    if(recvSegment->stcpheader.th_flags==TH_ACK)
      {
	ctx->connection_state=CSTATE_FIN_WAIT_2;
	bzero(recvSegment,sizeof(SEGMENT));
	stcp_network_recv(sd,recvSegment,sizeof(SEGMENT));
	if(recvSegment->stcpheader.th_flags==TH_FIN)
	  {
	    bzero(sendSegment,sizeof(SEGMENT));
	    sendSegment->stcpheader.th_flags=TH_ACK;
	    sendSegment->stcpheader.th_ack=htonl(ctx->initial_sequence_num2+1);
	    sendSegment->stcpheader.th_win=htons(MIN_CWND_SIZE);
	    sendSegment->stcpheader.th_off=5;
	    stcp_network_send(sd,sendSegment,sizeof(SEGMENT),NULL);
	  }
      }
    /* do any cleanup here */
    free(ctx);
    free(recvSegment);
    free(sendSegment);
    return;
}


/* generate random initial sequence number for an STCP connection */
static void generate_initial_seq_num(context_t *ctx)
{
    assert(ctx);

#ifdef FIXED_INITNUM
    /* please don't change this! */
    ctx->initial_sequence_num = 1;
#else
    /* you have to fill this up */
    srand((unsigned)time(NULL));
    ctx->initial_sequence_num =rand()%256;
#endif
}


/* control_loop() is the main STCP loop; it repeatedly waits for one of the
 * following to happen:
 *   - incoming data from the peer
 *   - new data from the application (via mywrite())
 *   - the socket to be closed (via myclose())
 *   - a timeout
 */
static void control_loop(mysocket_t sd, context_t *ctx)
{
    assert(ctx);
    SEGMENT *recvSegment,*sendSegment;
    int lastack=ctx->initial_sequence_num;
    recvSegment=(SEGMENT *)calloc(1,sizeof(SEGMENT));
    sendSegment=(SEGMENT *)calloc(1,sizeof(SEGMENT));
    while (!ctx->done)
    {
        unsigned int event;
        /* see stcp_api.h or stcp_api.c for details of this function */
        /* XXX: you will need to change some of these arguments! */
        event = stcp_wait_for_event(sd, ANY_EVENT, NULL);

        /* check whether it was the network, app, or a close request */
        if (event & APP_DATA)
	  {
	    /* the application has requested that data be sent */
            /* see stcp_app_recv() */
	    stcp_app_recv(sd,sendSegment->data,MAX_PAYLOAD_SIZE-1);
	    sendSegment->stcpheader.th_seq=htonl(ctx->initial_sequence_num);
	    sendSegment->stcpheader.th_win=htons(MIN_CWND_SIZE);
	    sendSegment->stcpheader.th_off=5;
	    stcp_network_send(sd,sendSegment,sizeof(SEGMENT),NULL);
	    /* fprintf(stdout,"senddata : %d %d %X %d %d %s\n",ntohl(sendSegment->stcpheader.th_seq),ntohl(sendSegment->stcpheader.th_ack),sendSegment->stcpheader.th_flags,ntohs(sendSegment->stcpheader.th_win),sendSegment->stcpheader.th_off,sendSegment->data);*/
	    ctx->initial_sequence_num+=strlen(sendSegment->data);
	    bzero(sendSegment,sizeof(SEGMENT));
	    
	  }
	else if(event & NETWORK_DATA)
	  {
	    stcp_network_recv(sd,recvSegment,sizeof(SEGMENT));
	    /*fprintf(stdout,"recv : %d %d %X %d %d %s\n",ntohl(recvSegment->stcpheader.th_seq),ntohl(recvSegment->stcpheader.th_ack),recvSegment->stcpheader.th_flags,ntohs(recvSegment->stcpheader.th_win),strlen(recvSegment->data),recvSegment->data);*/
	    if(recvSegment->stcpheader.th_flags==TH_ACK)
	      {
	        lastack=ntohl(recvSegment->stcpheader.th_ack);
	      }
	    else if(recvSegment->stcpheader.th_flags==TH_FIN)
	      {
		stcp_fin_received(sd);
		bzero(sendSegment,sizeof(SEGMENT));
		ctx->connection_state=CSTATE_CLOSE_WAIT;
		sendSegment->stcpheader.th_flags=TH_ACK;
		ctx->initial_sequence_num2+=1;
		sendSegment->stcpheader.th_ack=htonl(ctx->initial_sequence_num2);
		sendSegment->stcpheader.th_win=htons(MIN_CWND_SIZE);
		sendSegment->stcpheader.th_off=5;
		stcp_network_send(sd,sendSegment,sizeof(SEGMENT),NULL);
		 free(recvSegment);
		 free(sendSegment);
		return;
	      }
	    else
	      {
		/*check window size and packet*/
		if((ctx->initial_sequence_num2+MIN_CWND_SIZE-1)>ntohl(recvSegment->stcpheader.th_seq))
		  {
		    stcp_app_send(sd,recvSegment->data,strlen(recvSegment->data));
		    ctx->initial_sequence_num2+=strlen(recvSegment->data);
		  }
		/*send ACK*/
		sendSegment->stcpheader.th_flags=TH_ACK;
		sendSegment->stcpheader.th_ack=htonl(ctx->initial_sequence_num2);
		sendSegment->stcpheader.th_win=htons(MIN_CWND_SIZE);
		sendSegment->stcpheader.th_off=5;
		/*fprintf(stdout,"sendack : %d %d %X %d %d %s\n",ntohl(sendSegment->stcpheader.th_seq),ntohl(sendSegment->stcpheader.th_ack),sendSegment->stcpheader.th_flags,ntohs(sendSegment->stcpheader.th_win),strlen(sendSegment->data),sendSegment->data);*/
		stcp_network_send(sd,sendSegment,sizeof(SEGMENT),NULL);
	      }
	    /*send ACK*/
	  }
	else if(event & APP_CLOSE_REQUESTED)
	  {
	    sendSegment->stcpheader.th_flags=TH_FIN;
	    sendSegment->stcpheader.th_seq=htonl(ctx->initial_sequence_num);
	    sendSegment->stcpheader.th_win=htons(MIN_CWND_SIZE);
	    sendSegment->stcpheader.th_off=5;
	    stcp_network_send(sd,sendSegment,sizeof(SEGMENT),NULL);
	    fprintf(stdout,"sendfin : %d %d %X %d %d %s\n",ntohl(sendSegment->stcpheader.th_seq),ntohl(sendSegment->stcpheader.th_ack),sendSegment->stcpheader.th_flags,ntohs(sendSegment->stcpheader.th_win),strlen(sendSegment->data),sendSegment->data);
	    ctx->connection_state=CSTATE_FIN_WAIT_1;
	     free(recvSegment);
	     free(sendSegment);
	     return;
	  }
	bzero(sendSegment,sizeof(SEGMENT));
	bzero(recvSegment,sizeof(SEGMENT));
        /* etc. */
    }
    free(recvSegment);
    free(sendSegment);
    return;
}


/**********************************************************************/
/* our_dprintf
 *
 * Send a formatted message to stdout.
 * 
 * format               A printf-style format string.
 *
 * This function is equivalent to a printf, but may be
 * changed to log errors to a file if desired.
 *
 * Calls to this function are generated by the dprintf amd
 * dperror macros in transport.h
 */
void our_dprintf(const char *format,...)
{
    va_list argptr;
    char buffer[1024];

    assert(format);
    va_start(argptr, format);
    vsnprintf(buffer, sizeof(buffer), format, argptr);
    va_end(argptr);
    fputs(buffer, stdout);
    fflush(stdout);
}



