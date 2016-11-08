/*
 * Copyright (c) 2008-2011 Atheros Communications Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */


#include <linux/timer.h> //for timer mengy
#include <linux/time.h>
//#include <linux/types.h>
#include <linux/math64.h>
#include <linux/sysctl.h>
//#include <linux/hw_random.h>
#include <net/mac80211.h>
//#include <sys/types.h>
#include "ath9k.h"


/*for update_deqrate*/
extern long long flow_peak ; // bits/s
///int beta_ ; //bits/s
//int burst_size_; //bits
//int deltaIncrease_ ; //bits/s
//struct timespec checkThtime_;
//struct timespec checkThInterval_;
//int throughput_sum_;
//struct timespec checkThtime_;

#ifndef ATH9K_DSSHAPPER_H
#define ATH9K_DSSHAPPER_H

/*add for sysctl*/
#define MY_ROOT (CTL_CPU + 10)
#define MY_MAX_SIZE 256
enum {
        MY_INT_EXAM = 1,
	MY_STRING_EXAM = 2,
};

void update_deqrate(struct timespec p_delay,struct timespec all_delay, int pktsize_, int pnumber_);
extern void update_bucket_contents(void);
void recv(int len, struct ath_softc* sc, struct ath_txq* txq, struct list_head p, bool internal);
extern void ath_tx_txqaddbuf(struct ath_softc *sc, struct ath_txq *txq,struct list_head *head, bool internal); // changed by my

struct DSShaper {
	long		received_packets ;
	long		sent_packets ;
	long		shaped_packets ;
	long		dropped_packets ;
	long long		curr_bucket_contents ;
	int		flow_id_;
	struct timespec      last_time ; // last time update bucket contents
	//int		peak_ ;
	int			burst_size_ ;
	int         max_queue_length;
};

//extern int flow_peak;
struct packet_msg
{
	/* data */
	struct list_head list;
	struct list_head packet;
	struct ath_softc *sc;
	struct ath_txq *txq;
	bool internal;
	int len;


};


#endif
