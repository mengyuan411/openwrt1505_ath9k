/*staopyright (c) 1999, Federal University of Pernambuco - Brazil.
 * All rights reserved.
 *
 * License is granted to copy, to use, and to make and to use derivative
 * works for research and evaluation purposes.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 *
 * Carlos Alberto Kamienski <cak@di.ufpe.br>
 *
 */

#include "dsshaper.h"
#include <linux/dma-mapping.h>
#include "ath9k.h"
#include "ar9003_mac.h"
#include <linux/math64.h>
#include <linux/spinlock.h>
#include <linux/hrtimer.h>
#include <linux/ktime.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/spinlock_types.h>
/*for timestamp te th tw by mengy*/
#define MS_TO_NS(x)	(x * 1E6L)
 /*
struct timespec last_ack={0}; // for the last packet ack by mengy
int update_te_flag = 0;
int update_tw_flag = 0;
int has_beacon_flag = 0;
int packet_number = 0;
int packet_size_all = 0;
int last_ack_update_flag = 0;
struct timespec this_ack = {0};
struct timespec this_tw = {0};
*/
int schedule_packet_number =0;
//int restart_flag=0;
/*for update_deqrate*/
//int flow_peak = 80000000;
int ntrans_ = 0;
struct timespec delay_sum_ = {0};
int pktsize_sum_ = 0;
struct timespec checkInterval_ = {0,5000000};
struct timespec checktime_;
int throughput_sum_ = 0;
int alpha_ = 0; //%
spinlock_t lock;
int rate_avg_ = 0; //bits/us
int delay_avg_ = 0;
int switchOn_ = 0;
int delay_optimal_ = 2000;//us
int fix_peak = 8000000; //bits/s
int flow_peak = 8000000; // bits/s
int beta_ = 100000; //bits/s
int burst_size_ = 80000;// bits
int deltaIncrease_ = 1000000; //bits/s
struct timespec checkThInterval_ = {1,0};
struct timespec checkThtime_ = {0};
int shape_flag = 0;
struct hrtimer hr_timer;
//extern void recv(int len, struct ath_softc *sc, struct ath_txq *txq, struct list_head *p, bool internal);
int list_length(struct list_head *head);
void resume_test(void);
int timer_module(int time_delay,struct timer_list *my_timer); // time_delay(ms)
//void recv(int len, struct ath_softc *sc, struct ath_txq *txq, struct list_head *p, bool internal);
bool shape_packet(struct list_head packet,struct ath_softc *sc, struct ath_txq *txq,bool internal,int len,int schedule_flag);
void schedule_packet(struct list_head p,int len);
//void resume(void);
enum hrtimer_restart resume(struct hrtimer *timer );
bool in_profile(int size);
void update_bucket_contents(void);
struct DSShaper dsshaper_my = { 0,0,0,0,0,0,{0,0},500000,60};
int init_flag = 0; //for the initialize
struct list_head shape_queue; //for the packet queue
struct list_head shape_queue_msg; // for the packet queue msg




void update_bucket_contents()
{

	struct timespec current_time;
	getnstimeofday(&current_time);
	struct timespec tmp_sub = timespec_sub(current_time,dsshaper_my.last_time);
	//printk(KERN_EMERG "[mengy][update_bucket_contents] before contents %ld\n",dsshaper_my.curr_bucket_contents);
	//printk(KERN_EMERG "[mengy][update_bucket_contents] time gap  %ld.%ld flow_peak %ld\n",tmp_sub.tv_sec,tmp_sub.tv_nsec,flow_peak);
	//u64 tmp_number = 1000000; 
	long tmp_add;
	if ( tmp_sub.tv_sec >2)
		tmp_add = tmp_sub.tv_nsec /1000;
	else
		tmp_add = tmp_sub.tv_sec * 1000000 + tmp_sub.tv_nsec /1000;
	long added_bits = tmp_add * 80;  // s * bits/s
	//added_bits = 1000;
	//tmp_number = 10;
	//printk(KERN_EMERG "[mengy][update_bucket_contents] add bits %ld\n",added_bits);
	dsshaper_my.curr_bucket_contents =dsshaper_my.curr_bucket_contents +  added_bits;
	if (dsshaper_my.curr_bucket_contents > dsshaper_my.burst_size_)
		dsshaper_my.curr_bucket_contents=dsshaper_my.burst_size_ ; //unsettled how to update burst_size
	
	//printk(KERN_EMERG "[mengy][update_bucket_contents] tmp_add %ld curr_bucket:%ld,add bits:%ld",tmp_add,dsshaper_my.curr_bucket_contents,added_bits);	
	dsshaper_my.last_time = current_time ;


}

long count_schedule_time(int len)
{
	long delay = (len * 8 - dsshaper_my.curr_bucket_contents) / 80;
	if(delay == 0)
		delay=100;
	return delay;
}

enum hrtimer_restart resume(struct hrtimer *timer )
{
	struct timespec now;
	getnstimeofday(&now);
	printk(KERN_EMERG "[mengy][resume]resume after 100us time:%ld.%ld\n",now.tv_sec,now.tv_nsec);
	
	struct packet_msg *msg_resume;
	struct packet_dsshaper *packet_dsshaper_resume;
	struct list_head *lh_msg_resume;
	struct list_head *lh_p_resume;
	if (!list_empty(&shape_queue))
	{
		
		printk(KERN_EMERG "[mengy][resume]try get the packet and sent\n");
		lh_p_resume = shape_queue.next;
		printk(KERN_EMERG "[mengy][resume]get p resume\n");
		lh_msg_resume = shape_queue_msg.next;
		printk(KERN_EMERG "[mengy][resume]get msg resume\n");
		msg_resume = list_entry(lh_msg_resume,struct packet_msg,list);
		printk(KERN_EMERG "[mengy][resume]get msg entry\n");
		packet_dsshaper_resume = list_entry(lh_p_resume,struct packet_dsshaper,list);
		printk(KERN_EMERG "[mengy][resume]get packet entry\n");
	
		if (true) 
		{
			dsshaper_my.sent_packets++;
			printk(KERN_EMERG "[mengy][resume]try set the packet\n");
			ath_tx_txqaddbuf(msg_resume->sc, msg_resume->txq,&packet_dsshaper_resume->packet, msg_resume->internal);
			printk(KERN_EMERG "[mengy][resume]sent the packet number:%ld\n",dsshaper_my.sent_packets);
			list_del(lh_p_resume);
			list_del(lh_msg_resume);
			kfree(msg_resume);
			kfree(packet_dsshaper_resume);
			if (!list_empty(&shape_queue))
			{
				getnstimeofday(&now);
				printk(KERN_EMERG "[mengy][resume]list is not empty restart the timer %ld.%ld\n",now.tv_sec,now.tv_nsec);
				return HRTIMER_RESTART;
			}
			else
			{	
				printk(KERN_EMERG "[mengy][resume]stop the timer\n");
				return HRTIMER_NORESTART;
			}

		}
		else 
		{
			getnstimeofday(&now);
			long delay = count_schedule_time(msg_resume->len);
		//	ktime_t ktime;
		//	ktime = ktime_set( 0,(u64)delay*1000);//100us
			printk(KERN_EMERG "[mengy][schedule_packet]restart  the packet resume for %ldus time:%ld.%ld\n",delay,now.tv_sec,now.tv_nsec);
		//	hrtimer_forward_now(&hr_timer,ktime);
			return HRTIMER_RESTART;
		} 
	}  
	 	return HRTIMER_NORESTART;
} 

void schedule_packet(struct list_head p,int len)
{
	long delay = (len * 8 - dsshaper_my.curr_bucket_contents) / 80; //us
	if(delay == 0)
		delay=100;
	ktime_t ktime;
	ktime = ktime_set( 0,100000);//100us
	hrtimer_init(&hr_timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL );
	hr_timer.function = &resume;
	struct timespec now;
	getnstimeofday(&now);
	printk(KERN_EMERG "[mengy][schedule_packet]schedule the packet begin for 100us time:%ld.%ld\n",now.tv_sec,now.tv_nsec);
	hrtimer_start( &hr_timer, ktime, HRTIMER_MODE_REL );
	return;
}

bool shape_packet(struct list_head packet,struct ath_softc *sc, struct ath_txq *txq,bool internal,int len,int schedule_flag)
{
	   // schedule_packet(packet,len);
	//return true;
	/*
	if (list_length(&shape_queue) >= dsshaper_my.max_queue_length) {
			//drop (p);// unsettled how to drop?
			printk(KERN_DEBUG "[mengy][shape_packet]shape the packet fails over queue length\n");
			dsshaper_my.dropped_packets++;
			return false;
		} */
		//shape_queue.enque(p);
		struct packet_dsshaper* my_packet;
		my_packet = kzalloc(sizeof(struct packet_dsshaper),GFP_KERNEL);
		INIT_LIST_HEAD(&my_packet->list);
		my_packet->packet = packet;   
		list_add_tail(&my_packet->list,&shape_queue);
		//schedule_packet(packet,len,)
		//list_add_tail(packet,&shape_queue);
		

		struct packet_msg *msg;
		msg = kzalloc(sizeof(struct packet_msg),GFP_KERNEL);
		INIT_LIST_HEAD(&msg->list);//unsettled 
		msg->sc = sc;
		msg->txq = txq;
		msg->internal = internal;
		msg->len = len;
		list_add_tail(&msg->list,&shape_queue_msg);
	//	spin_unlock_bh(&lock);

		dsshaper_my.shaped_packets++;
		printk(KERN_EMERG "[mengy][shape_packet]shape the packe shape number:%ld\n",dsshaper_my.shaped_packets);
		if(schedule_flag ==1)
			schedule_packet(packet,len);
	return true;
}

bool in_profile(int size)
{

	update_bucket_contents() ;

	long packetsize = size * 8;

	printk(KERN_EMERG "[mengy][in_profile] packetsize:%ld,curr_bucket:%ld\n",packetsize,dsshaper_my.curr_bucket_contents);	
	if (packetsize > dsshaper_my.curr_bucket_contents)
		return false;
	else {
		dsshaper_my.curr_bucket_contents -= packetsize ;
		return true ;
	}
}

void recv(int len, struct ath_softc* sc, struct ath_txq* txq, struct list_head p, bool internal)
{

	//
	if(init_flag == 0){
		INIT_LIST_HEAD(&shape_queue);
		INIT_LIST_HEAD(&shape_queue_msg);
		struct timespec now;
		getnstimeofday(&now);
		spin_lock_init(&lock);
		dsshaper_my.last_time = now;
		printk(KERN_EMERG "[mengy][recv]init finished\n");		
		init_flag=1;
	}				
	dsshaper_my.received_packets++;
	printk(KERN_EMERG "[mengy][recv]receive packet number :%ld \n",dsshaper_my.received_packets);
	//spin_lock_bh(&lock);
	/* test for the q*/
	if(dsshaper_my.received_packets > 301)
	{	
		if(list_empty(&shape_queue))
		{
			printk(KERN_EMERG "[mengy][recv]shape and schedule the packet number :%ld \n",dsshaper_my.received_packets);
			shape_packet(p,sc,txq,internal,len,1);
		}
		else
		{
			printk(KERN_EMERG "[mengy][recv]just shape the packet number :%ld \n",dsshaper_my.received_packets);
			shape_packet(p,sc,txq,internal,len,0);
		}
		//shape_packet(p,sc,txq,internal,len,1);	

		return;
	}
/*
		
	if(dsshaper_my.received_packets == 306)
	{
		struct packet_msg *msg_resume;
        	struct packet_dsshaper *packet_dsshaper_resume;
        	struct list_head *lh_msg_resume;
        	struct list_head *lh_p_resume;
		int free_count = 0;
        	while (!list_empty(&shape_queue))
        	{

                	lh_p_resume = shape_queue.next;
                	lh_msg_resume = shape_queue_msg.next;
                	msg_resume = list_entry(lh_msg_resume,struct packet_msg,list);
                	packet_dsshaper_resume = list_entry(lh_p_resume,struct packet_dsshaper,list);
			free_count++;

                	//if (in_profile(msg_resume->len))
                //	{
                        	dsshaper_my.sent_packets++;
         //               	ath_tx_txqaddbuf(msg_resume->sc, msg_resume->txq, packet_dsshaper_resume->packet, msg_resume->internal);
                        	list_del(lh_p_resume);
                        	list_del(lh_msg_resume);
				printk(KERN_DEBUG "[mengy][q test]free count %ld\n",free_count);			
                        	kfree(msg_resume);
                        	kfree(packet_dsshaper_resume);	
			}		
	
	}
	
*/
		ath_tx_txqaddbuf(sc, txq, &p, internal);
	return;
	if (list_empty(&shape_queue)) 
	{
///		  There are no packets being shapped. Tests profile.
		if (in_profile(len)) 
		{ 	
			spin_unlock_bh(&lock);		
			dsshaper_my.sent_packets++;
			printk(KERN_EMERG "[mengy][recv]sent the packet number:%ld\n",dsshaper_my.sent_packets);
			ath_tx_txqaddbuf(sc, txq, &p, internal);
		} 
		else
		{
			shape_packet(p,sc,txq,internal,len,1);
			//ath_tx_txqaddbuf(sc, txq, p, internal);
		}	

  	} 
  	else 
  	{		  		
//		  There are packets being shapped. Shape this packet too.
			shape_packet(p,sc,txq,internal,len,0);   
			printk(KERN_EMERG "[mengy][recv]just add buffer queue\n");
		 //ath_tx_txqaddbuf(sc, txq, p, internal); 
	}
}

void update_deqrate(struct timespec p_delay,struct timespec all_delay, int pktsize_, int pnumber_)
{
	//printk(KERN_DEBUG "pdelay:%ld.%ld,alldelay_:%ld.%ld,pktsize_:%ld,pnumber_:%ld\n",pdelay_sec,pdelay_nsec,alldelay_sec,alldelay_nsec,pktsize_,pnumber_);
	struct timespec now_;
	getnstimeofday(&now_);
	//double now_ = Scheduler::instance().clock();
//	printk(KERN_DEBUG "[mengy][update_deqrate entrance][time=%ld.%ld][p_delay=%ld.%ld][all_delay=%ld.%ld][pktsize_=%d bite][pktnumber_=%d]\n",now_.tv_sec,now_.tv_nsec,p_delay.tv_sec,p_delay.tv_nsec,all_delay.tv_sec,all_delay.tv_nsec,pktsize_*8,pnumber_);
	if(init_flag == 0){
		INIT_LIST_HEAD(&shape_queue);
		INIT_LIST_HEAD(&shape_queue_msg);
		struct timespec now;
		getnstimeofday(&now);
		spin_lock_init(&lock);
		dsshaper_my.last_time = now;		
		init_flag=1;
	}	
	


	int pri_peak_ = flow_peak;
	ntrans_ = ntrans_ + pnumber_;
	//delay_sum_ += pdelay_;
	delay_sum_ = timespec_add(delay_sum_,p_delay);
	pktsize_sum_ += pktsize_*8;

	struct timespec tmp_sub = timespec_sub(now_, checktime_); // unsettled checktime_
	if( timespec_compare(&tmp_sub,&checkInterval_) >0 ){
		int delay_instant_ = (delay_sum_.tv_sec * 1000000 + delay_sum_.tv_nsec/1000)/ntrans_; //us
		delay_avg_ = alpha_ * delay_avg_  / 100 + ( 100 - alpha_) * delay_instant_/100;//us
		
		
		
		rate_avg_ = pktsize_sum_ / (delay_sum_.tv_sec * 1000000 + delay_sum_.tv_nsec /1000) ; //bits/us
		if (switchOn_)
		{
			if( delay_avg_ > delay_optimal_ )
			{
				update_bucket_contents();
				flow_peak = delay_optimal_ * pri_peak_ / delay_avg_; //unsettled
				if (flow_peak  < beta_)
					flow_peak = beta_;
			}else{
				update_bucket_contents();
				flow_peak =  pri_peak_ + deltaIncrease_;
				if (flow_peak  > rate_avg_ * 1000000 )
					flow_peak = rate_avg_ * 1000000 ;
			}
		}else{
			flow_peak = fix_peak; //fixed rate 
		}
		ntrans_ = 0;
		pktsize_sum_ = 0;
		delay_sum_.tv_sec = 0;
		delay_sum_.tv_nsec = 0;
		checktime_ = now_;
		
	}
	update_bucket_contents();	
	//printk(KERN_EMERG "[mengy][update_deqrate after peak ][time=%ld.%ld][rate=%ld][delay_avg=%ld][pri_peak=%ld][now_peak_=%ld]\n",now_.tv_sec,now_.tv_nsec,rate_avg_,delay_avg_,pri_peak_,flow_peak);
	
	
	
	throughput_sum_ += pktsize_;
	tmp_sub = timespec_sub(now_,checkThtime_);
	if(  timespec_compare(&tmp_sub,&checkThInterval_)>0 ){
		int throughput_avg_ = ( 8 * throughput_sum_ )/((int) (tmp_sub.tv_sec * 1000000 + tmp_sub.tv_nsec / 1000 )) * 1000;
		//printk(KERN_DEBUG "[mengy][update_deqrate throughput][time=%ld.%ld][bytes=%ld][throughput=%ld Kbps]\n",now_.tv_sec,now_.tv_nsec,throughput_sum_,throughput_avg_);
		throughput_sum_ = 0;
		checkThtime_ = now_;
	}
}

int list_length(struct list_head *head)
{
	if(list_empty(head)){
		return 0;
	}
	int count = 0;
	struct list_head *p;
	p = head->next;
	while(p){
		count++;
		if(list_is_last(p,head)){
			return count;
		}
		p = p->next;

	}

}
/*
int timer_module(int time_delay,struct timer_list *my_timer)
{
  int ret;

  //printk("Timer module installing\n");

  // my_timer.function, my_timer.data
  setup_timer( my_timer,resume, 0 );

  //printk( "Starting timer to fire in %ld ms (%ld)\n", time_delay,jiffies );
  ret = mod_timer(my_timer, jiffies + msecs_to_jiffies(time_delay) );
  if (ret) printk("Error in mod_timer\n");

  return 0;
}
/*
enum hrtimer_restart my_hrtimer_callback( struct hrtimer *timer )
{
  struct timespec now;
  getnstimeofday(&now);
  printk(KERN_DEBUG "[mengy][schedule_packet]schedule the packet resume for 1ms time:%ld.%ld\n",now.tv_sec,now.tv_nsec);
  //printk(KERN_DEBUG "my_hrtimer_callback called (%ld).\n", jiffies );
  int ret;
  shape_flag=0;
  //ret = hrtimer_cancel(&hr_timer );
  //if (ret) printk(KERN_DEBUG "The timer was still in use...\n");

  //printk(KERN_DEBUG "HR Timer module uninstalling\n");
  //shape_flag=0;
  return HRTIMER_NORESTART;
}*/
//struct hrtimer hr_timer;
/*
void resume_test(void)
{
	
	struct timespec now;
	getnstimeofday(&now);
	printk(KERN_DEBUG "[mengy][schedule_packet]schedule the packet resume test:%ld.%ld\n",now.tv_sec,now.tv_nsec);
	//return;
	//spinlock_t lock;
	//spin_lock_init(&lock); 
	
	spin_lock_bh(&lock);
	struct packet_msg *msg_resume;
	struct packet_dsshaper *packet_dsshaper_resume;
	struct list_head *lh_msg_resume;
	struct list_head *lh_p_resume;
	if (!list_empty(&shape_queue))
	{

		lh_p_resume = shape_queue.next;
		lh_msg_resume = shape_queue_msg.next;
		msg_resume = list_entry(lh_msg_resume,struct packet_msg,list);
		packet_dsshaper_resume = list_entry(lh_p_resume,struct packet_dsshaper,list);
		//printk(KERN_DEBUG "[mengy][resume]resume the packet length:%ld\n",msg_resume->len);
		ath_tx_txqaddbuf(msg_resume->sc, msg_resume->txq, packet_dsshaper_resume->packet, msg_resume->internal);
				printk(KERN_DEBUG "[mengy][resume]sent the packet number:%ld\n",dsshaper_my.sent_packets);
			list_del(lh_p_resume);
				list_del(lh_msg_resume);
				kfree(msg_resume);
				kfree(packet_dsshaper_resume);
		spin_unlock_bh(&lock);
		return;
	}
	else
	{
		printk(KERN_DEBUG "[mengy][Error	 ][the queue is empty!]\n");
		spin_unlock_bh(&lock);
		return;
	}

	//struct hdr_cmn *hdr = hdr_cmn::access(p);
	//printf("[changhua pei][TC-resume ][%d->%d][id=%d][type=%d][time=%f][eqts_=%f][holts_=%f][wait_time_=%f][retrycnt=%d]\n",hdr->prev_hop_,hdr->next_hop_,hdr->uid_,hdr->ptype_,Scheduler::instance().clock(),hdr->eqts_,hdr->holts_,hdr->holts_-hdr->eqts_,hdr->retrycnt_);
	
if (in_profile(msg_resume->len)) {
	//if(true){
		dsshaper_my.sent_packets++;
		ath_tx_txqaddbuf(msg_resume->sc, msg_resume->txq, packet_dsshaper_resume->packet, msg_resume->internal);
		printk(KERN_DEBUG "[mengy][resume]sent the packet number:%ld\n",dsshaper_my.sent_packets);
		list_del(lh_p_resume);
		list_del(lh_msg_resume);
		kfree(msg_resume);
		kfree(packet_dsshaper_resume);
	//	spin_unlock_bh(&lock);
	//	shape_flag =0;
		//return HRTIMER_NORESTART;
			//target_->recv(p,(Handler*) NULL);  //unsettled why recv? 

	}
else {
		//printf("[changhua pei][TC-resume0][%d->%d][id=%d][puid_=%d][schedule until the packet is sent out!]\n",hdr->prev_hop_,hdr->next_hop_,hdr->uid_, p->uid_);
			//printk(KERN_DEBUG "[mengy][resume]resume and schedule the packet length:%ld\n",msg_resume->len);
		spin_unlock_bh(&lock);
		schedule_packet(packet_dsshaper_resume->packet,msg_resume->len);
		//spin_unlock_bh(&lock);
		return;
	} 

	if (!list_empty(&shape_queue)) {  //why don't check the bucket again?
//		 There are packets in the queue. Schedule the first one.
		   //Packet *first_p = shape_queue.lookup(0);
		   
		   //Scheduler& s = Scheduler::instance();
		   //s.schedule(&sh_, first_p, 0);
		//printk(KERN_DEBUG "[mengy][resume]sent success and schedule again\n");   
		//struct timer_list my_timer;  
		//timer_module(1,&my_timer); 
			lh_p_resume = shape_queue.next;
			lh_msg_resume = shape_queue_msg.next;
			msg_resume = list_entry(lh_msg_resume,struct packet_msg,list);
			packet_dsshaper_resume = list_entry(lh_p_resume,struct packet_dsshaper,list);
			schedule_packet(packet_dsshaper_resume->packet,msg_resume->len);
				//printk(KERN_DEBUG "[mengy][resume]resume the packet length:%ld\n",msg_resume->len);   
	 	//dsshaper_my.sent_packets++;
				//printk(KERN_DEBUG "[mengy][resume]resume and sent the packet length:%ld\n",msg_resume->len);
				//printk(KERN_DEBUG "[mengy][schedule_packet]schedule the packet resume for 1ms time:%ld.%ld\n",now.tv_sec,now.tv_nsec);
				//ath_tx_txqaddbuf(msg_resume->sc, msg_resume->txq, packet_dsshaper_resume->packet, msg_resume->internal);
				//list_del(lh_p_resume);
				//list_del(lh_msg_resume);
				//kfree(msg_resume);
				//kfree(packet_dsshaper_resume);
			spin_unlock_bh(&lock);
		// schedule_packet(packet,len,my_packet->hr_timer);
	}  
	 return HRTIMER_NORESTART;
} */


