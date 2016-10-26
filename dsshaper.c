/*staopyright (c) 1999, Federal University of Pernambuco - Brazil.
	printk(KERN_EMERG "[mengy][update_bucket_contents] before contents %ld\n",dsshaper_my.curr_bucket_contents);
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
#include <asm/div64.h>
#include <linux/spinlock.h>
#include <linux/hrtimer.h>
#include <linux/ktime.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/spinlock_types.h>

#include <linux/types.h> 
#include <linux/sysctl.h>

/*for timestamp te th tw by mengy*/
#define MS_TO_NS(x)	(x * 1E6L)
 
int schedule_packet_number =0;
//int restart_flag=0;
/*for update_deqrate*/
//int flow_peak = 80000000;
int ntrans_ = 0;
struct timespec delay_sum_ = {0};
int pktsize_sum_ = 0;
struct timespec checkInterval_ = {0,5000000};
struct timespec checktime_;
long throughput_sum_ = 0;
int alpha_ = 0; //%
spinlock_t lock;
long long rate_avg_ = 0; //bits/s
int delay_avg_ = 0;
static int switchOn_ = 1;
//SYSCTL_INT( _net, OID_AUTO, fixpeak, CTLFLAG_RW, &switchOn_, 1, "whether to set the fix peak");
int delay_optimal_ = 2000;//us
int fix_peak = 100000000; //bits/s
long long flow_peak = 100000000; // bits/s
int beta_ = 100000; //bits/s
int burst_size_ = 80000;// bits
int deltaIncrease_ = 1000000; //bits/s
struct timespec checkThInterval_ = {1,0};
struct timespec checkThtime_ = {0};
int shape_flag = 0;
int restart_times = 0;
struct hrtimer hr_timer;
//extern void recv(int len, struct ath_softc *sc, struct ath_txq *txq, struct list_head *p, bool internal);
int list_length_one(struct list_head *head);
void resume_test(void);
int timer_module(int time_delay,struct timer_list *my_timer); // time_delay(ms)
//void recv(int len, struct ath_softc *sc, struct ath_txq *txq, struct list_head *p, bool internal);
bool shape_packet(struct list_head packet,struct ath_softc *sc, struct ath_txq *txq,bool internal,int len,int schedule_flag);
void schedule_packet(int len);
//void resume(void);
enum hrtimer_restart resume(struct hrtimer *timer );
bool in_profile(int size);
void update_bucket_contents(void);
struct DSShaper dsshaper_my = { 0,0,0,0,0,0,{0,0},80000,60};
int init_flag = 0; //for the initialize
struct list_head shape_queue; //for the packet queue
//struct list_head shape_queue_msg; // for the packet queue msg

/*add for sysctl*/
static char mystring[256];
static int myint;
static struct ctl_table my_sysctl_exam[] = {
        {
                .procname       = "myint",
                .data           = &myint,
                .maxlen         = sizeof(int),
                .mode           = 0666,
                .proc_handler   = &proc_dointvec,
        },
        {
                .procname       = "mystring",
                .data           = mystring,
                .maxlen         = MY_MAX_SIZE,
                .mode           = 0666,
                .proc_handler   = &proc_dostring,
        },
        {
        }
};

static struct ctl_table my_root = {
        .procname       = "mysysctl",
        .mode           = 0555,
        .child          = my_sysctl_exam,
};

static struct ctl_table_header * my_ctl_header;

static int __init sysctl_exam_init(void)
{
        my_ctl_header = register_sysctl_table(&my_root);

        return 0;
}

static void __exit sysctl_exam_exit(void)
{
        unregister_sysctl_table(my_ctl_header);
}


void update_bucket_contents()
{

	struct timespec current_time;
	getnstimeofday(&current_time);
	struct timespec tmp_sub = timespec_sub(current_time,dsshaper_my.last_time);
	//printk(KERN_EMERG "[mengy][update_bucket_contents] before contents %ld time gap  %ld.%ld flow_peak %ld\n",dsshaper_my.curr_bucket_contents,tmp_sub.tv_sec,tmp_sub.tv_nsec,flow_peak);
	//u64 tmp_number = 1000000; 
	long long tmp_add;
	if ( tmp_sub.tv_sec >2)
		tmp_add = tmp_sub.tv_nsec /1000;
	else
		tmp_add = tmp_sub.tv_sec * 1000000 + tmp_sub.tv_nsec /1000;
	long long added_bits = div64_s64(tmp_add * flow_peak ,(long long) 1000000) ; // us * bits/s / 1000000
	//added_bits = 1000;
	//tmp_number = 10;
	//printk(KERN_EMERG "[mengy][update_bucket_contents] add bits %lld\n",added_bits);
	dsshaper_my.curr_bucket_contents =dsshaper_my.curr_bucket_contents +  added_bits;
	if (dsshaper_my.curr_bucket_contents > dsshaper_my.burst_size_)
		dsshaper_my.curr_bucket_contents=dsshaper_my.burst_size_ ; //unsettled how to update burst_size
	
	//printk(KERN_EMERG "[mengy][update_bucket_contents] tmp_add %ldus curr_bucket:%ld,add bits:%ld\n",tmp_add,dsshaper_my.curr_bucket_contents,added_bits);	
	getnstimeofday(&current_time);
	dsshaper_my.last_time = current_time ;


}

long long count_schedule_time(int len)
{
	long long delay = div64_s64((((long long)len * 8 - dsshaper_my.curr_bucket_contents) * 1000000),flow_peak) ; // bits / (bits/s /1000000)   = us
	if(delay == 0)
		delay=100;
	return delay;
}

enum hrtimer_restart resume(struct hrtimer *timer )
{
	struct timespec now;
	getnstimeofday(&now);
	//printk(KERN_EMERG "[mengy][resume]resume after time:%ld.%ld\n",now.tv_sec,now.tv_nsec);
	int resume_count = 0;
	struct packet_msg *packet_resume;
	//struct packet_dsshaper *packet_dsshaper_resume;
	//struct list_head *lh_packet_resume;
	//struct list_head *lh_p_resume;
	while (!list_empty(&shape_queue))
	{
		packet_resume = list_entry(shape_queue.next,struct packet_msg,list);
		resume_count++;
		//printk(KERN_EMERG "[mengy][resume]while count %ld\n",resume_count);
		if (in_profile(packet_resume->len)) 
		{
			dsshaper_my.sent_packets++;
			//printk(KERN_EMERG "[mengy][resume]try set the packet\n");
			ath_tx_txqaddbuf(packet_resume->sc, packet_resume->txq,&packet_resume->packet, packet_resume->internal);
			//printk(KERN_EMERG "[mengy][resume]sent the packet number:%ld\n",dsshaper_my.sent_packets);
			list_del(shape_queue.next);
			kfree(packet_resume);
		}
		else 
		{
			long long delay = count_schedule_time(packet_resume->len);
			ktime_t ktime;
			ktime = ktime_set( 0,delay*1000);//100us
			getnstimeofday(&now);
			restart_times++;
			//if(restart_times%500==1)
			//printk(KERN_EMERG "[mengy][resume]restart the packet resume for %lldus restart times %d\n",delay,restart_times);
			hrtimer_forward_now(&hr_timer,ktime);
			return HRTIMER_RESTART;
		} 
	}
		restart_times=0;
		//printk(KERN_EMERG "[mengy][resume]stop the timer\n");
		return HRTIMER_NORESTART;
} 

void schedule_packet(int len)
{
	long long delay = div64_s64((((long long )len * 8 - dsshaper_my.curr_bucket_contents) * 1000000), flow_peak) ; //us
	if(delay == 0)
		delay=100;
	ktime_t ktime;
	ktime = ktime_set( 0,(u64)delay*1000);//100us
	hrtimer_init(&hr_timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL );
	hr_timer.function = &resume;
	struct timespec now;
	getnstimeofday(&now);
	//printk(KERN_EMERG "[mengy][schedule_packet]schedule the packet begin for %lldus time:%ld.%ld\n",delay,now.tv_sec,now.tv_nsec);
	hrtimer_start( &hr_timer, ktime, HRTIMER_MODE_REL );
	return;
}

bool shape_packet(struct list_head packet,struct ath_softc *sc, struct ath_txq *txq,bool internal,int len,int schedule_flag)
{

	//if (list_length(&shape_queue) >= 2) {
			//drop (p);// unsettled how to drop?
			//printk(KERN_DEBUG "[mengy][shape_packet]shape the packet fails over queue length\n");
//			dsshaper_my.dropped_packets++;
			//printk(KERN_DEBUG "[mengy][shape_packet]q list: %ld\n",list_length(&shape_queue));
			//return false;
	//	} 

		struct packet_msg *my_packet;
		my_packet = kzalloc(sizeof(struct packet_msg),GFP_KERNEL);
		INIT_LIST_HEAD(&my_packet->list);//unsettled
		my_packet->packet = packet; 
		my_packet->sc = sc;
		my_packet->txq = txq;
		my_packet->internal = internal;
		my_packet->len = len;
		list_add_tail(&my_packet->list,&shape_queue);
	//	spin_unlock_bh(&lock);

		dsshaper_my.shaped_packets++;
		//printk(KERN_EMERG "[mengy][shape_packet]shape the packe shape number:%ld\n",dsshaper_my.shaped_packets);
		//printk(KERN_DEBUG "[mengy][shape_packet]q list: %ld shedule_flag %ld\n",list_length_one(&shape_queue),schedule_flag);
		//if(list_length_one(&shape_queue))
		if(schedule_flag ==1)
				schedule_packet(len);
			
	return true;
}

bool in_profile(int size)
{

	update_bucket_contents() ;

	long packetsize = size * 8;

	//printk(KERN_EMERG "[mengy][in_profile] packetsize:%ld,curr_bucket:%ld\n",packetsize,dsshaper_my.curr_bucket_contents);	
	if(packetsize > dsshaper_my.burst_size_)
	{
		if(dsshaper_my.curr_bucket_contents == dsshaper_my.burst_size_)
		{
			dsshaper_my.curr_bucket_contents=0;
			return true;
		}
		else
			return false;
	}

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
		//INIT_LIST_HEAD(&shape_queue_msg);
		sysctl_exam_init();
		struct timespec now;
		getnstimeofday(&now);
		spin_lock_init(&lock);
		dsshaper_my.last_time = now;
		//long long test1 = 100000000;
		//long long test2 = 1000000;
		//long long  result;
		//result = div64_s64(test1,test2);
		
	//	printk(KERN_EMERG "[mengy][recv]resutl div %lld\n",result);		
		init_flag=1;
	}				
	dsshaper_my.received_packets++;
	//printk(KERN_EMERG "[mengy][recv]receive packet number :%ld \n",dsshaper_my.received_packets);
	spin_lock_irq(&lock);
	if (list_empty(&shape_queue)) 
	//if(true)
	{
///		  There are no packets being shapped. Tests profile.
//		printk(KERN_EMERG "[mengy][recv]list is empty\n");
		if (in_profile(len)) 
	//	if(true)
		{ 	
			spin_unlock_irq(&lock);		
			dsshaper_my.sent_packets++;
			//printk(KERN_EMERG "[mengy][recv]sent the packet number:%ld\n",dsshaper_my.sent_packets);
			ath_tx_txqaddbuf(sc, txq, &p, internal);
			return;
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
			//printk(KERN_EMERG "[mengy][recv]just add buffer queue\n");
		 //ath_tx_txqaddbuf(sc, txq, p, internal); 
	}
	spin_unlock_irq(&lock);
}

void update_deqrate(struct timespec p_delay,struct timespec all_delay, int pktsize_, int pnumber_)
{
	//printk(KERN_DEBUG "pdelay:%ld.%ld,pktsize_:%ld,pnumber_:%ld\n",p_delay.tv_sec,p_delay.tv_nsec,pktsize_,pnumber_);
	struct timespec now_;
	getnstimeofday(&now_);
	//double now_ = Scheduler::instance().clock();
//	printk(KERN_DEBUG "[mengy][update_deqrate entrance][time=%ld.%ld][p_delay=%ld.%ld][all_delay=%ld.%ld][pktsize_=%d bite][pktnumber_=%d]\n",now_.tv_sec,now_.tv_nsec,p_delay.tv_sec,p_delay.tv_nsec,all_delay.tv_sec,all_delay.tv_nsec,pktsize_*8,pnumber_);
	if(init_flag == 0){
		INIT_LIST_HEAD(&shape_queue);
		//INIT_LIST_HEAD(&shape_queue_msg);
		struct timespec now;
		getnstimeofday(&now);
		spin_lock_init(&lock);
		dsshaper_my.last_time = now;		
		init_flag=1;
		sysctl_exam_init();
	}	
	


	long long pri_peak_ = flow_peak;
	//printk(KERN_DEBUG "pdelay:%ld.%ld,pktsize_:%ld,pnumber_:%ld,ntrans_:%ld\n",p_delay.tv_sec,p_delay.tv_nsec,pktsize_,pnumber_,ntrans_);	
	ntrans_ = ntrans_ + pnumber_;
	//printk(KERN_DEBUG "pdelay:%ld.%ld,pktsize_:%ld,pnumber_:%ld,ntrans_:%ld,delay_sum:%d.%d\n",p_delay.tv_sec,p_delay.tv_nsec,pktsize_,pnumber_,ntrans_,delay_sum_.tv_sec,delay_sum_.tv_nsec);
	//delay_sum_ += pdelay_;
	delay_sum_ = timespec_add(delay_sum_,p_delay);
	//printk(KERN_DEBUG "pdelay:%ld.%ld,pktsize_:%ld,pnumber_:%ld,ntrans_:%ld,delay_sum:%d.%d\n",p_delay.tv_sec,p_delay.tv_nsec,pktsize_,pnumber_,ntrans_,delay_sum_.tv_sec,delay_sum_.tv_nsec);
	pktsize_sum_ += pktsize_*8;

	struct timespec tmp_sub = timespec_sub(now_, checktime_); // unsettled checktime_
	if( timespec_compare(&tmp_sub,&checkInterval_) >0 ){
		//printk(KERN_DEBUG "pdelay:%ld.%ld,pktsize_:%ld,pnumber_:%ld,ntrans_:%ld,delay_sum:%ld.%ld\n",p_delay.tv_sec,p_delay.tv_nsec,pktsize_,pnumber_,ntrans_,delay_sum_.tv_sec,delay_sum_.tv_nsec);
		int delay_instant_;
		//int tmpus = delay_sum_.tv_sec * 1000000 + delay_sum_.tv_nsec/1000;
		//int tmpdelay = tmpus / ntrans_;
		//printk(KERN_EMERG "[mengy][update_deqrate after peak ][tmpus=%ld][delay_instant=%ld][ntrans=%ld][delay_sum=%ld.%ld]\n",tmpus,tmpdelay,ntrans_,delay_sum_.tv_sec,delay_sum_.tv_nsec);
		delay_instant_ = (delay_sum_.tv_sec * 1000000 + delay_sum_.tv_nsec/1000) / ntrans_; //us
		delay_avg_ = alpha_ * delay_avg_  / 100 + ( 100 - alpha_) * delay_instant_/100;//us
		//delay_avg_ = delay_instant_;
		//printk(KERN_EMERG "[mengy][update_deqrate after peak ][delay_avg=%ld][delay_instant=%ld][ntrans=%ld][delay_sum=%ld.%ld]\n",delay_avg_,delay_instant_,ntrans_,delay_sum_.tv_sec,delay_sum_.tv_nsec);

		
		
		rate_avg_ = div64_s64(((long long)pktsize_sum_ * 1000000),(delay_sum_.tv_sec * 1000000 + delay_sum_.tv_nsec /1000)) ; //bits/us
		if (switchOn_)
		{
			if( delay_avg_ > delay_optimal_ )
			{
				update_bucket_contents();
				flow_peak = div64_s64(delay_optimal_ * pri_peak_,(long long)delay_avg_); //unsettled
				if (flow_peak  < beta_)
					flow_peak = beta_;
			}else{
				update_bucket_contents();
				flow_peak =  pri_peak_ + deltaIncrease_;
				if (flow_peak  > rate_avg_)
					flow_peak = rate_avg_;
			}
		}else{
			update_bucket_contents();
			flow_peak = fix_peak; //fixed rate 
		}
		ntrans_ = 0;
		pktsize_sum_ = 0;
		delay_sum_.tv_sec = 0;
		delay_sum_.tv_nsec = 0;
		checktime_ = now_;
		
	}
	//update_bucket_contents();	
	printk(KERN_EMERG "[mengy][update_deqrate after peak ][rate=%lld][delay_avg=%ld][pri_peak=%lld][now_peak_=%lld]\n",rate_avg_,delay_avg_,pri_peak_,flow_peak);
	
	
	
	throughput_sum_ += pktsize_;
	tmp_sub = timespec_sub(now_,checkThtime_);
	if(  timespec_compare(&tmp_sub,&checkThInterval_)>0 ){
		long long throughput_avg_ = div64_s64((long long)( 8 * throughput_sum_ ) * 1000 ,(tmp_sub.tv_sec * 1000000 + tmp_sub.tv_nsec / 1000 ));
		printk(KERN_DEBUG "[mengy][update_deqrate throughput][bytes=%ld][throughput=%lld Kbps]\n",throughput_sum_,throughput_avg_);
		throughput_sum_ = 0;
		checkThtime_ = now_;
	}
}

int list_length_one(struct list_head *head)
{
	if(list_empty(head)){
		return 0;
	}
	//int count = 0;
	//struct list_head *p;
	//p = head->next;
	//while(p){
	//	count++;
	if(list_is_last(head->next,head))
			return 1;
	else
		return 0;

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



