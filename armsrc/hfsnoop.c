#include "proxmark3.h"
#include "apps.h"
#include "BigBuf.h"
#include "util.h"
#include "usb_cdc.h"	// for usb_poll_validate_length

static void RAMFUNC optimizedSnoop(void);

static void RAMFUNC optimizedSnoop(void)
{
	int n = BigBuf_max_traceLen() / sizeof(uint16_t); // take all memory

	uint16_t *dest = (uint16_t *)BigBuf_get_addr();
    uint16_t *destend = dest + n-1;

	AT91C_BASE_SSC->SSC_RFMR = SSC_FRAME_MODE_BITS_IN_WORD(16); // Setting Frame mode, 16 bits per word
	// Reading data loop
	while(dest <= destend)
	{
		if(AT91C_BASE_SSC->SSC_SR & AT91C_SSC_RXRDY)
		{
			*dest = (uint16_t)(AT91C_BASE_SSC->SSC_RHR);
			dest++;
		}
	}
	//Resetting Frame mode (First set in fpgaloader.c)
	AT91C_BASE_SSC->SSC_RFMR = SSC_FRAME_MODE_BITS_IN_WORD(8) | AT91C_SSC_MSBF | SSC_FRAME_MODE_WORDS_PER_TRANSFER(0);
    //setting tracelen - importsnt!  it was set by buffer overflow before
    set_tracelen( BigBuf_max_traceLen());
}

void HfSnoop(int samplesToSkip, int triggersToSkip)
{
	BigBuf_free(); BigBuf_Clear();
	
	Dbprintf("Skipping first %d sample pairs, Skipping %d triggers.\n", samplesToSkip, triggersToSkip);
	int trigger_cnt;

	LED_D_ON();
	// Select correct configs
	FpgaDownloadAndGo(FPGA_BITSTREAM_HF);
	// Set up the synchronous serial port
	FpgaSetupSsc();
	// connect Demodulated Signal to ADC:
	SetAdcMuxFor(GPIO_MUXSEL_HIPKD);
	FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_SNOOP);
    SpinDelay(100);
	
	AT91C_BASE_SSC->SSC_RFMR = SSC_FRAME_MODE_BITS_IN_WORD(16); // Setting Frame Mode For better performance on high speed data transfer.

	trigger_cnt = 0;
	uint16_t r = 0;
	while(!BUTTON_PRESS() && !usb_poll_validate_length() ) {
		WDT_HIT();
		if(AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_RXRDY)) {
			r = (uint16_t)AT91C_BASE_SSC->SSC_RHR;
			r = MAX(r & 0xff, r >> 8); 
            if (r >= 180) {
                if (++trigger_cnt > triggersToSkip)
				break;
			} 
		}
	}

	if(!BUTTON_PRESS()) {
		int waitcount = samplesToSkip; // lets wait 40000 ticks of pck0
		while(waitcount != 0) {
			
			if(AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_RXRDY))
				waitcount--;
		}
		optimizedSnoop();
		Dbprintf("Trigger kicked! Value: %d, Dumping Samples Hispeed now.", r);
	}

	DbpString("HF Snoop end");
	FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
	LED_D_OFF();
}


//structure to hold incoming NFC frame, used for ISO/IEC 18092-compatible frames
static struct {
    enum {
        STATE_UNSYNCD,
        STATE_TRYING_SYNC,
        STATE_GET_LENGTH,
        STATE_GET_DATA,
        STATE_GET_CRC,
        STATE_FULL
    }       state;

    uint16_t    shiftReg; //for synchronization and offset calculation
    int     posCnt;
    uint8_t   crc_ok;
    int   rem_len;
    uint16_t   len;
    uint8_t   byte_offset;
    uint16_t rolling_crc;
    
    uint8_t   framebytes[260]; //should be enough. maxlen is 255, 254 for data, 2 for sync, 2  for crc
    // 0,1 -> SYNC, 2 - len,  3-(len+1)->data, then crc
} NFCFrame;

//b2 4d is SYNC, 45645 in 16-bit notation, 10110010 01001101 binary. Frame will not start filling until this is shifted in
//bit order in byte -reverse, I guess?  [((bt>>0)&1),((bt>>1)&1),((bt>>2)&1),((bt>>3)&1),((bt>>4)&1),((bt>>5)&1),((bt>>6)&1),((bt>>7)&1)] -at least in the mode that I read those in

# define SYNC_16BIT 45645
static void ResetNFCFrame()
{
    NFCFrame.state=STATE_UNSYNCD;
    NFCFrame.posCnt=0;
    NFCFrame.crc_ok=0;
    NFCFrame.byte_offset=0;
    NFCFrame.rolling_crc=0;
}

uint8_t reverse(uint8_t b) {
    b = (b & 0xF0) >> 4 | (b & 0x0F) << 4;
    b = (b & 0xCC) >> 2 | (b & 0x33) << 2;
    b = (b & 0xAA) >> 1 | (b & 0x55) << 1;
    return b;
}

//shift byte into frame, reversing it at the same time
static void shiftInByte(uint8_t bt)
{
    
    for(int j=0;j<NFCFrame.byte_offset;j++)
    {
        NFCFrame.framebytes[NFCFrame.posCnt]=(NFCFrame.framebytes[NFCFrame.posCnt]<<1)+(bt&1);//(bt&1)?+0x80:(NFCFrame.framebytes[2]>>1);
        bt>>=1;
    }
    NFCFrame.posCnt++;
    NFCFrame.rem_len--;
    for(int j=NFCFrame.byte_offset;j<8;j++)
    {
        NFCFrame.framebytes[NFCFrame.posCnt]=(NFCFrame.framebytes[NFCFrame.posCnt]<<1)+(bt&1);//(bt&1)?+0x80:(NFCFrame.framebytes[2]>>1);
        bt>>=1;
    }
}

//crc table - from lammertb/libcrc
static uint16_t crc_tabccitt[256];
static uint8_t crc_tabccitt_init=0;


static void init_crcccitt_tab( void ) 
{
    uint16_t i;
    uint16_t j;
    uint16_t crc;
    uint16_t c;

    for (i=0; i<256; i++) {

        crc = 0;
        c   = i << 8;

        for (j=0; j<8; j++) {

            if ( (crc ^ c) & 0x8000 ) crc = ( crc << 1 ) ^ 0x1021;
            else                      crc =   crc << 1;

            c = c << 1;
        }

        crc_tabccitt[i] = crc;
    }

    crc_tabccitt_init = true;

} 

static uint16_t update_crc_ccitt( uint16_t crc, unsigned char c ) 
{
    //rely on prior init 
    //if ( ! crc_tabccitt_init ) init_crcccitt_tab();
    return (crc << 8) ^ crc_tabccitt[ ((crc >> 8) ^ (uint16_t) c) & 0x00FF ];

} 


static void ProcessNFCByte(uint8_t bt)
{
    switch(NFCFrame.state)
    {
    case STATE_UNSYNCD:
    {
        if(bt>0) //almost any nonzero byte can be start of SYNC. SYNC should be preceded by zeros, but that is not alsways the case
        {
            NFCFrame.shiftReg=reverse(bt);
            NFCFrame.state=STATE_TRYING_SYNC;
        }
    };break;
    case STATE_TRYING_SYNC:
    {
        if(bt==0)
        {
            //desync
            NFCFrame.shiftReg=bt;
            NFCFrame.state=STATE_UNSYNCD;
        }
        else
        {
            for(int i=0;i<8;i++)
            {
                if(NFCFrame.shiftReg==SYNC_16BIT)
                {   //SYNC done!
                    NFCFrame.state=STATE_GET_LENGTH;
                    NFCFrame.framebytes[0]=0xb2;
                    NFCFrame.framebytes[1]=0x4d; //write SYNC
                    NFCFrame.byte_offset=i;
                    //shift in remaining byte, slowly...
                    for(int j=i;j<8;j++)
                    {
                        NFCFrame.framebytes[2]=(NFCFrame.framebytes[2]<<1)+(bt&1);
                        bt>>=1;
                    }
                    
                    NFCFrame.posCnt=2;
                    if(i==0)
                        break;
                }
                NFCFrame.shiftReg=(NFCFrame.shiftReg<<1)+(bt&1);
                bt>>=1;
            }

            //that byte was last byte of sync
            if(NFCFrame.shiftReg==SYNC_16BIT)
            {   //Force SYNC on next byte
                NFCFrame.state=STATE_GET_LENGTH;
                NFCFrame.framebytes[0]=0xb2;
                NFCFrame.framebytes[1]=0x4d; 
                NFCFrame.byte_offset=0;
                NFCFrame.posCnt=1;
            }
        }
    };break;
    case STATE_GET_LENGTH:
    {

        shiftInByte(bt);
        NFCFrame.rem_len= NFCFrame.framebytes[2]-1;
        NFCFrame.rolling_crc=update_crc_ccitt(0,NFCFrame.framebytes[2]); //start calculating CRC for later
        NFCFrame.len= NFCFrame.framebytes[2]+4;//with crc and sync
        NFCFrame.state=STATE_GET_DATA;
    };break;
    case STATE_GET_DATA:
    {
        shiftInByte(bt);
        NFCFrame.rolling_crc=update_crc_ccitt(NFCFrame.rolling_crc,NFCFrame.framebytes[NFCFrame.posCnt-1]);

        if(NFCFrame.rem_len<=0)
        {
            NFCFrame.state=STATE_GET_CRC;
            NFCFrame.rem_len=2;
        }
    };break;
    case STATE_GET_CRC:
    {
        shiftInByte(bt);
        if(NFCFrame.rem_len<=0)
        {
            NFCFrame.crc_ok=((NFCFrame.rolling_crc&0xff)==NFCFrame.framebytes[NFCFrame.len-1]&&(NFCFrame.rolling_crc>>8)==NFCFrame.framebytes[NFCFrame.len-2]) ;

            NFCFrame.state=STATE_FULL;
            NFCFrame.rem_len=0;
        }

    };break;
    case STATE_FULL:
    {
        //ignore byte. Don't forget to clear frame to receive next one...
        
    };break;
    }
}


void HfSnoopLite(int samplesToSkip)
{
    if(!crc_tabccitt_init)
        init_crcccitt_tab();

    BigBuf_free(); BigBuf_Clear();
    
    int remFrames=samplesToSkip;
    if (remFrames==0) remFrames=50;
    Dbprintf("Snoop FelicaLiteS: Getting first %d frames \n", samplesToSkip);
  
    LED_D_ON();
    // Select correct configs
    FpgaDownloadAndGo(FPGA_BITSTREAM_NFC);
    // Set up the synchronous serial port
    FpgaSetupSsc();
    // connect Demodulated Signal to ADC:
    SetAdcMuxFor(GPIO_MUXSEL_HIPKD);
    FpgaWriteConfWord(FPGA_MAJOR_MODE_TEST_NFC);
    SpinDelay(100);

    //the frame bits are slow enough. 
    int n = BigBuf_max_traceLen() / sizeof(uint8_t); // take all memory

    uint8_t *dest = (uint8_t *)BigBuf_get_addr();
    uint8_t *destend = dest + n-2;
    StartCountSspClk(); //for apx frame timing
  
    AT91C_BASE_SSC->SSC_RFMR = SSC_FRAME_MODE_BITS_IN_WORD(8)  | SSC_FRAME_MODE_WORDS_PER_TRANSFER(0);
    ResetNFCFrame();
    
    int numbts=0;

    uint32_t endframe= GetCountSspClk();

    while(dest <= destend)
    {
        WDT_HIT();
        if(AT91C_BASE_SSC->SSC_SR & AT91C_SSC_RXRDY)
        {
            uint8_t dist = (uint8_t)(AT91C_BASE_SSC->SSC_RHR);
            ProcessNFCByte(dist);
            
            if(NFCFrame.state==STATE_GET_LENGTH) //to be sure we are in frame
            {
                uint16_t distance=GetCountSspClk()-endframe;
                *dest=distance>>8;
                dest++;
                *dest=(distance&0xff);
                dest++;
            }
            if(NFCFrame.state==STATE_FULL) //crc NOT checked
            {
                endframe=GetCountSspClk();
                
                for(int i=0;i<NFCFrame.len;i++)
                {
                    *dest=NFCFrame.framebytes[i];
                    dest++;
                    if(dest>=destend ) break;

                }

                remFrames--;
                if(remFrames<=0) break;
                if(dest>=destend ) break;
                numbts+=NFCFrame.len;
                ResetNFCFrame();
            }
        }

        if( BUTTON_PRESS()) break;
    }


    //reset framing
    AT91C_BASE_SSC->SSC_RFMR = SSC_FRAME_MODE_BITS_IN_WORD(8) | AT91C_SSC_MSBF | SSC_FRAME_MODE_WORDS_PER_TRANSFER(0);
    set_tracelen(numbts);
    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
    Dbprintf("S-Lite tracing done, tracelen: %i)",BigBuf_get_traceLen());
    LED_D_OFF();
}

// poll-0: 0xb2,0x4d,0x06,0x00,0xff,0xff,0x00,0x00,0x09,0x21,
// resp:  0xb2,0x4d,0x12,0x01,0xXX,0xXX,0xXX,0xXX,0xXX,0xXX,0xXX,0xXX,0x00,0xf1,0x00,0x00,0x00,0x01,0x43,0x00,0xb3,0x7f,
// poll-1 (reply with available system codes - NFC Tag3 specs, IIRC): 0xb2,0x4d,0x06,0x00,0xff,0xff,0x01,0x00,0x3a,0x10
// resp: 0xb2,0x4d,0x14,0x01,  0xXX,0xXX,0xXX,0xXX,0xXX,0xXX,0xXX,0xXX,  0x00,0xf1,0x00,0x00,0x00,0x01,0x43,0x00,  0x88,0xb4,0x0c,0xe2,
// page-req:  0xb2,0x4d,0x10,0x06,  0xXX,0xXX,0xXX,0xXX,0xXX,0xXX,0xXX,0xXX,  0x01,  0x0b,0x00,  0x01,  0x80,0x00,  0x2e,0xb3,
// page-req: 0x06, IDm(8), ServiceNum(1),Slist(2*num) BLocknum (1) BLockids(2-3*num) 
// page-resp: 0xb2,0x4d,0x1d,0x07,  0xXX,0xXX,0xXX,0xXX,0xXX,0xXX,0xXX,0xXX,  0x00,  0x00,  0x01,  0x10,0x04,0x01,0x00,0x0d,0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x23,   0xcb,0x6e,

void SetcrcToFrame(uint8_t * framebf)
{
    //expect framebuf to be preset with len...
    uint16_t  crc=0;
    for(int i=2;i<2+framebf[2];i++)
    {
        crc=update_crc_ccitt(crc,framebf[i]);
    }
    framebf[2+framebf[2]]=(crc>>8);
    framebf[3+framebf[2]]=(crc&0xff);
}

static void  sendNFCToFPGA(uint8_t * frame, int len)
{
 
    //copying from iso14443a.c
    //switch mode...
    FpgaWriteConfWord(FPGA_MAJOR_MODE_TEST_NFC | FPGA_HF_ISO14443A_TAGSIM_MOD);
        BigBuf_free(); //BigBuf_Clear();
    // clear receiving shift register and holding register
    uint8_t b;
    while(!(AT91C_BASE_SSC->SSC_SR & AT91C_SSC_RXRDY));
    b = AT91C_BASE_SSC->SSC_RHR; (void) b;
    while(!(AT91C_BASE_SSC->SSC_SR & AT91C_SSC_RXRDY));
    b = AT91C_BASE_SSC->SSC_RHR; (void) b;
    
  
    uint8_t *buff = (uint8_t *)BigBuf_get_addr(); //uses bigBuf for tracing
    buff[0]=1;
  
    // wait for the FPGA to signal 1-s on ssp (the FPGA is ready to queue new data in its delay line)
    int didget=0;
    uint16_t r = 0;
    for (uint16_t j = 0; j < 128; j++) // allow timeout - better late than never. Not sure how much is needed in 512 bits worth, though. 128 cycles should be enough?
    {
        while(!(AT91C_BASE_SSC->SSC_SR & AT91C_SSC_RXRDY));

        if (( b=AT91C_BASE_SSC->SSC_RHR))
        {
            didget=b;
            break;
        }
    }
    
    uint32_t ThisTransferTime;
    ThisTransferTime = GetCountSspClk();

    // Clear TXRDY:
    AT91C_BASE_SSC->SSC_THR = 0;
    
    uint16_t i = 0;
    for(; i < len; ) 
       {
        unsigned long STATUS = AT91C_BASE_SSC->SSC_SR;
        if(STATUS & (AT91C_SSC_TXRDY))
        {
            AT91C_BASE_SSC->SSC_THR = frame[i++];
        }
 
        if(STATUS&(AT91C_SSC_RXRDY)) //trace incoming for debug purposes
        {
            buff [r++]=(uint8_t)AT91C_BASE_SSC->SSC_RHR;
        }
       }
       
    uint32_t prevtime=GetCountSspClk()-ThisTransferTime;
    //spin to clear delay line
    for (uint16_t j = 0; j < 16; j++)
    {
        while(!(AT91C_BASE_SSC->SSC_SR & AT91C_SSC_RXRDY));
        buff[r++] = AT91C_BASE_SSC->SSC_RHR;
    }

    //switch back
    FpgaWriteConfWord(FPGA_MAJOR_MODE_TEST_NFC | FPGA_HF_ISO14443A_TAGSIM_LISTEN);
 
    set_tracelen(r+1); // should be filled by shifted input frame 
    if(didget>0)
        Dbprintf(" got %02x %d %d len:%d ",didget,prevtime, ThisTransferTime,len);
}

//simulate NFC Tag3 card - for now only poll response works
// second half (4 bytes)  of NDEF2 goes into nfcid2_0, first into nfcid2_1
void HfSimLite(unsigned int nfcid2_0,unsigned int nfcid2_1)
{
    if(!crc_tabccitt_init)
        init_crcccitt_tab();

    DbpString("Felica Lite-S sim start"); //NFC tag 3/ ISo technically. Many overlapping standards
    Dbprintf("NDEF2_0: %x",nfcid2_0);
    Dbprintf("NDEF2_1: %x",nfcid2_1);
    uint8_t ndef[8]={nfcid2_1>>24,((nfcid2_1&0x00ff0000) >>16),((nfcid2_1&0x0000ff00) >>8),(nfcid2_1&0xff),
                     nfcid2_0>>24,((nfcid2_0&0x00ff0000) >>16),((nfcid2_0&0x0000ff00) >>8),(nfcid2_0&0xff)};
    Dbprintf("NDEF2: %02x %02x %02x %02x %02x %02x %02x %02x",ndef[0],ndef[1],ndef[2],ndef[3],ndef[4],ndef[5],ndef[6],ndef[7]);
    //prepare our 3 responses...

#define R_POLL0_LEN (0x16)
#define R_POLL1_LEN (0x18)
#define R_READBLK_LEN (0x21)

    uint8_t resp_poll0[R_POLL0_LEN]={ 0xb2,0x4d,0x12,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xf1,0x00,0x00,0x00,0x01,0x43,0x00,0xb3,0x7f};
    uint8_t resp_poll1[R_POLL1_LEN]={ 0xb2,0x4d,0x14,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xf1,0x00,0x00,0x00,0x01,0x43,0x00, 0x88,0xb4,0xb3,0x7f};
    uint8_t resp_readblk[R_READBLK_LEN]={0xb2,0x4d,0x1d,0x07,  0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,  0x00,  0x00,  0x01,  0x10,0x04,0x01,0x00,0x0d,0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x23,   0xcb,0x6e};
    
    int i;
    uint8_t *curresp=0;
    int curlen=0;
    
    //fill in blanks
    for( i=0;i<8;i++)
    {
        resp_poll0[i+4]=ndef[i];
        resp_poll1[i+4]=ndef[i];
        resp_readblk[i+4]=ndef[i];
    }
    //calculate and set CRC
    SetcrcToFrame(resp_poll0);
    SetcrcToFrame(resp_poll1);
    SetcrcToFrame(resp_readblk);

    // Select correct configs
    FpgaDownloadAndGo(FPGA_BITSTREAM_NFC);
    // Set up the synchronous serial port
    FpgaSetupSsc();
    // connect Demodulated Signal to ADC:
    SetAdcMuxFor(GPIO_MUXSEL_HIPKD);
    FpgaWriteConfWord(FPGA_MAJOR_MODE_TEST_NFC|FPGA_HF_ISO14443A_TAGSIM_LISTEN);
    SpinDelay(100);
    //it might be possible to use MSB?
    AT91C_BASE_SSC->SSC_RFMR = SSC_FRAME_MODE_BITS_IN_WORD(8)  | SSC_FRAME_MODE_WORDS_PER_TRANSFER(0);
    
    ResetNFCFrame();
    StartCountSspClk(); // should work without now, this is mostly for debugging
    // do sim...
    int listenmode=1;
    for(;;)
    {
        WDT_HIT();
        
        
        if(listenmode==1)
        {
            //waiting for request...
            if(AT91C_BASE_SSC->SSC_SR & AT91C_SSC_RXRDY)
            {
                uint8_t dist = (uint8_t)(AT91C_BASE_SSC->SSC_RHR);
                ProcessNFCByte(dist);
                if(NFCFrame.state==STATE_FULL)
                {

                    if(NFCFrame.crc_ok)
                    {
                        if(NFCFrame.framebytes[2]==6&&NFCFrame.framebytes[3]==0)
                        {
                            //polling... there are two types of polling we answer to

                            if (NFCFrame.framebytes[6]==0)
                            {
                                curresp=resp_poll0;
                                curlen=R_POLL0_LEN;
                                listenmode=0;
 
                            }
                            if (NFCFrame.framebytes[6]==1)
                            {
                                curresp=resp_poll1;
                                curlen=R_POLL1_LEN;
                                listenmode=0;
                            }
                        }
                        if(NFCFrame.framebytes[2]>5&&NFCFrame.framebytes[3]==0x06)
                        {
                            //we should rebuild it depending on page size, but...
                            //Let's see first
                            curresp=resp_readblk;
                            curlen=R_READBLK_LEN;
                            listenmode=0;
                        }
                        
                        //clear frame
                        ResetNFCFrame();
                    }
                    else
                    {
                        //frame invalid, clear it out to allow for the next one
                        ResetNFCFrame();
                    }
                }

            }
        }
        if(!listenmode)
        {
            //trying to answer... here to  start answering immediately.
            sendNFCToFPGA(curresp,curlen);
            ResetNFCFrame();
            listenmode=1;
            curlen=0; curresp=NULL;
        }
        if( BUTTON_PRESS()) break;
    }
    
    //finish sim...
    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
    DbpString("Felica Lite-S sim end");
}  

