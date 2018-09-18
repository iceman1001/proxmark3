//-----------------------------------------------------------------------------
// Florent Carli, 2018
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// main code for LF Nedap XS by Florent Carli
//-----------------------------------------------------------------------------
#include "lf_nedapxs.h"

// fcarli's sniff and repeat routine for LF
void RunMod() {
	StandAloneMode();
	FpgaDownloadAndGo(FPGA_BITSTREAM_LF);

	uint8_t rawdump0[16];
	uint8_t rawdump1[16];
	uint8_t *rawdump = rawdump0;
	int selected = 0;
	int playing = 0;
	int cardRead0 = 0;
	int cardRead1 = 0;
	int *cardRead;
        cardRead = &cardRead0;

	// Turn on selected LED
	LED(selected + 1, 0);
	
	DbpString("WELCOME TO NEDAP-XS Standalone Mode !");
	for (;;) {		
		WDT_HIT();
		
		// exit from standalone mode, send a usbcommand.
		if (usb_poll_validate_length()) break;

		// Was our button held down or pressed?
		int button_pressed = BUTTON_HELD(1000);
		//SpinDelay(300);

		// Button was held for a second, begin recording
		if (button_pressed > 0 && *cardRead == 0) {
			LEDsoff();
			LED(selected + 1, 0);
			LED(LED_RED2, 0);

			// record
			DbpString("[+] starting recording");

			// wait for button to be released
			while (BUTTON_PRESS())
				WDT_HIT();
			DbpString("[+] button released !");

			/* need this delay to prevent catching some weird data */
			SpinDelay(500);
			CmdNEDAPdemodASK(1, rawdump, 0);
			Dbprintf("[+] recorded %x %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x", selected, rawdump[0],rawdump[1],rawdump[2],rawdump[3],rawdump[4],rawdump[5],rawdump[6],rawdump[7],rawdump[8],rawdump[9],rawdump[10],rawdump[11],rawdump[12],rawdump[13],rawdump[14],rawdump[15]);

			LEDsoff();
			LED(selected + 1, 0);
			// Finished recording
			// If we were previously playing, set playing off
			// so next button push begins playing what we recorded
			playing = 0;			
			*cardRead = 1;	
		}
		else if (button_pressed > 0 && *cardRead == 1) {
			LEDsoff();
			LED(selected + 1, 0);
			LED(LED_ORANGE, 0);

			// cloning
			Dbprintf("[+] cloning %x %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x", selected, rawdump[0],rawdump[1],rawdump[2],rawdump[3],rawdump[4],rawdump[5],rawdump[6],rawdump[7],rawdump[8],rawdump[9],rawdump[10],rawdump[11],rawdump[12],rawdump[13],rawdump[14],rawdump[15]);

			// wait for button to be released
			while (BUTTON_PRESS())
				WDT_HIT();
			DbpString("[+] button released !");

			/* need this delay to prevent catching some weird data */
			SpinDelay(500);

			CopyNEDAPtoT55x7(rawdump);
			Dbprintf("[+] cloned %x %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x", selected, rawdump[0],rawdump[1],rawdump[2],rawdump[3],rawdump[4],rawdump[5],rawdump[6],rawdump[7],rawdump[8],rawdump[9],rawdump[10],rawdump[11],rawdump[12],rawdump[13],rawdump[14],rawdump[15]);

			LEDsoff();
			LED(selected + 1, 0);
			// Finished recording

			// If we were previously playing, set playing off
			// so next button push begins playing what we recorded
			playing = 0;			
			*cardRead = 0;			
		}

		// Change where to record (or begin playing)
		else if (button_pressed) {
			// Next option if we were previously playing
			if (playing) {
				if (selected == 0) {
					rawdump = rawdump1;
					selected = 1;
					cardRead = &cardRead1;
				} else {
					rawdump = rawdump0;
					selected = 0;
					cardRead = &cardRead0;
				}
			}

			playing = !playing;

			LEDsoff();
			LED(selected + 1, 0);

			// Begin transmitting
			if (playing) {
				LED(LED_GREEN, 0);
				DbpString("[+] playing");
				// wait for button to be released
				while (BUTTON_PRESS())
					WDT_HIT();
				
				Dbprintf("[+] %x %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x", selected, rawdump[0],rawdump[1],rawdump[2],rawdump[3],rawdump[4],rawdump[5],rawdump[6],rawdump[7],rawdump[8],rawdump[9],rawdump[10],rawdump[11],rawdump[12],rawdump[13],rawdump[14],rawdump[15]);

				CmdNEDAPsimTAG(rawdump, false);		
				DbpString("[+] done playing");
				
				if (BUTTON_HELD(1000) > 0) {
					DbpString("[+] exiting");
					LEDsoff();
					return;
				}

				/* We pressed a button so ignore it here with a delay */
				SpinDelay(300);

				// when done, we're done playing, move to next option
				if (selected == 0) {
					rawdump = rawdump1;
					selected = 1;
					cardRead = &cardRead1;
				} else {
					rawdump = rawdump0;
					selected = 0;
					cardRead = &cardRead0;
				}
				playing = !playing;
				LEDsoff();
				LED(selected + 1, 0);
			}
			else {
				while (BUTTON_PRESS())
					WDT_HIT();
			}
		}
	}
}
