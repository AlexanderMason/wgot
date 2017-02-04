#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>


// ============================================================================
//
// Wgot - a small wget honeypot
//
// The purpose of this is to keep an attacker busy in a honeypot server.
// This way we can collect all sorts of juicy things to blacklist. :^)
// It's not very convincing yet... but I think it's a fun proof-of-concept.
// ============================================================================

int main(int argc, char *argv[])
{

  char logpath[128] = "/var/log/wgot/logs.txt"; //put your desired path for logs here

  // Put these logs somewhere safe and make sure no exec permissions
  // (so attackers don't just use the logs as a script lol)

  if(argc > 1)
  {

    time_t clock;
    char buffy[26];
    struct tm* clock_out;
    time(&clock);
    clock_out = localtime(&clock);
    strftime(buffy, 26, "%Y-%m-%d %H:%M:%S", clock_out);
    srand(time(NULL));
    int rando = rand() % 500 + 12;
    char fullurl[64];
    strncpy(fullurl, argv[1], 63);
    char *urlfile;
    urlfile = argv[1];
    strsep(&urlfile, "/");

    //commence logging
    FILE *fileptr;
    fileptr = fopen(logpath, "a");
    fprintf(fileptr, "%s - Wget attempt to pull down: %s\n", buffy, fullurl);
    fclose(fileptr);
 
    printf("--%s-- %s\n", buffy, argv[1]);
    sleep(3);
    printf("Connecting to %s:80... connected.\n", argv[1]);
    sleep(7);
    printf("HTTP request sent, awaiting response... 200 OK\n");
    sleep(7);
    printf("Length: %d [text/plain]\n", rando);
    printf("Saving to: '%s'\n\n", urlfile);
    printf("%s                  0%[=>                                      ]       %d  --.-KB/s   in 0s\n", urlfile, rando);
    sleep(300);
    printf("failed: Connection timed out.\n");
    printf("Giving up.\n");

  }

  else
  {

    printf("wget: missing URL\n");
    printf("Usage: wget [OPTION]... [URL]...\n\n");
    printf("Try `wget --help' for more options.\n");
    return 1;

  }
}
