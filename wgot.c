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
  char *helpflag = "-h";

  if(argc > 1)
  {

    if(strstr(argv[1], helpflag) != NULL)
    {
      printf("GNU Wget 1.16(Beta), a non-interactive network retriever.\n");
      printf("Usage: wget [OPTION]... [URL]...\n\n");
      printf("Mandatory arguments to long options are mandatory for short options too.\n\n");
      printf("Startup:\n");
      printf("  -V,  --version                   display the version of Wget and exit.\n");
      printf("  -h,  --help                      print this help.\n");
      printf("  -b,  --background                go to background after startup.\n");
      printf("  -e,  --execute=COMMAND           execute a `.wgetrc'-style command.\n\n");
      printf("Logging and input file:\n");
      printf("  -o,  --output-file=FILE          log messages to FILE.\n");
      printf("  -a,  --append-output=FILE        append messages to FILE.\n");
      printf("  -d,  --debug                     print lots of debugging information.\n");
      printf("  -q,  --quiet                     quiet (no output).\n");
      printf("  -v,  --verbose                   be verbose (this is the default).\n");
      printf("  -nv, --no-verbose                turn off verboseness, without being quiet.\n");
      printf("       --report-speed=TYPE         Output bandwidth as TYPE.  TYPE can be bits.\n");
      printf("  -i,  --input-file=FILE           download URLs found in local or external FILE.\n");
      printf("  -F,  --force-html                treat input file as HTML.\n");
      printf("  -B,  --base=URL                  resolves HTML input-file links (-i -F) relative to URL.\n");
      printf("       --config=FILE               Specify config file to use.\n");
      printf("       --no-config                 Do not read any config file.\n\n");
      printf("Download:\n");
      printf("  -t,  --tries=NUMBER              set number of retries to NUMBER (0 unlimits).\n");
      printf("       --retry-connrefused         retry even if connection is refused.\n");
      printf("  -O,  --output-document=FILE      write documents to FILE.\n");
      printf("  -nc, --no-clobber                skip downloads that would download to existing files (overwriting them).\n");
      printf("  -c,  --continue                  resume getting a partially-downloaded file.\n");
      printf("       --start-pos=OFFSET          start downloading from zero-based position OFFSET.\n");
      printf("       --progress=TYPE             select progress gauge type.\n");
      printf("       --show-progress             display the progress bar in any verbosity mode.\n");
      printf("  -N,  --timestamping              don't re-retrieve files unless newer than local.\n");
      printf("  --no-use-server-timestamps       don't set the local file's timestamp by the one on the server.\n");
      printf("  -S,  --server-response           print server response.\n");
      printf("       --spider                    don't download anything.\n");
      printf("  -T,  --timeout=SECONDS           set all timeout values to SECONDS.\n");
      printf("       --dns-timeout=SECS          set the DNS lookup timeout to SECS.\n");
      printf("       --connect-timeout=SECS      set the connect timeout to SECS.\n");
      printf("       --read-timeout=SECS         set the read timeout to SECS.\n");
      printf("  -w,  --wait=SECONDS              wait SECONDS between retrievals.\n");
      printf("       --waitretry=SECONDS         wait 1..SECONDS between retries of a retrieval.\n");
      printf("       --random-wait               wait from 0.5*WAIT...1.5*WAIT secs between retrievals.\n");
      printf("       --no-proxy                  explicitly turn off proxy.\n");
      printf("  -Q,  --quota=NUMBER              set retrieval quota to NUMBER.\n");
      printf("       --bind-address=ADDRESS      bind to ADDRESS (hostname or IP) on local host.\n");
      printf("       --limit-rate=RATE           limit download rate to RATE.\n");
      printf("       --no-dns-cache              disable caching DNS lookups.\n");
      printf("       --restrict-file-names=OS    restrict chars in file names to ones OS allows.\n");
      printf("       --ignore-case               ignore case when matching files/directories.\n");
      printf("  -4,  --inet4-only                connect only to IPv4 addresses.\n");
      printf("  -6,  --inet6-only                connect only to IPv6 addresses.\n");
      printf("       --prefer-family=FAMILY      connect first to addresses of specified family,\n");
      printf("                                   one of IPv6, IPv4, or none.\n");
      printf("       --user=USER                 set both ftp and http user to USER.\n");
      printf("       --password=PASS             set both ftp and http password to PASS.\n");
      printf("       --ask-password              prompt for passwords.\n");
      printf("       --no-iri                    turn off IRI support.\n");
      printf("       --local-encoding=ENC        use ENC as the local encoding for IRIs.\n");
      printf("       --remote-encoding=ENC       use ENC as the default remote encoding.\n");
      printf("       --unlink                    remove file before clobber.\n\n");
      printf("Directories:\n");
      printf("  -nd, --no-directories            don't create directories.\n");
      printf("  -x,  --force-directories         force creation of directories.\n");
      printf("  -nH, --no-host-directories       don't create host directories.\n");
      printf("       --protocol-directories      use protocol name in directories.\n");
      printf("  -P,  --directory-prefix=PREFIX   save files to PREFIX/...\n");
      printf("cut-dirs=NUMBER           ignore NUMBER remote directory components.\n\n");
      printf("HTTP options:\n");
      printf("       --http-user=USER            set http user to USER.\n");
      printf("       --http-password=PASS        set http password to PASS.\n");
      printf("       --no-cache                  disallow server-cached data.\n");
      printf("       --default-page=NAME         Change the default page name (normally\n");
      printf("                                   this is `index.html'.).\n");
      printf("  -E,  --adjust-extension          save HTML/CSS documents with proper extensions.\n");
      printf("       --ignore-length             ignore `Content-Length' header field.\n");
      printf("       --header=STRING             insert STRING among the headers.\n");
      printf("       --max-redirect              maximum redirections allowed per page.\n");
      printf("       --proxy-user=USER           set USER as proxy username.\n");
      printf("       --proxy-password=PASS       set PASS as proxy password.\n");
      printf("       --referer=URL               include `Referer: URL' header in HTTP request.\n");
      printf("       --save-headers              save the HTTP headers to file.\n");
      printf("  -U,  --user-agent=AGENT          identify as AGENT instead of Wget/VERSION.\n");
      printf("       --no-http-keep-alive        disable HTTP keep-alive (persistent connections).\n");
      printf("       --no-cookies                don't use cookies.\n");
      printf("       --load-cookies=FILE         load cookies from FILE before session.\n");
      printf("       --save-cookies=FILE         save cookies to FILE after session.\n");
      printf("       --keep-session-cookies      load and save session (non-permanent) cookies.\n");
      printf("       --post-data=STRING          use the POST method; send STRING as the data.\n");
      printf("       --post-file=FILE            use the POST method; send contents of FILE.\n");
      printf("       --method=HTTPMethod         use method \"HTTPMethod\" in the request.\n");
      printf("       --body-data=STRING          Send STRING as data. --method MUST be set.\n");
      printf("       --body-file=FILE            Send contents of FILE. --method MUST be set.\n");
      printf("       --content-disposition       honor the Content-Disposition header when\n");
      printf("                                   choosing local file names (EXPERIMENTAL).\n");
      printf("       --content-on-error          output the received content on server errors.\n");
      printf("       --auth-no-challenge         send Basic HTTP authentication information\n");
      printf("                                   without first waiting for the server's\n");
      printf("                                   challenge.\n\n");
      printf("HTTPS (SSL/TLS) options:\n");
      printf("       --secure-protocol=PR        choose secure protocol, one of auto, SSLv2,\n");
      printf("                                   SSLv3, TLSv1 and PFS.\n");
      printf("       --https-only                only follow secure HTTPS links\n");
      printf("       --no-check-certificate      don't validate the server's certificate.\n");
      printf("       --certificate=FILE          client certificate file.\n");
      printf("       --certificate-type=TYPE     client certificate type, PEM or DER.\n");
      printf("       --private-key=FILE          private key file.\n");
      printf("       --private-key-type=TYPE     private key type, PEM or DER.\n");
      printf("       --ca-certificate=FILE       file with the bundle of CA's.\n");
      printf("       --ca-directory=DIR          directory where hash list of CA's is stored.\n");
      printf("       --random-file=FILE          file with random data for seeding the SSL PRNG.\n");
      printf("       --egd-file=FILE             file naming the EGD socket with random data.\n\n");
      printf("FTP options:\n");
      printf("       --ftp-user=USER             set ftp user to USER.\n");
      printf("       --ftp-password=PASS         set ftp password to PASS.\n");
      printf("       --no-remove-listing         don't remove `.listing' files.\n");
      printf("       --no-glob                   turn off FTP file name globbing.\n");
      printf("       --no-passive-ftp            disable the \"passive\" transfer mode.\n");
      printf("       --preserve-permissions      preserve remote file permissions.\n");
      printf("       --retr-symlinks             when recursing, get linked-to files (not dir).\n\n");
      printf("WARC options:\n");
      printf("       --warc-file=FILENAME        save request/response data to a .warc.gz file.\n");
      printf("       --warc-header=STRING        insert STRING into the warcinfo record.\n");
      printf("       --warc-max-size=NUMBER      set maximum size of WARC files to NUMBER.\n");
      printf("       --warc-cdx                  write CDX index files.\n");
      printf("       --warc-dedup=FILENAME       do not store records listed in this CDX file.\n");
      printf("       --no-warc-compression       do not compress WARC files with GZIP.\n");
      printf("       --no-warc-digests           do not calculate SHA1 digests.\n");
      printf("       --no-warc-keep-log          do not store the log file in a WARC record.\n");
      printf("       --warc-tempdir=DIRECTORY    location for temporary files created by the\n");
      printf("                                   WARC writer.\n\n");
      printf("Recursive download:\n");
      printf("  -r,  --recursive                 specify recursive download.\n");
      printf("  -l,  --level=NUMBER              maximum recursion depth (inf or 0 for infinite).\n");
      printf("       --delete-after              delete files locally after downloading them.\n");
      printf("  -k,  --convert-links             make links in downloaded HTML or CSS point to\n");
      printf("                                   local files.\n");
      printf("       --backups=N                 before writing file X, rotate up to N backup files.\n");
      printf("  -K,  --backup-converted          before converting file X, back up as X.orig.\n");
      printf("  -m,  --mirror                    shortcut for -N -r -l inf --no-remove-listing.\n");
      printf("  -p,  --page-requisites           get all images, etc. needed to display HTML page.\n");
      printf("       --strict-comments           turn on strict (SGML) handling of HTML comments.\n\n");
      printf("Recursive accept/reject:\n");
      printf("  -A,  --accept=LIST               comma-separated list of accepted extensions.\n");
      printf("  -R,  --reject=LIST               comma-separated list of rejected extensions.\n");
      printf("       --accept-regex=REGEX        regex matching accepted URLs.\n");
      printf("       --reject-regex=REGEX        regex matching rejected URLs.\n");
      printf("       --regex-type=TYPE           regex type (posix).\n");
      printf("  -D,  --domains=LIST              comma-separated list of accepted domains.\n");
      printf("       --exclude-domains=LIST      comma-separated list of rejected domains.\n");
      printf("       --follow-ftp                follow FTP links from HTML documents.\n");
      printf("       --follow-tags=LIST          comma-separated list of followed HTML tags.\n");
      printf("       --ignore-tags=LIST          comma-separated list of ignored HTML tags.\n");
      printf("  -H,  --span-hosts                go to foreign hosts when recursive.\n");
      printf("  -L,  --relative                  follow relative links only.\n");
      printf("  -I,  --include-directories=LIST  list of allowed directories.\n");
      printf("       --trust-server-names        use the name specified by the redirection\n");
      printf("                                   url last component.\n");
      printf("  -X,  --exclude-directories=LIST  list of excluded directories.\n");
      printf("  -np, --no-parent                 don't ascend to the parent directory.\n\n");
      printf("Mail bug reports and suggestions to <bug-wget@gnu.org>.\n");
      exit(1);
    }

    time_t clock;
    char datetime[26];
    struct tm* clock_out;
    time(&clock);
    clock_out = localtime(&clock);
    strftime(datetime, 26, "%Y-%m-%d %H:%M:%S", clock_out);
    srand(time(NULL));
    int rando = rand() % 500 + 12;
    char *urlfile;
    urlfile = argv[1];
    strsep(&urlfile, "/");
    char domain[64];
    strncpy(domain, argv[1], 63);
 

    //commence logging
    FILE *fileptr;
    fileptr = fopen(logpath, "a");
    fprintf(fileptr, "%s - Wget attempt to pull down: %s/%s\n", datetime, domain, urlfile);
    fclose(fileptr);

    //pretend to download a file, then fail after 5 mins.
    printf("--%s-- %s/%s\n", datetime, domain, urlfile);
    sleep(3);
    printf("Connecting to %s:80... connected.\n", domain);
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
