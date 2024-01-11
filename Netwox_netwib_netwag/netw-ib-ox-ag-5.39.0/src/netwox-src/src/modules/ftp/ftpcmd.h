
/*-------------------------------------------------------------*/
/* rfc 959, and rfc 2428 for IPv6 */

/*-------------------------------------------------------------*/
typedef enum {
  NETWOX_FTPCMD_UNKNOWN = 1,
  NETWOX_FTPCMD_USER,
  NETWOX_FTPCMD_PASS,
  NETWOX_FTPCMD_ACCT,
  NETWOX_FTPCMD_CWD,
  NETWOX_FTPCMD_CDUP,
  NETWOX_FTPCMD_SMNT,
  NETWOX_FTPCMD_REIN,
  NETWOX_FTPCMD_QUIT,
  NETWOX_FTPCMD_PORT,
  NETWOX_FTPCMD_PASV,
  NETWOX_FTPCMD_TYPE,
  NETWOX_FTPCMD_STRU,
  NETWOX_FTPCMD_MODE,
  NETWOX_FTPCMD_RETR,
  NETWOX_FTPCMD_STOR,
  NETWOX_FTPCMD_STOU,
  NETWOX_FTPCMD_APPE,
  NETWOX_FTPCMD_ALLO,
  NETWOX_FTPCMD_REST,
  NETWOX_FTPCMD_RNFR,
  NETWOX_FTPCMD_RNTO,
  NETWOX_FTPCMD_ABOR,
  NETWOX_FTPCMD_DELE,
  NETWOX_FTPCMD_RMD,
  NETWOX_FTPCMD_MKD,
  NETWOX_FTPCMD_PWD,
  NETWOX_FTPCMD_LIST,
  NETWOX_FTPCMD_NLST,
  NETWOX_FTPCMD_SITE,
  NETWOX_FTPCMD_SYST,
  NETWOX_FTPCMD_STAT,
  NETWOX_FTPCMD_HELP,
  NETWOX_FTPCMD_NOOP,
  NETWOX_FTPCMD_SIZE,
  NETWOX_FTPCMD_EPRT,
  NETWOX_FTPCMD_EPSV
} netwox_ftpcmd;

/*-------------------------------------------------------------*/
netwib_err netwox_ftpcmd_init_buf(netwib_constbuf *pbuf,
                                  netwox_ftpcmd *pftpcmd);
